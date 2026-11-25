//! Call-stack sampling of busy threads in another process.
//!
//! Wait chains answer "what is it waiting for?". When the answer is "nothing, it is flat out
//! on the CPU", the next question is "running what?". This samples the call stack of any thread
//! that has been burning CPU, once a second, and reports which modules (DLLs) and functions keep
//! showing up. No debug symbols are needed to name the DLL; function names come from export
//! tables, so treat them as "somewhere near this function" rather than exact.
//!
//! To read a stack the thread has to be paused for a few milliseconds. That is the same thing
//! Process Explorer and every profiler do. The pause is kept as short as possible and nothing
//! that could fail happens between pausing and resuming.

#![allow(non_upper_case_globals)]

use std::collections::HashMap;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::{
    GetThreadTimes, OpenProcess, OpenThread, ResumeThread, SuspendThread,
};

const MAX_FRAMES: usize = 48;
/// How much of the busy thread's stack to copy when looking for file paths.
const STACK_BYTES: usize = 64 * 1024;
/// Upper bound on pointers followed from the stack per sample.
const MAX_POINTERS: usize = 4000;
/// A thread counts as busy if it used at least this much CPU since the previous look.
const HOT_MS: u64 = 250;

#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

pub struct Sampler {
    process: HANDLE,
    pub error: Option<String>,
    last_cpu: HashMap<u32, u64>,
    names: HashMap<u64, String>,
    /// One entry per captured stack, innermost frame first, already resolved to text.
    pub samples: Vec<Vec<String>>,
    /// File paths found on (or pointed to from) the busy thread's stack, one list per sample.
    pub paths: Vec<Vec<String>>,
}

impl Sampler {
    /// `symbol_dir` may hold PDBs fetched by `symbols::fetch`; it is fine if it is empty.
    pub fn open(pid: u32, symbol_dir: &std::path::Path) -> Sampler {
        let mut s = Sampler {
            process: std::ptr::null_mut(),
            error: None,
            last_cpu: HashMap::new(),
            names: HashMap::new(),
            samples: Vec::new(),
            paths: Vec::new(),
        };
        unsafe {
            // QUERY_INFORMATION | VM_READ: enough to read memory and list modules.
            let h = OpenProcess(0x0400 | 0x0010, 0, pid);
            if h.is_null() {
                s.error = Some(format!("could not open the process (Windows error {})", windows_sys::Win32::Foundation::GetLastError()));
                return s;
            }
            // UNDNAME | DEFERRED_LOADS | FAIL_CRITICAL_ERRORS | NO_PROMPTS
            SymSetOptions(0x2 | 0x4 | 0x200 | 0x80000);
            let search: Vec<u16> = symbol_dir.display().to_string().encode_utf16().chain(std::iter::once(0)).collect();
            if SymInitializeW(h, search.as_ptr(), 1) == 0 {
                s.error = Some(format!("could not initialise symbol handling (Windows error {})", windows_sys::Win32::Foundation::GetLastError()));
                CloseHandle(h);
                return s;
            }
            s.process = h;
        }
        s
    }

    pub fn clear(&mut self) {
        self.samples.clear();
        self.paths.clear();
    }

    fn cpu_ms(thread: HANDLE) -> Option<u64> {
        unsafe {
            let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let (mut c, mut e, mut k, mut u) = (z, z, z, z);
            if GetThreadTimes(thread, &mut c, &mut e, &mut k, &mut u) == 0 {
                return None;
            }
            let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64) / 10_000;
            Some(ft(k) + ft(u))
        }
    }

    /// Look at every thread; capture the stack of each one that has been busy since last time.
    pub fn sample(&mut self, tids: &[u32]) {
        if self.process.is_null() {
            return;
        }
        let mut hot = Vec::new();
        for &tid in tids {
            unsafe {
                // QUERY_LIMITED_INFORMATION is enough for thread times.
                let th = OpenThread(0x0800, 0, tid);
                if th.is_null() {
                    continue;
                }
                if let Some(now) = Self::cpu_ms(th) {
                    if let Some(prev) = self.last_cpu.insert(tid, now) {
                        if now.saturating_sub(prev) >= HOT_MS {
                            hot.push(tid);
                        }
                    }
                }
                CloseHandle(th);
            }
        }
        if hot.is_empty() {
            return;
        }
        // DLLs get loaded during sign-in; make sure they are known before we pause anything.
        unsafe { SymRefreshModuleList(self.process) };
        for tid in hot {
            let (addrs, stack_base, stack) = unsafe { self.capture(tid) };
            if addrs.is_empty() {
                continue;
            }
            // The thread is running again; now look through the copy of its stack.
            let found = self.find_paths(stack_base, &stack);
            if !found.is_empty() {
                self.paths.push(found);
            }
            let frames: Vec<String> = addrs.iter().map(|a| self.resolve(*a)).collect();
            self.samples.push(frames);
        }
    }

    /// Pause one thread, walk its stack and copy the top of it, resume it. Returns return
    /// addresses (innermost first), the stack pointer, and the copied stack bytes.
    /// Nothing in the paused section may allocate or panic: buffers are sized beforehand.
    unsafe fn capture(&self, tid: u32) -> (Vec<u64>, u64, Vec<u8>) {
        let mut addrs: Vec<u64> = Vec::with_capacity(MAX_FRAMES);
        let mut stack: Vec<u8> = vec![0u8; STACK_BYTES];
        let mut stack_len = 0usize;
        let mut rsp = 0u64;
        let mut ctx: AlignedContext = std::mem::zeroed();
        let mut frame: STACKFRAME64 = std::mem::zeroed();
        // SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION
        let th = OpenThread(0x0002 | 0x0008 | 0x0040, 0, tid);
        if th.is_null() {
            return (addrs, 0, Vec::new());
        }
        ctx.0.ContextFlags = 0x0010_000B; // CONTEXT_FULL on x64
        if SuspendThread(th) != u32::MAX {
            if GetThreadContext(th, &mut ctx.0) != 0 {
                rsp = ctx.0.Rsp;
                // Copy the stack first: StackWalk64 modifies the context as it unwinds.
                // The stack may be shorter than our buffer, so fall back to smaller reads.
                let mut want = STACK_BYTES;
                while want >= 4096 {
                    let mut got = 0usize;
                    if ReadProcessMemory(self.process, rsp as *const core::ffi::c_void, stack.as_mut_ptr() as *mut core::ffi::c_void, want, &mut got) != 0 {
                        stack_len = got.min(STACK_BYTES);
                        break;
                    }
                    want /= 2;
                }
                frame.AddrPC.Offset = ctx.0.Rip;
                frame.AddrPC.Mode = AddrModeFlat;
                frame.AddrFrame.Offset = ctx.0.Rbp;
                frame.AddrFrame.Mode = AddrModeFlat;
                frame.AddrStack.Offset = ctx.0.Rsp;
                frame.AddrStack.Mode = AddrModeFlat;
                while addrs.len() < MAX_FRAMES {
                    let ok = StackWalk64(
                        0x8664, // IMAGE_FILE_MACHINE_AMD64
                        self.process,
                        th,
                        &mut frame,
                        &mut ctx.0 as *mut CONTEXT as *mut core::ffi::c_void,
                        None,
                        Some(SymFunctionTableAccess64),
                        Some(SymGetModuleBase64),
                        None,
                    );
                    if ok == 0 || frame.AddrPC.Offset == 0 {
                        break;
                    }
                    addrs.push(frame.AddrPC.Offset);
                }
            }
            ResumeThread(th);
        }
        CloseHandle(th);
        stack.truncate(stack_len);
        (addrs, rsp, stack)
    }

    /// Code that walks folders keeps the path it is working on in a local buffer or points to
    /// it from one. Pull every file path out of the copied stack, and out of whatever the
    /// stack points at, so the report can say WHICH folder tree is being walked.
    fn find_paths(&self, base: u64, stack: &[u8]) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        let wide: Vec<u16> = stack.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();

        // 1. Paths stored directly on the stack.
        let mut i = 0;
        while i + 4 < wide.len() {
            if let Some(p) = path_at(&wide[i..]) {
                i += p.encode_utf16().count().max(1);
                found.push(p);
            } else {
                i += 1;
            }
        }

        // 2. Paths the stack points to (heap buffers).
        let end = base + stack.len() as u64;
        let mut seen = std::collections::HashSet::new();
        for q in stack.chunks_exact(8) {
            if seen.len() >= MAX_POINTERS {
                break;
            }
            let ptr = u64::from_le_bytes([q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7]]);
            let plausible = ptr >= 0x10000 && ptr < 0x7FFF_FFFF_0000 && ptr % 2 == 0 && !(ptr >= base && ptr < end);
            if !plausible || !seen.insert(ptr) {
                continue;
            }
            // Cheap probe first: does it start like a path at all?
            let mut head = [0u16; 8];
            if !self.read_wide(ptr, &mut head) || path_at(&head).is_none() && !looks_like_path_start(&head) {
                continue;
            }
            let mut buf = [0u16; 520];
            for len in [520usize, 130, 32] {
                if self.read_wide(ptr, &mut buf[..len]) {
                    if let Some(p) = path_at(&buf[..len]) {
                        found.push(p);
                    }
                    break;
                }
            }
        }
        for p in found.iter_mut() {
            *p = normalise(p);
        }
        found.sort();
        found.dedup();
        found
    }

    fn read_wide(&self, addr: u64, out: &mut [u16]) -> bool {
        let mut got = 0usize;
        unsafe {
            ReadProcessMemory(
                self.process,
                addr as *const core::ffi::c_void,
                out.as_mut_ptr() as *mut core::ffi::c_void,
                out.len() * 2,
                &mut got,
            ) != 0
        }
    }

    /// Address -> "module!function" (or "module+0xOFFSET" when no export is nearby).
    fn resolve(&mut self, addr: u64) -> String {
        if let Some(n) = self.names.get(&addr) {
            return n.clone();
        }
        let name = unsafe {
            let mut module: IMAGEHLP_MODULEW64 = std::mem::zeroed();
            module.SizeOfStruct = std::mem::size_of::<IMAGEHLP_MODULEW64>() as u32;
            let (mod_name, base) = if SymGetModuleInfoW64(self.process, addr, &mut module) != 0 {
                (wide_str(&module.ModuleName), module.BaseOfImage)
            } else {
                ("?".to_string(), 0)
            };
            // SYMBOL_INFOW is followed by the name; u64 storage keeps it aligned.
            const NAME_CHARS: usize = 256;
            let mut buf = [0u64; (std::mem::size_of::<SYMBOL_INFOW>() + NAME_CHARS * 2) / 8 + 2];
            let sym = buf.as_mut_ptr() as *mut SYMBOL_INFOW;
            (*sym).SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
            (*sym).MaxNameLen = NAME_CHARS as u32;
            let mut disp = 0u64;
            if SymFromAddrW(self.process, addr, &mut disp, sym) != 0 {
                let len = ((*sym).NameLen as usize).min(NAME_CHARS);
                let chars = std::slice::from_raw_parts(std::ptr::addr_of!((*sym).Name) as *const u16, len);
                format!("{}!{}", mod_name, String::from_utf16_lossy(chars))
            } else if base != 0 {
                format!("{}+0x{:x}", mod_name, addr - base)
            } else {
                format!("0x{:x}", addr)
            }
        };
        self.names.insert(addr, name.clone());
        name
    }

    pub fn summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(e) = &self.error {
            out.push(format!("  Stack sampling was not available: {}", e));
            return out;
        }
        let n = self.samples.len();
        if n == 0 {
            out.push("  No thread in the profile service was busy enough to sample.".into());
            return out;
        }
        let module_of = |f: &str| f.split(['!', '+']).next().unwrap_or("?").to_lowercase();
        let pct = |c: usize| format!("{:>3}%", c * 100 / n);

        out.push(format!("  {} stack samples of busy threads.", n));
        out.push("  DLLs on the busy stack (share of samples each one appears in):".into());
        let mut mods: HashMap<String, usize> = HashMap::new();
        for s in &self.samples {
            let mut seen: Vec<String> = s.iter().map(|f| module_of(f)).collect();
            seen.sort();
            seen.dedup();
            for m in seen {
                *mods.entry(m).or_default() += 1;
            }
        }
        let mut mods: Vec<_> = mods.into_iter().collect();
        mods.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        for (m, c) in mods.iter().take(20) {
            out.push(format!("    {}  {}", pct(*c), m));
        }

        out.push("  Where the CPU was actually spent (innermost function):".into());
        let mut inner: HashMap<&str, usize> = HashMap::new();
        for s in &self.samples {
            *inner.entry(s[0].as_str()).or_default() += 1;
        }
        let mut inner: Vec<_> = inner.into_iter().collect();
        inner.sort_by(|a, b| b.1.cmp(&a.1));
        for (f, c) in inner.iter().take(8) {
            out.push(format!("    {}  {}", pct(*c), f));
        }

        out.extend(self.path_summary());

        out.push("  Most common call paths (innermost first):".into());
        let mut paths: HashMap<&Vec<String>, usize> = HashMap::new();
        for s in &self.samples {
            *paths.entry(s).or_default() += 1;
        }
        let mut paths: Vec<_> = paths.into_iter().collect();
        paths.sort_by(|a, b| b.1.cmp(&a.1));
        for (i, (p, c)) in paths.iter().take(3).enumerate() {
            out.push(format!("    Path {} - {} of samples:", i + 1, pct(*c).trim()));
            for f in p.iter().take(30) {
                out.push(format!("        {}", f));
            }
        }
        out
    }
}

impl Sampler {
    /// Share of samples (percent) whose innermost call was a file-system call, and a registry call.
    pub fn kind_shares(&self) -> (usize, usize) {
        let n = self.samples.len().max(1);
        let is = |f: &str, words: &[&str]| words.iter().any(|w| f.contains(w));
        let file = self.samples.iter().filter(|s| is(&s[0], &["File", "Directory", "PathCch"])).count();
        let reg = self.samples.iter().filter(|s| is(&s[0], &["Key"])).count();
        (file * 100 / n, reg * 100 / n)
    }

    /// Folder tree of the paths seen, with the share of samples that mention each folder.
    fn path_summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        let n = self.paths.len();
        if n == 0 {
            out.push("  No file paths were found on the busy thread's stack.".into());
            return out;
        }
        let mut prefixes: HashMap<String, usize> = HashMap::new();
        for sample in &self.paths {
            let mut mine: Vec<String> = Vec::new();
            for p in sample {
                let parts: Vec<&str> = p.split('\\').filter(|x| !x.is_empty()).collect();
                for depth in 1..=parts.len().min(8) {
                    mine.push(parts[..depth].join("\\"));
                }
            }
            mine.sort();
            mine.dedup();
            for m in mine {
                *prefixes.entry(m).or_default() += 1;
            }
        }
        let mut rows: Vec<(String, usize)> = prefixes.into_iter().filter(|(_, c)| c * 100 / n >= 4).collect();
        rows.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
        out.push(format!(
            "  Folders the busy thread was working in ({} samples had paths; share that mention each folder):",
            n
        ));
        for (p, c) in rows.iter().take(70) {
            let depth = p.matches('\\').count();
            out.push(format!("    {:>3}%  {}{}", c * 100 / n, "  ".repeat(depth), p));
        }
        // A few raw examples from the middle of the capture, for the exact files involved.
        out.push("  Example paths:".into());
        let mut examples: Vec<&String> = self.paths.iter().skip(n / 3).flatten().collect();
        examples.sort_by_key(|p| std::cmp::Reverse(p.len()));
        examples.dedup();
        for p in examples.iter().take(12) {
            out.push(format!("        {}", p));
        }
        out
    }
}

fn printable(c: u16) -> bool {
    // Printable, and legal in a Windows path.
    c >= 0x20 && c != 0x7f && !matches!(c, 0x22 | 0x2a | 0x3c | 0x3e | 0x7c) && !(0xD800..=0xDFFF).contains(&c) && c < 0xFFF0
}

/// `\\??\\` / `\\\\?\\` prefix, or a drive letter and colon.
fn looks_like_path_start(w: &[u16]) -> bool {
    let b = |i: usize, ch: char| w.get(i).map(|&c| c == ch as u16).unwrap_or(false);
    let letter = |i: usize| w.get(i).map(|&c| (c as u8 as char).is_ascii_alphabetic() && c < 128).unwrap_or(false);
    (letter(0) && b(1, ':') && b(2, '\\'))
        || (b(0, '\\') && (b(1, '?') || b(1, '\\')) && b(2, '?') && b(3, '\\'))
}

/// If `w` begins with a plausible absolute file path, return it.
fn path_at(w: &[u16]) -> Option<String> {
    if !looks_like_path_start(w) {
        return None;
    }
    let len = w.iter().take(520).position(|&c| !printable(c)).unwrap_or(w.len().min(520));
    // Needs at least one component after the root to be worth reporting.
    if len < 8 {
        return None;
    }
    let s = String::from_utf16_lossy(&w[..len]);
    let body = normalise(&s);
    if body.matches('\\').count() < 2 {
        return None;
    }
    Some(s)
}

/// Strip the NT / long-path prefixes and any trailing separators or wildcards.
fn normalise(p: &str) -> String {
    let p = p.strip_prefix("\\??\\").or(p.strip_prefix("\\\\?\\")).unwrap_or(p);
    p.trim_end_matches(['\\', '*', ' ']).to_string()
}

fn wide_str(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}
