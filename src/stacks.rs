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
}

impl Sampler {
    pub fn open(pid: u32) -> Sampler {
        let mut s = Sampler {
            process: std::ptr::null_mut(),
            error: None,
            last_cpu: HashMap::new(),
            names: HashMap::new(),
            samples: Vec::new(),
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
            if SymInitializeW(h, std::ptr::null(), 1) == 0 {
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
            let addrs = unsafe { self.capture(tid) };
            if addrs.is_empty() {
                continue;
            }
            let frames: Vec<String> = addrs.iter().map(|a| self.resolve(*a)).collect();
            self.samples.push(frames);
        }
    }

    /// Pause one thread, walk its stack, resume it. Returns return addresses, innermost first.
    /// Nothing in the paused section may allocate past `MAX_FRAMES` or panic.
    unsafe fn capture(&self, tid: u32) -> Vec<u64> {
        let mut addrs: Vec<u64> = Vec::with_capacity(MAX_FRAMES);
        let mut ctx: AlignedContext = std::mem::zeroed();
        let mut frame: STACKFRAME64 = std::mem::zeroed();
        // SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION
        let th = OpenThread(0x0002 | 0x0008 | 0x0040, 0, tid);
        if th.is_null() {
            return addrs;
        }
        ctx.0.ContextFlags = 0x0010_000B; // CONTEXT_FULL on x64
        if SuspendThread(th) != u32::MAX {
            if GetThreadContext(th, &mut ctx.0) != 0 {
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
        addrs
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

fn wide_str(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}
