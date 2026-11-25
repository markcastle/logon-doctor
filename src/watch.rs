//! Live watch mode: catches a slow sign-in in the act.
//!
//! The event logs tell us the User Profile Service sat on the logon for minutes, but not what it
//! was doing. So we watch it while it happens, once a second, and ask Windows two questions:
//!
//!  1. What is each ProfSvc thread waiting on? (Wait Chain Traversal - the same API Task Manager's
//!     "Analyze wait chain" uses. It follows a blocked call across processes, so it can say
//!     "ProfSvc is waiting on a reply from service X".)
//!  2. Which processes were burning CPU or disk while we waited? (Covers the case where nothing
//!     is blocked and something is simply grinding.)
//!
//! It has to run while you are signed OUT, so it is meant to be started as SYSTEM from a
//! scheduled task. It only observes; it never suspends or modifies another process.

#![allow(non_upper_case_globals)] // Win32 constant names used in match patterns

use crate::evt;
use crate::report::{fmt_bytes, fmt_ms, local, local_ms, span};
use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, OpenProcess, OpenProcessToken,
    IO_COUNTERS,
};

struct Log {
    file: Option<std::fs::File>,
    path: String,
}

impl Log {
    fn new() -> Log {
        let name = format!(
            "LogonDoctor-watch-{}.txt",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        );
        // Next to the exe: when run as SYSTEM the current directory is System32.
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_default();
        let path = dir.join(name);
        Log {
            file: std::fs::File::create(&path).ok(),
            path: path.display().to_string(),
        }
    }
    fn line(&mut self, s: impl AsRef<str>) {
        println!("{}", s.as_ref());
        if let Some(f) = &mut self.file {
            let _ = write!(f, "{}\r\n", s.as_ref());
            let _ = f.flush();
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// SeDebugPrivilege lets an administrator inspect service processes. Present but disabled by
/// default in an elevated token.
fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, &mut token) == 0 {
            return false;
        }
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        let name = wide("SeDebugPrivilege");
        let mut ok = LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) != 0;
        if ok {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: 2 }],
            };
            ok = AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0
                && windows_sys::Win32::Foundation::GetLastError() == 0;
        }
        CloseHandle(token);
        ok
    }
}

/// The process hosting one service, asked for directly. Err carries the Win32 error code.
fn service_pid(name: &str) -> Result<u32, u32> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), 0x0001 /* CONNECT */);
        if scm.is_null() {
            return Err(windows_sys::Win32::Foundation::GetLastError());
        }
        let wname = wide(name);
        let svc = OpenServiceW(scm, wname.as_ptr(), 0x0004 /* QUERY_STATUS */);
        if svc.is_null() {
            let e = windows_sys::Win32::Foundation::GetLastError();
            CloseServiceHandle(scm);
            return Err(e);
        }
        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut needed = 0u32;
        let ok = QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        );
        let e = windows_sys::Win32::Foundation::GetLastError();
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err(e);
        }
        if status.dwProcessId == 0 {
            return Err(1062); // ERROR_SERVICE_NOT_ACTIVE
        }
        Ok(status.dwProcessId)
    }
}

/// Running services as (service name, pid), used only to label processes. Best effort:
/// Err carries the Win32 error code and the capture carries on without the labels.
fn services() -> Result<Vec<(String, u32)>, u32> {
    let mut out = Vec::new();
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), 0x0001 | 0x0004 /* CONNECT | ENUMERATE_SERVICE */);
        if scm.is_null() {
            return Err(windows_sys::Win32::Foundation::GetLastError());
        }
        // Windows rejects buffers over 256 KB here, so stay well under and page through
        // with the resume handle. u64 backing store keeps the returned structs aligned.
        let mut buf: Vec<u64> = vec![0; 8 * 1024]; // 64 KB
        let mut resume: u32 = 0;
        let mut failure = None;
        loop {
            let (mut needed, mut count) = (0u32, 0u32);
            let ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buf.as_mut_ptr() as *mut u8,
                (buf.len() * 8) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                std::ptr::null(),
            );
            let err = windows_sys::Win32::Foundation::GetLastError();
            let more = ok == 0 && err == 234; // ERROR_MORE_DATA
            if ok == 0 && !more {
                failure = Some(err);
                break;
            }
            let items = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for it in items {
                let mut len = 0;
                while *it.lpServiceName.add(len) != 0 {
                    len += 1;
                }
                let name = String::from_utf16_lossy(std::slice::from_raw_parts(it.lpServiceName, len));
                out.push((name, it.ServiceStatusProcess.dwProcessId));
            }
            if !more {
                break;
            }
        }
        CloseServiceHandle(scm);
        if let (Some(e), true) = (failure, out.is_empty()) {
            return Err(e);
        }
    }
    Ok(out)
}

/// pid -> exe name, and every thread id grouped by owning pid.
fn snapshot() -> (HashMap<u32, String>, HashMap<u32, Vec<u32>>) {
    let mut procs = HashMap::new();
    let mut threads: HashMap<u32, Vec<u32>> = HashMap::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return (procs, threads);
        }
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                procs.insert(pe.th32ProcessID, from_wide(&pe.szExeFile));
                if Process32NextW(snap, &mut pe) == 0 {
                    break;
                }
            }
        }
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te) != 0 {
            loop {
                threads.entry(te.th32OwnerProcessID).or_default().push(te.th32ThreadID);
                if Thread32Next(snap, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    (procs, threads)
}

#[derive(Clone, Copy, Default)]
struct Usage {
    cpu_ms: u64,
    read_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
}

fn usage(pid: u32) -> Option<Usage> {
    unsafe {
        let h = OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, 0, pid);
        if h.is_null() {
            return None;
        }
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (zero, zero, zero, zero);
        let mut io: IO_COUNTERS = std::mem::zeroed();
        let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) != 0;
        let _ = GetProcessIoCounters(h, &mut io);
        CloseHandle(h);
        if !ok {
            return None;
        }
        let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64) / 10_000;
        Some(Usage {
            cpu_ms: ft(k) + ft(u),
            read_ops: io.ReadOperationCount,
            read_bytes: io.ReadTransferCount,
            write_bytes: io.WriteTransferCount,
        })
    }
}

fn type_name(t: i32) -> &'static str {
    match t {
        WctCriticalSectionType => "critical section",
        WctSendMessageType => "window message",
        WctMutexType => "mutex",
        WctAlpcType => "RPC/ALPC call",
        WctComType => "COM call",
        WctThreadWaitType => "thread wait",
        WctProcessWaitType => "process wait",
        WctThreadType => "thread",
        WctComActivationType => "COM activation",
        WctSocketIoType => "network socket",
        WctSmbIoType => "network file share (SMB)",
        _ => "unknown object",
    }
}

struct Ctx {
    procs: HashMap<u32, String>,
    svc_by_pid: HashMap<u32, Vec<String>>,
}

impl Ctx {
    fn who(&self, pid: u32) -> String {
        let exe = self.procs.get(&pid).cloned().unwrap_or_else(|| "?".into());
        match self.svc_by_pid.get(&pid) {
            Some(s) => format!("{} [services: {}]", exe, s.join(", ")),
            None => exe,
        }
    }
}

/// One thread's wait chain as (signature for grouping, detailed text). None when the thread is
/// just idle (a lone blocked thread with nothing identifiable behind it).
fn chain(wct: *const core::ffi::c_void, tid: u32, ctx: &Ctx) -> Option<(String, String)> {
    unsafe {
        let mut nodes: [WAITCHAIN_NODE_INFO; 16] = std::mem::zeroed();
        let mut count: u32 = 16;
        let mut cycle = 0;
        let flags = WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_COM_FLAG | WCT_OUT_OF_PROC_CS_FLAG;
        if GetThreadWaitChain(wct, 0, flags, tid, &mut count, nodes.as_mut_ptr(), &mut cycle) == 0 {
            return None;
        }
        let nodes = &nodes[..(count as usize).min(16)];
        let interesting = nodes
            .iter()
            .any(|n| !matches!(n.ObjectType, WctThreadType | WctUnknownType));
        if nodes.len() < 2 || !interesting {
            return None;
        }
        let (mut sig, mut text) = (Vec::new(), Vec::new());
        for n in nodes {
            if n.ObjectType == WctThreadType {
                let t = n.Anonymous.ThreadObject;
                let state = match n.ObjectStatus {
                    WctStatusBlocked => "blocked",
                    WctStatusRunning => "RUNNING",
                    WctStatusPidOnly | WctStatusPidOnlyRpcss => "(thread unknown)",
                    WctStatusNoAccess => "(no access)",
                    _ => "",
                };
                sig.push(format!("{} {}", ctx.who(t.ProcessId), state));
                text.push(format!("{} pid {} tid {} {}", ctx.who(t.ProcessId), t.ProcessId, t.ThreadId, state));
            } else {
                let name = from_wide(&n.Anonymous.LockObject.ObjectName);
                let label = if name.is_empty() { type_name(n.ObjectType).to_string() } else { format!("{} '{}'", type_name(n.ObjectType), name) };
                sig.push(type_name(n.ObjectType).to_string());
                text.push(label);
            }
        }
        if cycle != 0 {
            sig.push("DEADLOCK".into());
            text.push("DEADLOCK (cycle)".into());
        }
        Some((sig.join("  ->  "), text.join("  ->  ")))
    }
}

/// Is a sign-in in flight? Returns (start, finished) for the newest logon seen since `since`.
fn logon_state(since: evt::Dt) -> Option<(evt::Dt, Option<evt::Dt>)> {
    let q = "*[System[(EventID=1 or EventID=2) and TimeCreated[timediff(@SystemTime) <= 3600000]]]";
    let evs = evt::query(evt::UPS, q, 200).ok()?;
    let start = evs.iter().rev().find(|e| e.id == 1 && e.time >= since)?;
    let sess = start.first_numeric().map(|s| s.to_string());
    let done = evs
        .iter()
        .find(|e| e.id == 2 && e.time >= start.time && e.first_numeric().map(|s| s.to_string()) == sess)
        .map(|e| e.time);
    Some((start.time, done))
}

pub const TASK: &str = "LogonDoctorWatch";

/// Entry point for the scheduled task. With `self_remove` the task deletes itself afterwards,
/// so a capture never leaves anything behind.
pub fn run(minutes: u64, self_remove: bool) {
    watch(minutes);
    if self_remove {
        let _ = std::process::Command::new("schtasks")
            .args(["/delete", "/tn", TASK, "/f"])
            .output();
    }
}

fn watch(minutes: u64) {
    let mut log = Log::new();
    let began = chrono::Utc::now();
    log.line("Logon Doctor - watch mode");
    log.line(format!("Started {}. Waiting up to {} min for a sign-in.", local(began), minutes));
    log.line(format!("Log file: {}", log.path));
    if !enable_debug_privilege() {
        log.line("WARNING: could not enable SeDebugPrivilege - run elevated or as SYSTEM, or results will be empty.");
    }

    let prof_pid = match service_pid("ProfSvc") {
        Ok(pid) => pid,
        Err(code) => {
            log.line(format!("ERROR: could not locate the User Profile Service (ProfSvc) process. Windows error {}.", code));
            return;
        }
    };
    let svcs = services().unwrap_or_else(|code| {
        log.line(format!("Note: could not list services (Windows error {}), so processes will be shown without service names.", code));
        Vec::new()
    });
    let mut svc_by_pid: HashMap<u32, Vec<String>> = HashMap::new();
    for (n, p) in &svcs {
        if *p != 0 {
            svc_by_pid.entry(*p).or_default().push(n.clone());
        }
    }
    log.line(format!(
        "User Profile Service is pid {} (sharing its process with: {})",
        prof_pid,
        svc_by_pid.get(&prof_pid).map(|v| v.join(", ")).unwrap_or_default()
    ));

    let wct = unsafe { OpenThreadWaitChainSession(0, None) };
    if wct.is_null() {
        log.line("ERROR: could not open a wait-chain session.");
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(minutes * 60);
    let mut tally: HashMap<String, (u32, String)> = HashMap::new(); // signature -> (samples, example)
    let mut last_sig = String::new();
    let mut usage_log: Vec<(evt::Dt, HashMap<u32, Usage>)> = Vec::new();
    let mut names: HashMap<u32, String> = HashMap::new();
    let mut window: Option<(evt::Dt, Option<evt::Dt>)> = None;
    let mut tick = 0u64;
    let mut samples_in_logon = 0u32;

    loop {
        let now = chrono::Utc::now();
        let (procs, threads) = snapshot();
        let ctx = Ctx { procs, svc_by_pid: svc_by_pid.clone() };

        // 1. What is ProfSvc blocked on right now?
        let mut sigs = Vec::new();
        for tid in threads.get(&prof_pid).cloned().unwrap_or_default() {
            if let Some((sig, text)) = chain(wct, tid, &ctx) {
                let e = tally.entry(sig.clone()).or_insert((0, text.clone()));
                e.0 += 1;
                sigs.push((sig, text));
            }
        }
        sigs.sort();
        let joined = sigs.iter().map(|s| s.0.as_str()).collect::<Vec<_>>().join(" | ");
        if joined != last_sig {
            if sigs.is_empty() {
                log.line(format!("{}  ProfSvc: no blocked calls", local_ms(now)));
            }
            for (_, text) in &sigs {
                log.line(format!("{}  ProfSvc waiting: {}", local_ms(now), text));
            }
            last_sig = joined;
        }
        if matches!(window, Some((_, None))) {
            samples_in_logon += 1;
        }

        // 2. Every 5 s: resource usage of every process, for the "who was busy" summary.
        if tick % 5 == 0 {
            let mut snap = HashMap::new();
            for (pid, _) in &ctx.procs {
                if let Some(u) = usage(*pid) {
                    snap.insert(*pid, u);
                    names.entry(*pid).or_insert_with(|| ctx.who(*pid));
                }
            }
            usage_log.push((now, snap));
        }

        // 3. Every 3 s: has a sign-in started / finished?
        if tick % 3 == 0 {
            let state = logon_state(began);
            if let (None, Some((s, _))) = (&window, &state) {
                log.line(format!("{}  >>> sign-in started (profile service notified at {})", local_ms(now), local_ms(*s)));
                tally.clear(); // only count what happens during the sign-in
            }
            if state.is_some() {
                window = state;
            }
            if let Some((s, Some(e))) = window {
                log.line(format!("{}  >>> profile service finished after {}", local_ms(now), fmt_ms(span(s, e))));
                break;
            }
        }
        if Instant::now() > deadline {
            log.line("Gave up waiting: no completed sign-in was seen in the time allowed.");
            break;
        }
        tick += 1;
        std::thread::sleep(Duration::from_secs(1));
    }
    unsafe { CloseThreadWaitChainSession(wct) };

    // ---- Summary ----
    let Some((start, Some(end))) = window else { return };
    log.line("");
    log.line("=== SUMMARY ===================================================================");
    log.line(format!("Profile service held the sign-in for {} ({} -> {})", fmt_ms(span(start, end)), local_ms(start), local_ms(end)));
    log.line("");
    log.line(format!("What ProfSvc threads were waiting on ({} one-second samples):", samples_in_logon));
    let mut t: Vec<_> = tally.into_iter().collect();
    t.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    if t.is_empty() {
        log.line("  Nothing identifiable: it was not blocked on another process, lock or network call.");
        log.line("  That means ProfSvc was doing the work itself - see its own CPU/disk figures below.");
    }
    for (_, (n, example)) in t.iter().take(8) {
        log.line(format!("  ~{:>4} s  {}", n, example));
    }

    // Usage between the snapshots bracketing the wait.
    let first = usage_log.iter().rev().find(|(t, _)| *t <= start).or(usage_log.first());
    let last = usage_log.iter().find(|(t, _)| *t >= end).or(usage_log.last());
    if let (Some((t0, a)), Some((t1, b))) = (first, last) {
        let mut rows: Vec<(u32, Usage)> = Vec::new();
        for (pid, ub) in b {
            let ua = a.get(pid).cloned().unwrap_or_default();
            rows.push((
                *pid,
                Usage {
                    cpu_ms: ub.cpu_ms.saturating_sub(ua.cpu_ms),
                    read_ops: ub.read_ops.saturating_sub(ua.read_ops),
                    read_bytes: ub.read_bytes.saturating_sub(ua.read_bytes),
                    write_bytes: ub.write_bytes.saturating_sub(ua.write_bytes),
                },
            ));
        }
        let show = |log: &mut Log, pid: u32, u: &Usage| {
            log.line(format!(
                "  {:>9} cpu {:>9} reads {:>10} read {:>10} written  {} (pid {})",
                fmt_ms(u.cpu_ms),
                u.read_ops,
                fmt_bytes(u.read_bytes),
                fmt_bytes(u.write_bytes),
                names.get(&pid).cloned().unwrap_or_default(),
                pid
            ));
        };
        log.line("");
        log.line(format!("Resource use over {} around the wait:", fmt_ms(span(*t0, *t1))));
        log.line("The profile service's own process:");
        if let Some((pid, u)) = rows.iter().find(|(p, _)| *p == prof_pid) {
            show(&mut log, *pid, u);
        }
        log.line("Busiest by CPU:");
        rows.sort_by(|x, y| y.1.cpu_ms.cmp(&x.1.cpu_ms));
        for (pid, u) in rows.iter().filter(|(p, _)| *p != 0).take(8) {
            show(&mut log, *pid, u);
        }
        log.line("Busiest by disk reads:");
        rows.sort_by(|x, y| y.1.read_ops.cmp(&x.1.read_ops));
        for (pid, u) in rows.iter().take(8) {
            show(&mut log, *pid, u);
        }
    }
    log.line("");
    log.line("Run logon-doctor.exe again to see this alongside the full report.");
}
