//! Checks that look at the machine as it is now (registry, files, network paths), plus the
//! event-log sections that are not tied to one particular sign-in.

use crate::evt::{self, Event};
use crate::report::{fmt_bytes, fmt_ms, local, Report, Sev};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

pub struct Target {
    pub sid: String,
    pub path: String,
    pub name: String,
    pub central: String,
}

fn reg_str(v: &RegValue) -> Option<String> {
    match v.vtype {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            let w: Vec<u16> = v
                .bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(
                String::from_utf16_lossy(&w)
                    .trim_end_matches('\0')
                    .replace('\0', "; "),
            )
        }
        _ => None,
    }
}

fn get_str(k: &RegKey, name: &str) -> Option<String> {
    k.get_raw_value(name).ok().and_then(|v| reg_str(&v))
}

fn get_u32(k: &RegKey, name: &str) -> Option<u32> {
    k.get_value::<u32, _>(name).ok()
}

fn hklm(path: &str) -> Option<RegKey> {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(path).ok()
}

fn leaf(path: &str) -> String {
    path.trim_end_matches('\\').rsplit('\\').next().unwrap_or("").to_string()
}

/// Work out whose profile we are diagnosing. Normally the person running the tool, but if they
/// elevated with a different admin account they need `--user` to point back at the slow profile.
pub fn resolve_target(r: &mut Report, want_user: Option<&str>) -> Option<Target> {
    let userprofile = std::env::var("USERPROFILE").unwrap_or_default();
    let list = hklm(PROFILE_LIST)?;
    let mut found = None;
    let mut baks = Vec::new();
    let mut names = Vec::new();
    for sid in list.enum_keys().flatten() {
        let Ok(k) = list.open_subkey(&sid) else { continue };
        let path = get_str(&k, "ProfileImagePath").unwrap_or_default();
        if sid.to_lowercase().ends_with(".bak") {
            baks.push(format!("{} ({})", sid, path));
            continue;
        }
        if !sid.starts_with("S-1-5-21-") && !sid.starts_with("S-1-12-1-") {
            continue;
        }
        names.push(leaf(&path));
        let hit = match want_user {
            Some(u) => leaf(&path).eq_ignore_ascii_case(u),
            None => path.eq_ignore_ascii_case(&userprofile),
        };
        if hit {
            found = Some(Target {
                name: leaf(&path),
                central: get_str(&k, "CentralProfile").unwrap_or_default(),
                sid: sid.clone(),
                path,
            });
        }
    }
    if !baks.is_empty() {
        r.find(
            Sev::High,
            "Broken profile registration (.bak entry in ProfileList)",
            format!(
                "Windows renames a profile's registry entry to '.bak' when it fails to load it, then signs the user into a temporary profile. Found: {}",
                baks.join(", ")
            ),
            r"In regedit under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList: delete the duplicate SID key WITHOUT .bak (the temp one), remove '.bak' from the other, set its 'State' and 'RefCount' values to 0, then reboot. Back the key up first.",
        );
    }
    if found.is_none() {
        r.line(format!(
            "Could not match a profile for '{}'. Profiles on this PC: {}",
            want_user.unwrap_or(&userprofile),
            names.join(", ")
        ));
    }
    found
}

pub fn system_info(r: &mut Report, t: &Target, elevated: bool) {
    r.section("System");
    if let Some(k) = hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
        r.line(format!(
            "Windows        : {} {} (build {})",
            get_str(&k, "ProductName").unwrap_or_default(),
            get_str(&k, "DisplayVersion").or(get_str(&k, "ReleaseId")).unwrap_or_default(),
            get_str(&k, "CurrentBuild").unwrap_or_default()
        ));
    }
    let domain = hklm(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
        .and_then(|k| get_str(&k, "Domain"))
        .unwrap_or_default();
    r.line(format!("Computer       : {}", std::env::var("COMPUTERNAME").unwrap_or_default()));
    r.line(format!(
        "Domain joined  : {}",
        if domain.is_empty() { "no (workgroup / Microsoft account / Azure AD)".to_string() } else { format!("yes - {}", domain) }
    ));
    r.line(format!("Profile        : {}  ({})", t.path, t.sid));
    r.line(format!("Elevated       : {}", if elevated { "yes" } else { "NO - some checks will be skipped" }));
}

/// Probe paths in parallel, each with a hard timeout: a dead server must not hang the tool the
/// same way it hangs the sign-in.
fn probe(paths: &[String]) -> Vec<(String, Result<u64, String>)> {
    let timeout = Duration::from_secs(8);
    let rxs: Vec<_> = paths
        .iter()
        .map(|p| {
            let (tx, rx) = mpsc::channel();
            let p2 = p.clone();
            std::thread::spawn(move || {
                let t = Instant::now();
                let res = std::fs::metadata(&p2).map(|_| ()).map_err(|e| e.to_string());
                let _ = tx.send((t.elapsed().as_millis() as u64, res));
            });
            (p.clone(), rx)
        })
        .collect();
    let started = Instant::now();
    rxs.into_iter()
        .map(|(p, rx)| {
            let left = timeout.saturating_sub(started.elapsed());
            let res = match rx.recv_timeout(left) {
                Ok((ms, Ok(()))) => Ok(ms),
                Ok((ms, Err(e))) => Err(format!("failed after {}: {}", fmt_ms(ms), e)),
                Err(_) => Err("NO RESPONSE within 8 s".to_string()),
            };
            (p, res)
        })
        .collect()
}

/// Size and file count of a tree, skipping links/junctions, giving up after a time budget.
fn tree_size(root: &Path, budget: Duration) -> (u64, u64, bool) {
    let started = Instant::now();
    let (mut bytes, mut files) = (0u64, 0u64);
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if started.elapsed() > budget {
            return (bytes, files, false);
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else if let Ok(m) = e.metadata() {
                bytes += m.len();
                files += 1;
            }
        }
    }
    (bytes, files, true)
}

pub fn profile(r: &mut Report, t: &Target, user_root: Option<&RegKey>) {
    r.section("Profile");
    let base = Path::new(&t.path);

    if leaf(&t.path).eq_ignore_ascii_case("TEMP") || t.path.to_lowercase().contains(r"\temp.") {
        r.find(
            Sev::High,
            "You are signed in with a TEMPORARY profile",
            format!("The profile path is '{}'. Windows failed to load the real profile and built a throwaway one, which is slow every single time.", t.path),
            "Fix the ProfileList registry entry (see the .bak finding if present) or check the disk for errors with 'chkdsk /scan'.",
        );
    }

    // Registry hives are read in full at sign-in, so their size matters directly.
    for (label, rel, warn, bad) in [
        ("NTUSER.DAT", "NTUSER.DAT", 60u64, 250u64),
        ("UsrClass.dat", r"AppData\Local\Microsoft\Windows\UsrClass.dat", 100, 500),
    ] {
        match std::fs::metadata(base.join(rel)) {
            Ok(m) => {
                let mb = m.len() / (1024 * 1024);
                r.line(format!("{:<15}: {}", label, fmt_bytes(m.len())));
                if mb >= warn {
                    r.find(
                        if mb >= bad { Sev::High } else { Sev::Medium },
                        format!("Registry hive {} is bloated ({})", label, fmt_bytes(m.len())),
                        format!("This file is the user's registry and is loaded during every sign-in. Typical size is 5-30 MB; this one is {}. Bloat usually comes from an app leaking keys (printer/notification/AppX entries are common offenders).", fmt_bytes(m.len())),
                        "Sign in as a different admin, then compact the hive: load it in regedit (File > Load Hive), export it as a 'Registry Hive File', and swap it in for the original (keep a backup). If UsrClass.dat is the huge one, renaming it lets Windows rebuild it at next sign-in (per-user file associations are reset).",
                    );
                }
            }
            Err(e) => r.line(format!("{:<15}: could not read ({})", label, e)),
        }
    }

    // Roaming profile: the whole of AppData\Roaming is copied from the server at sign-in.
    let roaming = !t.central.is_empty();
    r.line(format!(
        "Profile type   : {}",
        if roaming { format!("ROAMING - server copy at {}", t.central) } else { "local".to_string() }
    ));
    let (bytes, files, complete) = tree_size(&base.join(r"AppData\Roaming"), Duration::from_secs(25));
    r.line(format!(
        "AppData\\Roaming: {} in {} files{}",
        fmt_bytes(bytes),
        files,
        if complete { "" } else { " (scan cut short - it is at least this big)" }
    ));
    if roaming {
        let big = bytes > 500 * 1024 * 1024 || files > 20_000;
        r.find(
            if big { Sev::High } else { Sev::Medium },
            format!("Roaming profile in use ({} / {} files synchronised at sign-in)", fmt_bytes(bytes), files),
            format!("This account's profile is copied from {} at every sign-in. Sign-in time grows with the number of files more than with total size.", t.central),
            "Ask whoever runs the domain to exclude cache folders from roaming (GPO 'Exclude directories in roaming profile'), or move to folder redirection / FSLogix. Clearing browser and Teams caches under AppData\\Roaming gives a quick win.",
        );
    }

    if let Ok(rd) = std::fs::read_dir(base.join("Desktop")) {
        let n = rd.count();
        r.line(format!("Desktop items  : {}", n));
        if n > 300 {
            r.find(
                Sev::Low,
                format!("{} items on the Desktop", n),
                "Explorer has to enumerate and draw icons for every Desktop item before the desktop appears usable.",
                "Move files into a folder under Documents.",
            );
        }
    }

    // Network locations the sign-in has to reach.
    let mut paths: Vec<(String, String)> = Vec::new();
    if let Some(root) = user_root {
        if let Ok(k) = root.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") {
            for (name, v) in k.enum_values().flatten() {
                if let Some(s) = reg_str(&v) {
                    // Anything not inside the profile itself: a share, or another (possibly mapped) drive.
                    let s = s.replace("%USERPROFILE%", &t.path).replace("%userprofile%", &t.path);
                    let outside = !s.to_lowercase().starts_with(&t.path.to_lowercase()) && !s.contains('%');
                    if outside && !name.starts_with('!') {
                        paths.push((format!("shell folder '{}'", name), s));
                    }
                }
            }
        }
        if let Ok(net) = root.open_subkey("Network") {
            for letter in net.enum_keys().flatten() {
                if let Some(remote) = net.open_subkey(&letter).ok().and_then(|k| get_str(&k, "RemotePath")) {
                    paths.push((format!("mapped drive {}:", letter.to_uppercase()), remote));
                }
            }
        }
    }
    if let Ok(h) = std::env::var("HOMESHARE") {
        if h.starts_with(r"\\") {
            paths.push(("home folder".to_string(), h));
        }
    }
    if roaming {
        paths.push(("roaming profile store".to_string(), t.central.clone()));
    }
    if paths.is_empty() {
        r.line("Network paths  : none (no mapped drives, redirected folders or home share)");
    } else {
        r.line("Network paths used at sign-in:");
        let results = probe(&paths.iter().map(|p| p.1.clone()).collect::<Vec<_>>());
        for ((what, _), (path, res)) in paths.iter().zip(results) {
            match res {
                Ok(ms) => {
                    r.line(format!("  ok   {:>8}  {} -> {}", fmt_ms(ms), what, path));
                    if ms >= 2000 {
                        r.find(
                            Sev::Medium,
                            format!("Slow network path: {} ({})", what, fmt_ms(ms)),
                            format!("'{}' took {} just to answer. Sign-in touches this path, usually more than once.", path, fmt_ms(ms)),
                            "Check the server and the link to it (Wi-Fi/VPN). If the share is not needed, disconnect the drive.",
                        );
                    }
                }
                Err(e) => {
                    r.line(format!("  FAIL           {} -> {} ({})", what, path, e));
                    r.find(
                        Sev::High,
                        format!("Unreachable network path: {}", what),
                        format!("'{}' did not respond ({}). Windows waits for a network timeout on each dead path during sign-in - typically 20-60 s apiece. (If you only sign in at a different location, e.g. the office, re-run this there.)", path, e),
                        "If it is a mapped drive you no longer use: 'net use X: /delete'. If it is a redirected folder or home drive, the server or its DNS name is the problem.",
                    );
                }
            }
        }
    }
}

/// Counts keys in the user's registry and finds where they pile up.
///
/// A profile service that spends minutes on the CPU with no disk activity is almost certainly
/// walking registry data, and what makes that slow is not the hive's size in megabytes but one
/// key with tens of thousands of children that some app or Windows component has leaked.
pub fn registry_census(r: &mut Report, t: &Target) {
    r.section("Registry census (where the user's registry is bloated)");
    struct Census {
        keys: u64,
        values: u64,
        fat: Vec<(u64, u64, String)>, // (direct subkeys, direct values, path)
        branches: std::collections::HashMap<String, u64>,
        deadline: Instant,
        complete: bool,
    }
    fn walk(k: &RegKey, path: &str, depth: usize, c: &mut Census) {
        if Instant::now() > c.deadline {
            c.complete = false;
            return;
        }
        let Ok(info) = k.query_info() else { return };
        c.keys += 1;
        c.values += info.values as u64;
        if info.sub_keys as u64 + info.values as u64 >= 400 {
            c.fat.push((info.sub_keys as u64, info.values as u64, path.to_string()));
        }
        // Attribute every key to its branch three levels down, e.g. Software\Microsoft\Windows.
        let branch: String = path.split('\\').take(4).collect::<Vec<_>>().join("\\");
        *c.branches.entry(branch).or_default() += 1;
        if depth >= 48 || info.sub_keys == 0 {
            return;
        }
        for name in k.enum_keys().flatten() {
            if let Ok(child) = k.open_subkey(&name) {
                walk(&child, &format!("{}\\{}", path, name), depth + 1, c);
            }
        }
    }

    let mut c = Census {
        keys: 0,
        values: 0,
        fat: Vec::new(),
        branches: std::collections::HashMap::new(),
        deadline: Instant::now() + Duration::from_secs(90),
        complete: true,
    };
    let hku = RegKey::predef(HKEY_USERS);
    let mut any = false;
    // The two hives loaded at sign-in: NTUSER.DAT and UsrClass.dat.
    for (label, sub) in [("HKCU", t.sid.clone()), ("HKCU-Classes", format!("{}_Classes", t.sid))] {
        if let Ok(root) = hku.open_subkey(&sub) {
            any = true;
            walk(&root, label, 0, &mut c);
        }
    }
    if !any {
        r.line("The user's registry is not loaded (user not signed in), so it could not be examined.");
        return;
    }
    r.line(format!(
        "{} keys and {} values{}",
        c.keys,
        c.values,
        if c.complete { "" } else { " (scan cut short after 90 s - at least this many)" }
    ));

    let mut branches: Vec<_> = c.branches.into_iter().collect();
    branches.sort_by(|a, b| b.1.cmp(&a.1));
    r.line("Largest branches by number of keys:");
    for (b, n) in branches.iter().take(10) {
        r.line(format!("  {:>8}  {}", n, b));
    }

    c.fat.sort_by(|a, b| (b.0 + b.1).cmp(&(a.0 + a.1)));
    if c.fat.is_empty() {
        r.line("No single key has an unusual number of entries.");
        return;
    }
    r.line("Keys with the most direct entries (subkeys / values):");
    for (subs, vals, path) in c.fat.iter().take(15) {
        r.line(format!("  {:>7} / {:<7} {}", subs, vals, path));
    }
    if let Some((subs, vals, path)) = c.fat.first() {
        let total = subs + vals;
        // Explorer caps Shell\\Bags at 5000 by design, so that size alone means nothing.
        if total >= 20_000 {
            r.find(
                if total >= 20_000 { Sev::High } else { Sev::Medium },
                format!("Registry bloat: one key holds {} entries", total),
                format!(
                    "'{}' has {} subkeys and {} values. A healthy key has a few dozen. Anything that enumerates this key at sign-in - including components the profile service notifies - \
                     slows down in proportion, and it does so on the CPU with no disk activity, which is the pattern a live capture shows when this is the cause.",
                    path, subs, vals
                ),
                "Do not delete it blindly. Identify which program owns the key from its path, then look up the documented cleanup for that program; export the key in regedit first so it can be restored.",
            );
        }
    }
}

/// Things around the profile service itself: who it notifies, and signs of profile damage.
pub fn profile_service(r: &mut Report, sid: &str) {
    r.section("Profile service environment");
    if let Some(k) = hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileNotification") {
        let subs: Vec<String> = k.enum_keys().flatten().collect();
        r.line(format!("Components notified on every profile load ({}): {}", subs.len(), subs.join(", ")));
    }
    // How Windows has this profile registered, and any policy that changes profile handling.
    // Raw values on purpose: these are what decide which code path the profile service takes.
    let dump = |r: &mut Report, title: &str, key: Option<RegKey>| {
        let Some(k) = key else { return };
        let mut vals: Vec<String> = Vec::new();
        for (name, v) in k.enum_values().flatten() {
            let shown = match v.vtype {
                REG_DWORD if v.bytes.len() >= 4 => {
                    let n = u32::from_le_bytes([v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]]);
                    format!("{} (0x{:x})", n, n)
                }
                REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => reg_str(&v).unwrap_or_default(),
                _ => format!("<{} bytes>", v.bytes.len()),
            };
            vals.push(format!("{}={}", name, shown));
        }
        if !vals.is_empty() {
            r.line(format!("{}:", title));
            for v in vals {
                r.line(format!("    {}", v.chars().take(150).collect::<String>()));
            }
        }
    };
    dump(r, "ProfileList (all profiles)", hklm(PROFILE_LIST));
    dump(r, "ProfileList entry for this profile", hklm(&format!(r"{}\{}", PROFILE_LIST, sid)));
    dump(r, "Machine policy: Windows\\System", hklm(r"SOFTWARE\Policies\Microsoft\Windows\System"));

    let users = Path::new(&std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())).join("\\Users");
    if let Ok(rd) = std::fs::read_dir(&users) {
        let temps: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.to_uppercase().starts_with("TEMP"))
            .collect();
        r.line(format!("Leftover temporary profile folders in {}: {}", users.display(), temps.len()));
        if temps.len() >= 3 {
            r.find(
                Sev::Medium,
                format!("{} leftover temporary profile folders (e.g. {})", temps.len(), temps[0]),
                "Windows keeps failing to build a profile for some account and leaves a TEMP folder behind each time. With 'Font Driver Host' or 'Window Manager' in the name, \
                 these belong to per-session system accounts, and the usual reason is that C:\\Users\\Default (the template every new profile is copied from) has damaged permissions or contents.",
                "Check C:\\Users\\Default: Properties > Security should give SYSTEM and Administrators full control and Users/Everyone read. 'sfc /scannow' does not repair it; \
                 copying Default from a healthy PC on the same Windows version does. The TEMP.* folders can be deleted once nothing is using them.",
            );
        }
    }
    let default = users.join("Default");
    match std::fs::read_dir(&default) {
        Ok(_) => r.line(format!("{} is readable by this account.", default.display())),
        Err(e) => r.line(format!("{} could NOT be read: {}", default.display(), e)),
    }
    for (name, why) in [("AppXSvc", "AppX deployment"), ("StateRepository", "app state repository"), ("AppReadiness", "app readiness"), ("ProfSvc", "user profile service"), ("UserManager", "user manager")] {
        if let Some(k) = hklm(&format!(r"SYSTEM\CurrentControlSet\Services\{}", name)) {
            let start = get_u32(&k, "Start").unwrap_or(99);
            if start == 4 {
                r.line(format!("Service {} ({}) is DISABLED", name, why));
                r.find(
                    Sev::High,
                    format!("Service {} is disabled", name),
                    format!("The {} service is set to Disabled. The profile service calls into it during sign-in and waits for a timeout when it cannot start.", why),
                    format!("Set it back to its default start type: 'sc config {} start= demand' (ProfSvc and UserManager: 'start= auto'), then restart.", name),
                );
            }
        }
    }
}

struct Startup {
    name: String,
    cmd: String,
    source: String,
    disabled: bool,
}

/// Task Manager's enable/disable switch lives in StartupApproved: first byte odd = disabled.
fn approved(roots: &[&RegKey], sub: &str, name: &str) -> bool {
    for root in roots {
        let p = format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{}", sub);
        if let Ok(k) = root.open_subkey(p) {
            if let Ok(v) = k.get_raw_value(name) {
                if let Some(b) = v.bytes.first() {
                    return b % 2 == 0;
                }
            }
        }
    }
    true
}

pub fn startup(r: &mut Report, t: &Target, user_root: Option<&RegKey>) {
    r.section("Startup programs");
    let lm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut roots: Vec<&RegKey> = vec![&lm];
    if let Some(u) = user_root {
        roots.push(u);
    }
    let mut items: Vec<Startup> = Vec::new();

    let mut run_key = |root: &RegKey, path: &str, source: &str, sub: &str, roots: &[&RegKey]| {
        if let Ok(k) = root.open_subkey(path) {
            for (name, v) in k.enum_values().flatten() {
                items.push(Startup {
                    disabled: !approved(roots, sub, &name),
                    cmd: reg_str(&v).unwrap_or_default(),
                    source: source.to_string(),
                    name,
                });
            }
        }
    };
    run_key(&lm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", "Run", &roots);
    run_key(&lm, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)", "Run32", &roots);
    run_key(&lm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce", "Run", &roots);
    if let Some(u) = user_root {
        run_key(u, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", "Run", &roots);
        run_key(u, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", "Run", &roots);
    }
    let programdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    for (dir, source) in [
        (format!(r"{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", t.path), "Startup folder (user)"),
        (format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", programdata), "Startup folder (all users)"),
    ] {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                items.push(Startup {
                    disabled: !approved(&roots, "StartupFolder", &name),
                    cmd: e.path().to_string_lossy().to_string(),
                    source: source.to_string(),
                    name,
                });
            }
        }
    }

    let enabled = items.iter().filter(|i| !i.disabled).count();
    r.line(format!("{} startup entries, {} enabled:", items.len(), enabled));
    for i in &items {
        let cmd: String = i.cmd.chars().take(70).collect();
        r.line(format!(
            "  {} {:<26} {:<26} {}",
            if i.disabled { "off" } else { "ON " },
            i.name.chars().take(26).collect::<String>(),
            i.source,
            cmd
        ));
    }
    if enabled > 12 {
        r.find(
            if enabled > 25 { Sev::Medium } else { Sev::Low },
            format!("{} programs start at sign-in", enabled),
            "Each one competes for disk and CPU in the first minute after the desktop appears, which is what makes the PC feel frozen after sign-in - especially on a hard disk rather than an SSD.",
            "Task Manager > Startup tab: disable everything you do not need immediately. Nothing is uninstalled; the programs still run when you open them.",
        );
    }

    // Scheduled tasks with a logon trigger are the 'hidden' startup list.
    let tasks_root = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join(r"System32\Tasks");
    let mut tasks = Vec::new();
    let mut stack = vec![tasks_root.clone()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if !p.ends_with("Microsoft") {
                    stack.push(p);
                }
                continue;
            }
            let Ok(bytes) = std::fs::read(&p) else { continue };
            let text = if bytes.starts_with(&[0xFF, 0xFE]) {
                let w: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&w)
            } else {
                String::from_utf8_lossy(&bytes).to_string()
            };
            if text.contains("<LogonTrigger>") {
                tasks.push(p.strip_prefix(&tasks_root).unwrap_or(&p).to_string_lossy().to_string());
            }
        }
    }
    if !tasks.is_empty() {
        r.line(format!("{} non-Microsoft scheduled tasks run at logon:", tasks.len()));
        for t in &tasks {
            r.line(format!("  {}", t));
        }
    }
}

pub fn policy(r: &mut Report, user_root: Option<&RegKey>) {
    r.section("Settings that make sign-in wait");
    let mut any = false;
    let mut note = |r: &mut Report, s: String| {
        any = true;
        r.line(s);
    };

    if let Some(k) = hklm(r"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon") {
        if get_u32(&k, "SyncForegroundPolicy") == Some(1) {
            note(r, "Policy 'Always wait for the network at computer startup and logon' is ENABLED".into());
            r.find(
                Sev::Medium,
                "Sign-in is forced to wait for the network and all policy",
                "The policy 'Always wait for the network at computer startup and logon' is on. Windows will not show the desktop until the network is up and every Group Policy extension has finished synchronously.",
                "Set by an administrator, sometimes deliberately (it is required for folder redirection / software install on first logon). If this is your own PC: gpedit.msc > Computer Configuration > Administrative Templates > System > Logon.",
            );
        }
    }
    if let Some(k) = hklm(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
        if get_u32(&k, "RunLogonScriptSync") == Some(1) {
            note(r, "Policy 'Run logon scripts synchronously' is ENABLED (machine)".into());
            r.find(
                Sev::Medium,
                "Logon scripts run synchronously",
                "The desktop is held back until every logon script has finished. One slow command in a script (a drive map to a dead server, a software inventory tool) delays every sign-in.",
                "Find the scripts with 'gpresult /h gp.html' and time them by hand, or turn off 'Run logon scripts synchronously'.",
            );
        }
        if let Some(v) = get_u32(&k, "DelayedDesktopSwitchTimeout") {
            note(r, format!("DelayedDesktopSwitchTimeout = {} s", v));
        }
        if get_u32(&k, "EnableFirstLogonAnimation") == Some(1) {
            note(r, "First sign-in animation is enabled (only affects brand-new profiles)".into());
        }
    }
    if let Some(k) = hklm(r"SOFTWARE\Policies\Microsoft\Windows\System") {
        if let Some(v) = get_u32(&k, "GpNetworkStartTimeoutPolicyValue") {
            note(r, format!("Group Policy network wait timeout = {} s", v));
        }
    }
    if let Some(k) = hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
        let userinit = get_str(&k, "Userinit").unwrap_or_default();
        let shell = get_str(&k, "Shell").unwrap_or_default();
        if !userinit.trim_end_matches(',').to_lowercase().ends_with(r"system32\userinit.exe") {
            note(r, format!("Winlogon Userinit is non-standard: {}", userinit));
            r.find(
                Sev::Medium,
                "Winlogon 'Userinit' has been modified",
                format!("Value is '{}'. Anything extra here runs before the desktop and is a classic place for both legacy software and malware to hook in.", userinit),
                r"Expected value: C:\Windows\system32\userinit.exe, - identify the extra program before removing it, and run a malware scan.",
            );
        }
        if !shell.eq_ignore_ascii_case("explorer.exe") {
            note(r, format!("Winlogon Shell is non-standard: {}", shell));
        }
    }
    if let Some(u) = user_root {
        if let Some(s) = u.open_subkey("Environment").ok().and_then(|k| get_str(&k, "UserInitMprLogonScript")) {
            note(r, format!("Per-user logon script (UserInitMprLogonScript): {}", s));
        }
        if let Ok(k) = u.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon") {
            let mut scripts = Vec::new();
            for gpo in k.enum_keys().flatten() {
                let Ok(g) = k.open_subkey(&gpo) else { continue };
                for n in g.enum_keys().flatten() {
                    if let Some(s) = g.open_subkey(&n).ok().and_then(|x| get_str(&x, "Script")) {
                        scripts.push(s);
                    }
                }
            }
            if !scripts.is_empty() {
                note(r, format!("Group Policy logon scripts: {}", scripts.join(" | ")));
            }
        }
    }

    // Known Windows 10 bug: firewall rules for AppX packages pile up per user per sign-in.
    for (label, path) in [
        ("Firewall rules", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"),
        ("Firewall AppIso rules", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules"),
    ] {
        if let Some(n) = hklm(path).and_then(|k| k.query_info().ok()).map(|i| i.values) {
            note(r, format!("{:<22}: {}", label, n));
            if n > 5000 {
                r.find(
                    if n > 15_000 { Sev::High } else { Sev::Medium },
                    format!("{} firewall rules have accumulated ({})", n, label),
                    "Windows 10 adds per-user firewall rules for Store apps at sign-in and, on some builds, never removes them. Tens of thousands of rules make sign-in (and the Start menu) progressively slower. A normal PC has a few hundred.",
                    r"Install current cumulative updates, then set HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DeleteUserAppContainersOnLogoff (DWORD) = 1. Existing duplicates can be cleared with 'netsh advfirewall reset' (this also removes your custom rules).",
                );
            }
        }
    }
    if !any {
        r.line("Nothing unusual.");
    }
}

fn load(r: &mut Report, channel: &str, q: &str) -> Vec<Event> {
    match evt::query(channel, q, 5000) {
        Ok(v) => v,
        Err(code) => {
            let why = match code {
                evt::ERROR_ACCESS_DENIED => "access denied - run as administrator".to_string(),
                evt::ERROR_EVT_CHANNEL_NOT_FOUND => "channel does not exist on this PC".to_string(),
                c => format!("error {}", c),
            };
            r.blind_spots.push(format!("Event log '{}': {}", channel, why));
            Vec::new()
        }
    }
}

/// What the well-known sign-in related error events actually mean.
fn explain(provider: &str, id: u32) -> (&'static str, Sev) {
    let p = provider.to_lowercase();
    if p.contains("user profile") {
        return match id {
            1511 | 1515 => ("Windows could not load your profile and used a TEMPORARY one", Sev::High),
            1500 | 1502 | 1508 => ("The profile or its registry hive failed to load", Sev::High),
            1509 | 1504 => ("Windows could not copy files while building a profile (see Source/Target in the data)", Sev::Medium),
            1521 | 1526 => ("Roaming profile could not be fully copied to/from the server", Sev::High),
            1533 => ("A leftover profile folder could not be deleted", Sev::Low),
            1542 => ("UsrClass.dat (per-user classes hive) failed to load - likely corrupt", Sev::High),
            1530 => ("Registry still in use at sign-out (usually harmless)", Sev::Info),
            1534 => ("A profile notification component failed (commonly harmless on Windows 10)", Sev::Info),
            _ => ("User Profile Service problem", Sev::Medium),
        };
    }
    if p.contains("winlogon") {
        return match id {
            6005 | 6006 => ("Winlogon itself reported a subscriber taking too long", Sev::High),
            _ => ("Winlogon problem", Sev::Medium),
        };
    }
    if p.contains("grouppolicy") {
        return match id {
            1129 | 1054 | 1055 => ("Group Policy could not reach / resolve a domain controller", Sev::High),
            1058 | 1030 => ("Group Policy could not read policy files from SYSVOL", Sev::Medium),
            _ => ("Group Policy processing problem", Sev::Medium),
        };
    }
    if p == "netlogon" {
        return ("No domain controller could be contacted (sign-in falls back to cached credentials after a timeout)", Sev::High);
    }
    ("Sign-in related problem", Sev::Low)
}

pub fn error_events(r: &mut Report, days: u32) {
    r.section(&format!("Sign-in related warnings and errors (last {} days)", days));
    let providers = [
        "Microsoft-Windows-User Profiles Service",
        "Microsoft-Windows-User Profile General",
        "Microsoft-Windows-User Profiles General",
        "Microsoft-Windows-Winlogon",
        "Microsoft-Windows-GroupPolicy",
        "Microsoft-Windows-Folder Redirection",
        "NETLOGON",
    ];
    let pq = providers.iter().map(|p| format!("@Name='{}'", p)).collect::<Vec<_>>().join(" or ");
    let q = format!(
        "*[System[Provider[{}] and (Level=1 or Level=2 or Level=3) and {}]]",
        pq,
        evt::last_days(days)
    );
    let mut evs = load(r, "Application", &q);
    evs.extend(load(r, "System", &q));

    let mut groups: BTreeMap<(String, u32), Vec<&Event>> = BTreeMap::new();
    for e in &evs {
        groups.entry((e.provider.clone(), e.id)).or_default().push(e);
    }
    if groups.is_empty() {
        r.line("None found.");
        return;
    }
    // Profile failures for Windows' own per-session accounts (Font Driver Host, Window
    // Manager) are not about the person signing in. They are reported once, by the
    // leftover-TEMP-folders finding, and must not be presented as "your profile".
    let system_account_noise = evs.iter().any(|e| {
        e.data.iter().any(|(_, v)| v.contains("Font Driver Host") || v.contains("Window Manager"))
    });
    for ((provider, id), list) in &groups {
        let latest = list.iter().max_by_key(|e| e.time).unwrap();
        let (mut meaning, mut sev) = explain(provider, *id);
        if system_account_noise && provider.to_lowercase().contains("user profile") && matches!(*id, 1500 | 1509 | 1511 | 1533) {
            meaning = "Profile failure for a Windows system account (Font Driver Host / Window Manager), not for you - see the leftover TEMP folders finding";
            sev = Sev::Info;
        }
        r.line(format!(
            "{:>4}x  {} #{}  (latest {})",
            list.len(),
            provider.trim_start_matches("Microsoft-Windows-"),
            id,
            local(latest.time)
        ));
        r.line(format!("       {}", meaning));
        let b = latest.brief(150);
        if !b.is_empty() {
            r.line(format!("       data: {}", b));
        }
        // Winlogon's "subscriber is slow" warning repeats what the timing analysis already found.
        let duplicate = matches!(*id, 6005 | 6006)
            && r.findings.iter().any(|f| f.title.starts_with("Loading the user profile") || f.title.starts_with("Winlogon subscriber"));
        if sev <= Sev::Medium && !duplicate {
            r.find(
                sev,
                format!("{} (event {} x{})", meaning, id, list.len()),
                format!(
                    "Logged by {} {} time(s), most recently {}. Details: {}",
                    provider, list.len(), local(latest.time), if b.is_empty() { "(none)".into() } else { b }
                ),
                format!("Event Viewer > Windows Logs > filter on Event ID {} to read the full message; it names the file, server or component involved.", id),
            );
        }
    }
}

pub fn boot_perf(r: &mut Report, days: u32) {
    r.section("Boot performance (Windows' own diagnostics)");
    let q = format!("*[System[(EventID>=100 and EventID<=110) and {}]]", evt::last_days(days.max(60)));
    let evs = load(r, evt::DIAGPERF, &q);
    let boots: Vec<&Event> = evs.iter().filter(|e| e.id == 100).collect();
    if boots.is_empty() {
        r.line("No boot records found (the PC has not been restarted recently, the log was cleared, or - if not elevated - it is unreadable).");
        return;
    }
    r.line(format!(
        "{:<20} {:>11} {:>11} {:>11} {:>11} {:>8}",
        "Boot", "Total", "To desktop", "Profile", "Explorer", "Apps"
    ));
    let ms = |e: &Event, k: &str| e.num(k).map(fmt_ms).unwrap_or_else(|| "-".into());
    for e in boots.iter().rev().take(6).rev() {
        r.line(format!(
            "{:<20} {:>11} {:>11} {:>11} {:>11} {:>8}",
            local(e.time),
            ms(e, "BootTime"),
            ms(e, "MainPathBootTime"),
            ms(e, "BootUserProfileProcessingTime"),
            ms(e, "BootExplorerInitTime"),
            e.get("BootNumStartupApps").unwrap_or("-")
        ));
    }
    r.line("Total includes the post-desktop settling period; 'To desktop' excludes time spent at the sign-in screen.");
    if let Some(last) = boots.last() {
        let post = last.num("BootPostBootTime").unwrap_or(0);
        if post >= 60_000 {
            r.find(
                Sev::Medium,
                format!("PC stays busy for {} after the desktop appears", fmt_ms(post)),
                "Windows measured how long the disk and CPU took to settle after the last boot. A long tail means startup programs and services are thrashing the disk, which makes the desktop look ready but feel frozen.",
                "Trim startup programs. If the system drive is a hard disk rather than an SSD, that is the single biggest upgrade for sign-in time.",
            );
        }
    }

    // 101-110: Windows names the specific app/driver/service that slowed a boot.
    let mut agg: BTreeMap<String, (u32, u64)> = BTreeMap::new();
    for e in evs.iter().filter(|e| e.id > 100) {
        let kind = match e.id {
            101 => "app",
            102 => "driver",
            103 => "service",
            106 => "background optimisation",
            109 => "device",
            _ => "component",
        };
        let name = e.get("FriendlyName").filter(|s| !s.is_empty()).or(e.get("Name")).unwrap_or("?");
        let entry = agg.entry(format!("{}: {}", kind, name)).or_default();
        entry.0 += 1;
        entry.1 = entry.1.max(e.num("DegradationTime").unwrap_or(0));
    }
    if !agg.is_empty() {
        r.line("");
        r.line("Windows blamed these for slowing startup:");
        let mut v: Vec<_> = agg.into_iter().collect();
        v.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        for (name, (count, worst)) in v.iter().take(10) {
            r.line(format!("  {:>3}x  worst delay {:>10}  {}", count, fmt_ms(*worst), name));
        }
        if let Some((name, (count, worst))) = v.first() {
            if *worst >= 5000 {
                r.find(
                    if *worst >= 20_000 { Sev::High } else { Sev::Medium },
                    format!("Windows itself blames '{}' (up to {} extra)", name, fmt_ms(*worst)),
                    format!("The Diagnostics-Performance log recorded this {} time(s) as taking much longer than normal during startup.", count),
                    "Update, disable or uninstall that component and compare the next few restarts.",
                );
            }
        }
    }
}
