//! Logon Doctor - works out why signing in to Windows is slow.
//!
//! Strictly read-only: it reads event logs, the registry and file sizes, and writes one text
//! report next to itself. It changes nothing on the machine.

mod checks;
mod evt;
mod logons;
mod report;
mod watch;

use report::{wrap, Report, Sev};
use std::io::Write;
use winreg::enums::*;
use winreg::RegKey;

/// Release builds stamp the tag in via LOGON_DOCTOR_VERSION; local builds use Cargo.toml.
const VERSION: &str = match option_env!("LOGON_DOCTOR_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

const HELP: &str = "\
Logon Doctor - finds out why a Windows sign-in is slow (read-only).

Usage: logon-doctor.exe [options] [profile]\n\nWith no arguments it diagnoses the profile of whoever runs it.

  --user NAME    Diagnose another profile (folder name under C:\\Users). Needed when you
                 run this elevated as a different admin account than the slow one.
  --days N       How far back to read event logs (default 30).
  --logons N     How many recent sign-ins to tabulate (default 8).
  --no-pause     Do not wait for Enter before closing.
  --capture      Record the NEXT sign-in live (needs administrator). Sets up a temporary
                 background task, then you sign out and back in; the task removes itself.
                 Run logon-doctor.exe again afterwards to see what it caught.
  --watch        Live mode: wait for a sign-in and record what the User Profile Service
                 is waiting on, second by second. Must run while you are signed out,
                 so start it from a scheduled task as SYSTEM. Add --minutes N (default 30).
  --version      Print the version.
  --help         This text.

Run it from an elevated prompt ('Run as administrator') for the full picture.";

fn main() {
    let mut days = 30u32;
    let mut show = 8usize;
    let mut user: Option<String> = None;
    let mut pause = true;
    let mut watch = false;
    let mut capture = false;
    let mut self_remove = false;
    let mut minutes = 30u64;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--days" => days = args.next().and_then(|v| v.parse().ok()).unwrap_or(days),
            "--logons" => show = args.next().and_then(|v| v.parse().ok()).unwrap_or(show),
            "--user" => user = args.next(),
            "--no-pause" => pause = false,
            "--watch" => watch = true,
            "--capture" => capture = true,
            "--self-remove" => self_remove = true,
            "--minutes" => minutes = args.next().and_then(|v| v.parse().ok()).unwrap_or(minutes),
            "--version" | "-v" | "-V" => {
                println!("logon-doctor {}", VERSION);
                return;
            }
            "--help" | "-h" | "/?" => {
                println!("{}", HELP);
                return;
            }
            // A bare name or path (e.g. C:\Users\mark) is taken as the profile to diagnose.
            other if !other.starts_with('-') => {
                user = other.trim_end_matches('\\').rsplit('\\').next().map(|s| s.to_string())
            }
            other => {
                println!("Unknown option '{}'.\n\n{}", other, HELP);
                return;
            }
        }
    }

    if watch {
        watch::run(minutes.clamp(1, 720), self_remove);
        return;
    }

    let elevated = unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 };
    if capture {
        if !elevated {
            println!("--capture needs an elevated prompt (right-click > Run as administrator).");
        } else {
            arm_capture();
        }
        return;
    }
    let mut r = Report::default();
    r.line(format!("Logon Doctor {} - read-only sign-in diagnostics", VERSION));
    r.line(format!("Run at {}", report::local(chrono::Utc::now())));

    match checks::resolve_target(&mut r, user.as_deref()) {
        Some(t) => {
            // Prefer the target user's loaded hive; fall back to our own HKCU if it is us.
            let user_root = RegKey::predef(HKEY_USERS).open_subkey(&t.sid).ok().or_else(|| {
                if user.is_none() {
                    Some(RegKey::predef(HKEY_CURRENT_USER))
                } else {
                    r.blind_spots.push(format!(
                        "Registry of '{}' is not loaded (user not signed in) - per-user startup items, mapped drives and scripts were skipped",
                        t.name
                    ));
                    None
                }
            });
            checks::system_info(&mut r, &t, elevated);
            let all = logons::collect(&mut r, days, &t.path);
            logons::report(&mut r, &all, show.max(1), days);
            checks::profile(&mut r, &t, user_root.as_ref());
            checks::startup(&mut r, &t, user_root.as_ref());
            checks::policy(&mut r, user_root.as_ref());
        }
        None => {
            r.line("Continuing with machine-wide checks only. Use --user NAME to pick a profile.");
            checks::policy(&mut r, None);
        }
    }
    checks::profile_service(&mut r);
    checks::error_events(&mut r, days);
    checks::boot_perf(&mut r, days);

    if !elevated {
        r.blind_spots.insert(
            0,
            "Not running as administrator: boot diagnostics and some logs/tasks are unreadable".into(),
        );
    }
    let captured = show_capture(&mut r);
    verdict(&mut r);

    let name = format!(
        "LogonDoctor-report-{}.txt",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    // An elevated prompt starts in System32; never leave reports there. Fall back to the
    // tool's own folder, where capture logs live too.
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase();
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut candidates = Vec::new();
    if !cwd.display().to_string().to_lowercase().starts_with(&windir) {
        candidates.push(cwd.join(&name));
    }
    candidates.push(exe_dir().join(&name));
    if let Ok(tmp) = std::env::var("TEMP") {
        candidates.push(std::path::Path::new(&tmp).join(&name));
    }
    let saved = candidates.iter().find(|p| std::fs::write(p, r.text.as_bytes()).is_ok());
    println!();
    match saved {
        Some(p) => println!(
            "Full report (with event timeline) saved to: {}",
            std::fs::canonicalize(p)
                .map(|c| c.display().to_string().trim_start_matches(r"\\?\").to_string())
                .unwrap_or_else(|_| p.display().to_string())
        ),
        None => println!("Could not save the report file."),
    }

    // The logs ran out of answers: offer to catch the next sign-in in the act.
    if r.suggest_capture && !captured && pause {
        if elevated {
            print!("\nThe logs cannot say what the profile service is waiting on.\nRecord the next sign-in live to find out? (sets up a temporary task that removes itself) [y/N] ");
            let _ = std::io::stdout().flush();
            let mut answer = String::new();
            let _ = std::io::stdin().read_line(&mut answer);
            if answer.trim().eq_ignore_ascii_case("y") {
                arm_capture();
            }
        } else {
            println!("\nTo find out what the profile service is waiting on, run this as administrator: logon-doctor.exe --capture");
        }
    }

    if pause && launched_by_double_click() {
        print!("\nPress Enter to close...");
        let _ = std::io::stdout().flush();
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}

fn verdict(r: &mut Report) {
    r.section("VERDICT - most likely causes first");
    let mut findings = std::mem::take(&mut r.findings);
    findings.sort_by_key(|f| f.sev);
    let real = findings.iter().filter(|f| f.sev < Sev::Info).count();
    if real == 0 {
        r.line("No clear cause found in what could be read.");
        if !r.blind_spots.is_empty() {
            r.line("Several sources were unreadable (below) - re-run as administrator first.");
        } else {
            r.line("Next step: sign out, sign in, then run this again straight away so the slow");
            r.line("sign-in is the latest one, and read the 'silent gaps' list above.");
        }
    }
    for (i, f) in findings.iter().enumerate() {
        r.line("");
        r.line(format!("{}. [{}] {}", i + 1, f.sev.label().trim(), f.title));
        r.line(wrap(&f.detail, "     ", 86));
        r.line(wrap(&format!("Fix: {}", f.fix), "     ", 86));
    }
    if !r.blind_spots.is_empty() {
        r.line("");
        r.line("Could not check:");
        let spots = r.blind_spots.clone();
        for b in spots {
            r.line(format!("  - {}", b));
        }
    }
    r.findings = findings;
}

/// True when we own the console window (started from Explorer), so it would vanish on exit.
fn launched_by_double_click() -> bool {
    let mut pids = [0u32; 2];
    unsafe { windows_sys::Win32::System::Console::GetConsoleProcessList(pids.as_mut_ptr(), 2) == 1 }
}

fn exe_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default()
}

/// Newest LogonDoctor-watch-*.txt next to the exe, with its modification time.
fn latest_watch_log() -> Option<(std::path::PathBuf, std::time::SystemTime)> {
    std::fs::read_dir(exe_dir())
        .ok()?
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("LogonDoctor-watch-") && n.ends_with(".txt")
        })
        .filter_map(|e| Some((e.path(), e.metadata().ok()?.modified().ok()?)))
        .max_by_key(|x| x.1)
}

/// Start the live capture: a one-off SYSTEM task running `--watch`, because the recording has
/// to keep going while the user is signed out. The task deletes itself when it finishes.
fn arm_capture() -> bool {
    let exe = std::env::current_exe().unwrap_or_default();
    let before = std::time::SystemTime::now();
    let command = format!("\"{}\" --watch --self-remove", exe.display());
    let run = |args: &[&str]| {
        std::process::Command::new("schtasks")
            .args(args)
            .output()
            .map(|o| (o.status.success(), String::from_utf8_lossy(&o.stderr).trim().to_string()))
            .unwrap_or((false, "could not start schtasks.exe".into()))
    };
    let (ok, err) = run(&["/create", "/tn", watch::TASK, "/tr", &command, "/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/f"]);
    if !ok {
        println!("Could not create the capture task: {}", err);
        return false;
    }
    let (ok, err) = run(&["/run", "/tn", watch::TASK]);
    if !ok {
        println!("Could not start the capture task: {}", err);
        let _ = run(&["/delete", "/tn", watch::TASK, "/f"]);
        return false;
    }
    // Proof of life: the recorder writes its log file as soon as it starts.
    let mut alive = false;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if latest_watch_log().map(|(_, t)| t >= before).unwrap_or(false) {
            alive = true;
            break;
        }
    }
    if !alive {
        println!("The capture task was created but did not start writing its log in {}.", exe_dir().display());
        println!("(On a laptop, plug in the charger. The exe must be on a local drive.) Removing the task.");
        let _ = run(&["/delete", "/tn", watch::TASK, "/f"]);
        return false;
    }
    // It started - but did it stay up? A recorder that hits an error says so in its log.
    std::thread::sleep(std::time::Duration::from_secs(3));
    if let Some((path, _)) = latest_watch_log() {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if let Some(err) = text.lines().find(|l| l.starts_with("ERROR")) {
            println!("The recorder started but stopped straight away:");
            println!("  {}", err);
            println!("Nothing is armed. Please report this line; the task has been removed.");
            let _ = run(&["/delete", "/tn", watch::TASK, "/f"]);
            return false;
        }
    }
    println!();
    println!("Recording is armed for the next 30 minutes. Now:");
    println!("  1. Sign out (Start > your picture > Sign out) - not Lock, not Switch user.");
    println!("  2. Sign back in and wait for the desktop.");
    println!("  3. Run logon-doctor.exe again. The capture appears under 'Live capture'.");
    println!("The background task removes itself when it is done.");
    true
}

/// Fold the most recent live capture into the report. Returns true if one with a result exists.
fn show_capture(r: &mut Report) -> bool {
    let Some((path, _)) = latest_watch_log() else { return false };
    let Ok(text) = std::fs::read_to_string(&path) else { return false };
    r.section("Live capture of a sign-in");
    r.line(format!("From {}", path.display()));
    match text.find("=== SUMMARY") {
        Some(i) => {
            for l in text[i..].lines().skip(1) {
                r.line(l);
            }
            // The second-by-second log is useful to whoever interprets the report.
            r.file_only("");
            r.file_only("--- Capture log (report file only) ---");
            for l in text[..i].lines() {
                r.file_only(l);
            }
            true
        }
        None => {
            r.line("The capture did not record a completed sign-in. Its log so far:");
            for l in text.lines().rev().take(12).collect::<Vec<_>>().into_iter().rev() {
                r.line(format!("  {}", l));
            }
            false
        }
    }
}
