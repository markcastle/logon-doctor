//! `--clean-temp`: empties the user's Temp folder.
//!
//! This is the one command that deletes anything, so it is deliberately cautious:
//!
//! * It only ever touches `<profile>\AppData\Local\Temp`, and refuses if the path looks wrong.
//! * It shows what it is about to delete and asks first (unless `--yes`).
//! * Anything created or changed in the last 24 hours is left alone, because a running
//!   installer or app may still need it (`--all` overrides).
//! * Files that are in use fail to delete and are simply counted as skipped.
//! * Links and junctions are removed as links; it never follows one out of the Temp folder.

use crate::report::fmt_bytes;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};

#[derive(Default)]
struct Tally {
    files: u64,
    bytes: u64,
    failed: u64,
}

/// Delete one entry (file, link or whole folder). Never follows links.
fn remove(path: &Path, t: &mut Tally) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        t.failed += 1;
        return;
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        // A link or junction: remove the link itself, whichever kind it is.
        if std::fs::remove_dir(path).is_err() && std::fs::remove_file(path).is_err() {
            t.failed += 1;
        }
        return;
    }
    if ft.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                remove(&e.path(), t);
            }
        }
        // Fails if anything inside survived; that is not an extra failure worth counting.
        let _ = std::fs::remove_dir(path);
        return;
    }
    let size = meta.len();
    let mut ok = std::fs::remove_file(path).is_ok();
    if !ok && meta.permissions().readonly() {
        // Read-only files refuse deletion on Windows; clear the flag and try once more.
        let mut p = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        ok = std::fs::set_permissions(path, p).is_ok() && std::fs::remove_file(path).is_ok();
    }
    if ok {
        t.files += 1;
        t.bytes += size;
    } else {
        t.failed += 1;
    }
}

/// Files and bytes under a path, without following links.
fn measure(path: &Path) -> (u64, u64) {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return (0, 0) };
    if meta.file_type().is_symlink() {
        return (0, 0);
    }
    if !meta.is_dir() {
        return (1, meta.len());
    }
    let (mut f, mut b) = (0, 0);
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            let (ef, eb) = measure(&e.path());
            f += ef;
            b += eb;
        }
    }
    (f, b)
}

pub fn run(profile: &Path, assume_yes: bool, include_recent: bool) {
    let temp = profile.join(r"AppData\Local\Temp");
    // Guard rails: be certain this really is a profile's Temp folder before deleting from it.
    let shown = temp.display().to_string();
    let looks_right = shown.to_lowercase().ends_with(r"\appdata\local\temp")
        && profile.join("NTUSER.DAT").exists()
        && temp.is_dir();
    if !looks_right {
        println!("Refusing to clean '{}': it does not look like a user profile's Temp folder.", shown);
        return;
    }

    println!("Measuring {} ...", shown);
    let cutoff = SystemTime::now() - Duration::from_secs(24 * 3600);
    let mut targets = Vec::new();
    let (mut files, mut bytes, mut recent) = (0u64, 0u64, 0u64);
    let Ok(rd) = std::fs::read_dir(&temp) else {
        println!("Could not read the folder.");
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        let is_recent = std::fs::symlink_metadata(&path)
            .map(|m| {
                let newest = m.modified().ok().into_iter().chain(m.created().ok()).max();
                newest.map(|t| t > cutoff).unwrap_or(true)
            })
            .unwrap_or(true);
        if is_recent && !include_recent {
            recent += 1;
            continue;
        }
        let (f, b) = measure(&path);
        files += f;
        bytes += b;
        targets.push(path);
    }

    println!();
    println!("About to delete {} files ({}) in {} top-level items.", files, fmt_bytes(bytes), targets.len());
    if recent > 0 {
        println!("Leaving {} items created or changed in the last 24 hours (use --all to include them).", recent);
    }
    println!("Files that are in use will be skipped. This cannot be undone.");
    if targets.is_empty() {
        println!("Nothing to do.");
        return;
    }
    if !assume_yes {
        print!("Delete them? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled. Nothing was deleted.");
            return;
        }
    }

    let mut t = Tally::default();
    let total = targets.len();
    for (i, path) in targets.iter().enumerate() {
        remove(path, &mut t);
        if (i + 1) % 200 == 0 || i + 1 == total {
            print!("\r  {} of {} items...", i + 1, total);
            let _ = std::io::stdout().flush();
        }
    }
    println!();
    println!();
    println!("Deleted {} files, freeing {}.", t.files, fmt_bytes(t.bytes));
    if t.failed > 0 {
        println!("Skipped {} that were in use or protected. Close your apps and run it again to get more.", t.failed);
    }
    println!("Sign out and back in, then run logon-doctor to see the new sign-in time.");
}
