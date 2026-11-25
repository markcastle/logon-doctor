# 🩺 Logon Doctor

[![Build](https://github.com/markcastle/logon-doctor/actions/workflows/build.yml/badge.svg)](https://github.com/markcastle/logon-doctor/actions/workflows/build.yml)
[![Latest release](https://img.shields.io/github/v/release/markcastle/logon-doctor)](https://github.com/markcastle/logon-doctor/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/markcastle/logon-doctor/total)](https://github.com/markcastle/logon-doctor/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20x64-0078D4)](#-install)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-b7410e)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A small Windows command-line tool that works out why signing in takes so long.

It exists because "my login takes three minutes" is miserable to debug by hand. The answer is nearly always already written down in the Windows event logs, but it is spread across a dozen channels with cryptic event IDs. Logon Doctor reads them all, rebuilds your recent sign-ins phase by phase, checks the usual suspects, and prints a ranked verdict.

One exe of about 600 KB. Nothing to install, no dependencies, and the normal run changes nothing on your PC. Only two explicit options do: `--capture` sets up a temporary recording task, and `--clean-temp` deletes temporary files after asking.

## 📦 Install

Paste this into PowerShell:

```powershell
irm https://raw.githubusercontent.com/markcastle/logon-doctor/main/install.ps1 | iex
```

This downloads the latest `logon-doctor.exe` to `%LOCALAPPDATA%\logon-doctor` and adds that folder to your user PATH. Run the same line again to upgrade. Nothing is changed system-wide.

If you'd rather do it by hand, download `logon-doctor.exe` from the [latest release](https://github.com/markcastle/logon-doctor/releases/latest) and put it anywhere you like.

The exe is not code-signed, so SmartScreen may warn on first run. Choose **More info**, then **Run anyway**, or check the file against `SHA256SUMS.txt` in the release first.

---

## ⚡ Quick start

### 1. Sign out and back in

This makes the slow sign-in the most recent one in the logs.

### 2. Run it from an elevated terminal

```bat
logon-doctor
```

It works without administrator rights, but some logs and the boot diagnostics are unreadable, so the picture is incomplete.

### 3. Read the verdict

Scroll to **VERDICT** at the end. Findings are ranked most likely cause first, each with a plain-English explanation and a fix. The full report, including a millisecond timeline of the latest sign-in, is saved as `LogonDoctor-report-<date>.txt` in the folder you ran it from.

### 4. If the logs don't have the answer, catch it live

```bat
logon-doctor --capture
```

Then sign out, sign back in, and run `logon-doctor` again. See [Live capture](#-live-capture) for what this does.

---

## 👀 What you're looking at

```
When                   To desktop      Profile   Grp Policy   Slowest Winlogon subscriber
2026-11-24 22:05:50    3 min 30 s   2 min 49 s        48 ms   Profiles / Logon (2 min 49 s)
2026-11-25 00:37:10    3 min 36 s   3 min 06 s        36 ms   Profiles / Logon (3 min 06 s)
```

A Windows sign-in is a relay race. Winlogon hands the baton to a list of components one at a time and cannot continue until each one returns. This table shows who was holding it.

| Column | Meaning |
| --- | --- |
| `To desktop` | From Winlogon starting the logon to Explorer running your startup items |
| `Profile` | The User Profile Service loading your profile |
| `Grp Policy` | User Group Policy, including logon scripts that run synchronously |
| `Slowest Winlogon subscriber` | The component Winlogon waited on longest |

Below the table you get a breakdown of the latest sign-in and a list of the **biggest silent gaps**: stretches where the clock ran and nothing was logged, with the event either side. That list is the safety net. It points at the problem even when the cause is something this tool has never heard of.

---

## 🔍 What it checks

| Area | What it looks for |
| --- | --- |
| ⏱️ Sign-in timing | Profile load, Group Policy and its extensions, every Winlogon subscriber, startup command launch times |
| 👤 Profile | Bloated `NTUSER.DAT` / `UsrClass.dat`, temporary profiles, broken `.bak` registrations, roaming profile size |
| 🧹 Temp folder | The file count under `%LOCALAPPDATA%\Temp`. Windows walks every file there at each sign-in, so a bloated Temp folder costs minutes |
| 🌐 Network paths | Dead or slow mapped drives, redirected folders and home shares, each probed with a timeout |
| 🚀 Startup load | Run keys, Startup folders, logon-triggered scheduled tasks, and whether Task Manager has them disabled |
| ⚙️ Settings | Policies that force sign-in to wait for the network or for scripts, a modified `Userinit`, disabled services the profile service depends on |
| 🗂️ Registry | A census of the user's registry: the largest branches and any key with thousands of entries |
| 🧱 Known bugs | The Windows 10 firewall-rule build-up, leftover `TEMP.*` profile folders |
| 📋 Windows' own records | Profile, Winlogon, Group Policy and Netlogon errors, plus the boot diagnostics that name slow apps, drivers and services |

---

## 🎥 Live capture

Sometimes the logs prove *where* the time goes but not *why*. A typical case: the profile service holds the sign-in for three minutes, yet the registry hives were loaded in the first half second and nothing is logged after that.

`logon-doctor --capture` watches the next sign-in as it happens. Once a second it asks Windows:

- What is each User Profile Service thread waiting on? This uses Wait Chain Traversal, the same API behind Task Manager's "Analyze wait chain". It follows a blocked call across processes, so it can say "the profile service is waiting on a reply from service X".
- Which processes were using CPU and disk during the wait? This covers the case where nothing is blocked and something is simply grinding.
- If the profile service itself is the one grinding, what code is it running? The capture samples the call stacks of its busy threads and reports which DLLs and functions keep showing up.
- If that code is walking files, which folders? The capture reads the paths off the busy thread's stack and shows them as a folder tree.

The recording has to keep running while you are signed out, so `--capture` creates a temporary scheduled task named `LogonDoctorWatch` that runs as SYSTEM. **This is the only part of the tool that is not read-only.** The task deletes itself after the sign-in, or after 30 minutes if you never sign out. It never modifies another process. To read a call stack it pauses the sampled thread for a few milliseconds, the same way Process Explorer and any profiler do.

The next normal run folds the result into the report under **Live capture of a sign-in**.

> Capture mode is newer and has had less real-world testing than the report. If it misbehaves, please open an issue with the `LogonDoctor-watch-*.txt` file.

---

## 🎛️ Options

```bat
logon-doctor                 :: diagnose the profile of whoever runs it
logon-doctor --user mark     :: diagnose another profile (folder name under C:\Users)
logon-doctor C:\Users\mark   :: same thing, a path works too
logon-doctor --days 90       :: read further back in the event logs (default 30)
logon-doctor --logons 20     :: tabulate more sign-ins (default 8)
logon-doctor --capture       :: record the next sign-in live (administrator)
logon-doctor --clean-temp    :: empty the Temp folder; asks first (--yes to skip, --all for recent files too)
logon-doctor --no-pause      :: never wait for Enter (for scripts)
logon-doctor --version
```

You only need `--user` when the elevated prompt belongs to a different account from the slow one, for example a standard user who types a separate admin password at the UAC prompt.

---

## 🔒 Privacy

Reports and capture logs contain usernames, SIDs, mapped drive paths, installed software and event log excerpts. Read one before you post it anywhere public. The repo's `.gitignore` excludes them so they can't be committed by accident.

The normal report makes no network connections other than probing the mapped drives and shares your own profile already points at. `--capture` makes one more: it downloads the debug symbols for `profsvc.dll` from Microsoft's public symbol server (`msdl.microsoft.com`) so call stacks show real function names.

---

## 🛠️ For developers

### How it's put together

| File | Job |
| --- | --- |
| `src/main.rs` | Argument handling, the order of the checks, the verdict, and arming a capture |
| `src/evt.rs` | The only code that talks to the Event Log API. Renders events as XML and flattens them into a plain `Event` struct |
| `src/logons.rs` | Rebuilds sign-ins from four channels, times the phases, and produces the gap timeline |
| `src/checks.rs` | Everything that inspects the machine as it is now: registry, file sizes, network paths, startup items |
| `src/watch.rs` | Live capture: wait chains, per-process CPU and disk deltas |
| `src/stacks.rs` | Call-stack sampling of busy threads in another process, and finding file paths on those stacks |
| `src/clean.rs` | `--clean-temp`: the only code that deletes anything, with its guard rails |
| `src/symbols.rs` | Downloads Microsoft's public PDB for a system DLL so stacks show real function names |
| `src/report.rs` | Output plumbing and the `Finding` type that every check reports through |
| `scripts/release-notes.sh` | Pulls one version's section out of `CHANGELOG.md` for the release text |

### Things worth knowing before you change it

- **Event fields are matched by shape as well as by name.** Field names in these logs vary between Windows builds and are barely documented. Where a name isn't certain, the code picks "the first numeric value" or "the first text value" instead. If you add a check, prefer that approach to trusting a name you saw on one machine.
- **Sign-ins are stitched together by time window.** The User Profile Service events give one skeleton entry per interactive logon; events from the other channels are attached if they fall inside that logon's window. There is no shared correlation ID to join on.
- **Thresholds are judgement calls.** "Profile load over 5 s is slow" and "a hive over 60 MB is bloated" are sensible defaults, not Microsoft figures. They live next to the check that uses them.
- **Every check reports through `Report::find`.** Give it a severity, a title, what it means, and a concrete fix. If you can't write the fix, it is probably information for the report body and not a finding.
- **Output is plain ASCII on purpose.** The Windows console code page mangles anything else.

### Building

The repo is set up to cross-compile from Linux, which is how CI builds releases:

```bash
sudo apt-get install -y gcc-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
cargo build --release
```

The exe lands in `target/x86_64-pc-windows-gnu/release/`.

On Windows with the standard MSVC toolchain, override the target that `.cargo/config.toml` selects:

```bat
cargo build --release --target x86_64-pc-windows-msvc
```

### Releasing

The version lives in one place: `version` in `Cargo.toml`. CI checks that the release tag matches it and that `CHANGELOG.md` has a section for it, so the tag, the release notes and what `logon-doctor --version` prints can never disagree.

1. Bump `version` in `Cargo.toml`.
2. In [`CHANGELOG.md`](CHANGELOG.md), rename `[Unreleased]` to the new version with today's date, and add a fresh empty `[Unreleased]` above it. Write entries for the people using the tool: what changed for them, not which functions moved.
3. Merge that to `main`.
4. Publish it, whichever way you prefer. The tag is the version number, with or without a leading `v`:

    - In the GitHub UI: **Releases > Draft a new release**, type the tag, publish. You can leave the description empty.
    - Or from a terminal:

```bash
git tag 0.2.0
git push origin 0.2.0
```

Either way the workflow builds the exe, attaches `logon-doctor.exe` and `SHA256SUMS.txt` to the release, and fills in that version's changelog section as the release text. If a release exists for the current version but has no exe yet, the next build on `main` attaches one. The install one-liner always fetches the latest release. Builds that aren't part of a release report themselves as `<version>-dev.<commit>`.

To preview the notes a release will get:

```bash
scripts/release-notes.sh 0.1.0
```

### Testing

There is no automated test suite yet. The tool can only really be exercised on Windows, against real event logs, and the cross-compiled exe does not run under Wine. Changes so far have been verified by running on Windows 10 22H2. A set of captured event XML fixtures for `evt.rs` and `logons.rs` would be the most valuable first addition.

---

## 📝 Changelog

What changed in each release is in [CHANGELOG.md](CHANGELOG.md). The same text appears on the [releases page](https://github.com/markcastle/logon-doctor/releases).

---

## 🧹 Uninstall

Delete `%LOCALAPPDATA%\logon-doctor` and remove it from your user PATH. If a capture was interrupted, this removes its task:

```bat
schtasks /delete /tn LogonDoctorWatch /f
```

---

## 📄 License

[MIT](LICENSE)
