# Changelog

Every release of Logon Doctor, newest first, written for the people who use it.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release on GitHub shows the matching section from this file.

## [Unreleased]

Nothing yet.

## [0.3.0] - 2026-11-25

### Added

- **The capture now names the folders a busy profile service is walking.** It reads file paths off the busy thread's stack and shows them as a folder tree with the share of samples that mention each one.
- **Real function names.** `--capture` downloads Microsoft's public debug symbols for `profsvc.dll`, so call stacks show the actual function instead of the nearest exported one. If the download fails the capture still works with approximate names.
- **Profile registration dump.** The report prints the raw `ProfileList` values for the profile and any machine policy under `Policies\Microsoft\Windows\System`, which decide how the profile service treats the profile.

### Changed

- The capture's verdict is now based on what the busy thread was calling. 0.2.0 guessed "registry work" whenever disk reads were low, which was wrong: walking folders is answered from memory and barely registers as disk reads either.
- The registry census no longer flags `Shell\Bags` at 5,000 entries. Explorer caps that key at 5,000 by design.

### Notes

- `--capture` now makes one outbound request, to Microsoft's symbol server (`msdl.microsoft.com`), to fetch `profsvc.pdb`.

## [0.2.0] - 2026-11-25

### Added

- **Live capture now says what a busy profile service is running.** When the User Profile Service is burning CPU instead of waiting, the capture samples its busy threads' call stacks once a second and reports which DLLs and functions keep appearing. No debug symbols are needed to name the DLL.
- **Registry census.** Counts the keys in the user's registry and lists the largest branches and the keys with the most entries. A single key with thousands of children is a classic cause of a sign-in that is slow on the CPU with no disk activity.
- **Capture verdict line.** The capture states outright when the profile service was computing for the whole wait, and whether that looks like registry work or file work.
- **Session and start time for busy processes** in the capture, so a process that was running while you were signed out stands out.

### Changed

- Once a capture exists, the verdict points at its result instead of telling you to take another one.

### Notes

- To read a call stack, the capture pauses the sampled thread for a few milliseconds, as any profiler does. Earlier versions only observed.

## [0.1.1] - 2026-11-25

### Fixed

- **Live capture quit immediately** with "the User Profile Service (ProfSvc) is not running or could not be found". It now asks Windows for that service's process directly, and reports the Windows error code if that ever fails.
- **`--capture` said "armed" when the recorder had already died.** It now checks the recorder is still running a few seconds after starting, and tells you straight away if it is not.
- **Reports were saved into `C:\Windows\System32`** when run from an elevated prompt. They now go to the tool's own folder in that case.
- **Profile errors for Windows' own accounts were blamed on you.** Failures for "Font Driver Host" and "Window Manager" were listed as "Windows could not load your profile". They are now reported once, under the leftover temporary folders finding.

## [0.1.0] - 2026-11-25

First public release.

### Added

- **Sign-in timing report.** Rebuilds recent sign-ins from the Windows event logs and times each phase: profile load, Group Policy and its extensions, every Winlogon subscriber, and startup command launches.
- **Profile load split.** Shows how long the registry hives took to load versus the time spent inside the User Profile Service afterwards, so hive bloat can be ruled in or out at a glance.
- **Silent gap finder.** Merges a dozen event channels for the latest sign-in and lists the longest stretches where nothing was logged, with the event either side.
- **Profile checks.** Oversized `NTUSER.DAT` and `UsrClass.dat`, temporary profiles, broken `.bak` registrations, roaming profile size, and leftover `TEMP.*` profile folders.
- **Network path checks.** Mapped drives, redirected shell folders and home shares, each probed with a timeout so a dead server cannot hang the tool.
- **Startup inventory.** Run keys, Startup folders and logon-triggered scheduled tasks, including whether Task Manager has each one disabled.
- **Settings checks.** Policies that make sign-in wait for the network or for scripts, a modified `Userinit`, disabled services the profile service depends on, and the Windows 10 firewall-rule build-up.
- **Error summary.** Sign-in related warnings and errors from the profile service, Winlogon, Group Policy and Netlogon, explained in plain English.
- **Boot diagnostics.** Windows' own records of which apps, drivers and services slowed startup.
- **Ranked verdict.** Findings ordered most likely cause first, each with an explanation and a fix, plus a full text report saved alongside.
- **Live capture (`--capture`).** Records the next sign-in as it happens: what each User Profile Service thread is waiting on, and which processes used the most CPU and disk. Runs through a temporary SYSTEM task that removes itself.
- **One-line installer.** `install.ps1` downloads the latest release to `%LOCALAPPDATA%\logon-doctor` and adds it to the user PATH.

### Known limitations

- Live capture has had far less real-world testing than the report.
- Verified on Windows 10 22H2 only. Event field names differ between Windows builds, so a section may come back empty elsewhere.
- No automated tests yet.

[Unreleased]: https://github.com/markcastle/logon-doctor/compare/0.3.0...HEAD
[0.3.0]: https://github.com/markcastle/logon-doctor/releases/tag/0.3.0
[0.2.0]: https://github.com/markcastle/logon-doctor/releases/tag/0.2.0
[0.1.1]: https://github.com/markcastle/logon-doctor/releases/tag/0.1.1
[0.1.0]: https://github.com/markcastle/logon-doctor/releases/tag/0.1.0
