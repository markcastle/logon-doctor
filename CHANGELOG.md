# Changelog

Every release of Logon Doctor, newest first, written for the people who use it.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release on GitHub shows the matching section from this file.

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/markcastle/logon-doctor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/markcastle/logon-doctor/releases/tag/v0.1.0
