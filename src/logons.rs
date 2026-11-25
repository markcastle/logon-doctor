//! Reconstructs recent sign-ins from the event logs and times each phase.
//!
//! A Windows sign-in is a relay race. Winlogon tells a list of "subscribers" (Profiles, GPClient,
//! SessionEnv, ...) that a logon is happening and waits for each one in turn; the User Profile
//! Service loads the registry hive; Group Policy runs its extensions and logon scripts; then
//! Explorer starts and launches the startup apps. Each runner logs when it starts and stops, so
//! we can see exactly who was holding the baton when the time went missing.

use crate::evt::{self, Dt, Event};
use crate::report::{fmt_ms, local, local_ms, span, Report, Sev};
use chrono::Duration;

pub struct Sub {
    pub name: String,
    pub code: String,
    pub ms: Option<u64>,
}

pub struct Logon {
    /// User Profile Service received the logon notification.
    pub start: Dt,
    pub session: String,
    pub profile_end: Option<Dt>,
    pub hive: Option<String>,
    /// Last "hive loaded / profile type decided" event: the registry part of the load is done.
    pub hive_at: Option<Dt>,
    pub mine: bool,
    /// Earliest related Winlogon activity (slightly before `start`).
    pub win_start: Dt,
    /// Explorer began processing startup items = the desktop is up.
    pub ready: Option<Dt>,
    pub gp: Option<(Dt, Option<Dt>)>,
    pub cses: Vec<(String, u64)>,
    pub subs: Vec<Sub>,
    pub cmds: Vec<(String, u64)>,
    pub end: Dt,
}

impl Logon {
    pub fn profile_ms(&self) -> Option<u64> {
        self.profile_end.map(|e| span(self.start, e))
    }
    pub fn gp_ms(&self) -> Option<u64> {
        match self.gp {
            Some((a, Some(b))) => Some(span(a, b)),
            _ => None,
        }
    }
    pub fn slowest_sub(&self) -> Option<&Sub> {
        self.subs.iter().filter(|s| s.ms.is_some()).max_by_key(|s| s.ms)
    }
    /// Best estimate of "credentials accepted -> desktop visible".
    pub fn total_ms(&self) -> Option<u64> {
        if let Some(r) = self.ready {
            return Some(span(self.win_start, r));
        }
        let mut last = self.profile_end?;
        if let Some((_, Some(g))) = self.gp {
            last = last.max(g);
        }
        Some(span(self.win_start, last))
    }
}

fn load(r: &mut Report, channel: &str, ids: &[u32], days: u32) -> Vec<Event> {
    let idq = ids
        .iter()
        .map(|i| format!("EventID={}", i))
        .collect::<Vec<_>>()
        .join(" or ");
    let q = format!("*[System[({}) and {}]]", idq, evt::last_days(days));
    match evt::query(channel, &q, 50_000) {
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

/// Winlogon 811/812 payload is (notification code, subscriber name); identify by shape.
fn sub_key(e: &Event) -> (String, String) {
    (
        e.get("SubscriberName").or(e.first_text()).unwrap_or("?").to_string(),
        e.get("Event").or(e.first_numeric()).unwrap_or("?").to_string(),
    )
}

/// Winlogon identifies the notification type (logon, start shell, ...) only by number.
/// (2 and 12 confirmed against Winlogon's own 6005/6006 messages on Windows 10 22H2.)
fn code_name(code: &str) -> String {
    match code {
        "2" => "Logon".to_string(),
        "12" => "StartShell".to_string(),
        other => format!("event {}", other),
    }
}

pub fn collect(r: &mut Report, days: u32, profile_path: &str) -> Vec<Logon> {
    let ups = load(r, evt::UPS, &[1, 2, 5, 67], days);
    let wl = load(r, evt::WINLOGON, &[811, 812], days);
    let gp = load(r, evt::GP, &[4001, 8001, 5016, 6016, 7016], days);
    let sh = load(r, evt::SHELL, &[9705, 9707, 9708], days);

    let want_hive = format!("{}\\ntuser.dat", profile_path.trim_end_matches('\\')).to_lowercase();

    // Pass 1: profile-service events give us the skeleton (one entry per interactive sign-in).
    let mut logons: Vec<Logon> = Vec::new();
    for e in &ups {
        match e.id {
            1 => logons.push(Logon {
                start: e.time,
                session: e.first_numeric().unwrap_or("?").to_string(),
                profile_end: None,
                hive: None,
                hive_at: None,
                mine: false,
                win_start: e.time,
                ready: None,
                gp: None,
                cses: vec![],
                subs: vec![],
                cmds: vec![],
                end: e.time,
            }),
            5 | 67 => {
                if let Some(l) = logons.last_mut().filter(|l| l.profile_end.is_none()) {
                    l.hive_at = Some(e.time);
                }
                if let Some(l) = logons.last_mut().filter(|l| e.id == 5 && l.profile_end.is_none() && l.hive.is_none()) {
                    if let Some((_, v)) = e.data.iter().find(|(_, v)| v.to_lowercase().ends_with("ntuser.dat")) {
                        l.hive = Some(v.clone());
                    }
                }
            }
            2 => {
                let sess = e.first_numeric().unwrap_or("?");
                if let Some(l) = logons
                    .iter_mut()
                    .rev()
                    .find(|l| l.profile_end.is_none() && l.session == sess)
                {
                    // Ignore a "finished" that is absurdly far from its "received".
                    if span(l.start, e.time) < 3_600_000 {
                        l.profile_end = Some(e.time);
                    }
                }
            }
            _ => {}
        }
    }

    // Pass 2: hang the other channels' events onto each sign-in by time window.
    let n = logons.len();
    for i in 0..n {
        let next_start = if i + 1 < n { Some(logons[i + 1].start) } else { None };
        let l = &mut logons[i];
        l.mine = match &l.hive {
            Some(h) => h.to_lowercase() == want_hive,
            // Hive was already loaded (e.g. a service runs as this user) - cannot tell whose it is.
            None => true,
        };
        let mut end = l.start + Duration::minutes(30);
        if let Some(ns) = next_start {
            end = end.min(ns - Duration::seconds(15));
        }
        l.end = end;

        let lead = l.start - Duration::seconds(15);
        l.win_start = wl
            .iter()
            .find(|e| e.id == 811 && e.time >= lead && e.time <= l.start)
            .map(|e| e.time)
            .unwrap_or(l.start);

        l.ready = sh
            .iter()
            .find(|e| e.id == 9705 && e.time >= l.start && e.time < end)
            .map(|e| e.time);
        let limit = l.ready.unwrap_or(end);

        // Group Policy: 4001 = user logon processing starts, 8001 = it completes.
        if let Some(s) = gp.iter().find(|e| e.id == 4001 && e.time >= l.win_start && e.time < end) {
            let done = gp
                .iter()
                .find(|e| e.id == 8001 && e.time >= s.time && e.time < end)
                .map(|e| e.time);
            l.gp = Some((s.time, done));
            let gp_end = done.unwrap_or(end);
            for e in gp.iter().filter(|e| matches!(e.id, 5016 | 6016 | 7016) && e.time >= s.time && e.time <= gp_end) {
                let name = e.get("CSEExtensionName").or(e.first_text()).unwrap_or("?").to_string();
                let ms = e
                    .data
                    .iter()
                    .find(|(k, _)| {
                        let k = k.to_lowercase();
                        k.contains("elasped") || k.contains("elapsed")
                    })
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                l.cses.push((name, ms));
            }
            l.cses.sort_by(|a, b| b.1.cmp(&a.1));
        }

        // Winlogon subscribers: pair each "began" (811) with its "finished" (812).
        let window: Vec<&Event> = wl.iter().filter(|e| e.time >= l.win_start && e.time < end).collect();
        for (j, e) in window.iter().enumerate() {
            if e.id != 811 || e.time > limit {
                continue;
            }
            let key = sub_key(e);
            let done = window[j + 1..].iter().find(|x| x.id == 812 && sub_key(x) == key);
            l.subs.push(Sub {
                name: key.0,
                code: key.1,
                ms: done.map(|d| span(e.time, d.time)),
            });
        }

        // Startup commands launched by Explorer (Run keys / Startup folder).
        if let Some(ready) = l.ready {
            let cmds: Vec<&Event> = sh
                .iter()
                .filter(|e| e.time >= ready && e.time < end && matches!(e.id, 9707 | 9708))
                .collect();
            for (j, e) in cmds.iter().enumerate() {
                if e.id != 9707 {
                    continue;
                }
                let cmd = e.first_text().unwrap_or("?").to_string();
                if let Some(d) = cmds[j + 1..].iter().find(|x| x.id == 9708 && x.first_text() == Some(cmd.as_str())) {
                    l.cmds.push((cmd, span(e.time, d.time)));
                }
            }
            l.cmds.sort_by(|a, b| b.1.cmp(&a.1));
        }
    }
    logons
}

fn opt(ms: Option<u64>) -> String {
    ms.map(fmt_ms).unwrap_or_else(|| "-".into())
}

pub fn report(r: &mut Report, all: &[Logon], show: usize, days: u32) {
    r.section("Recent sign-ins (reconstructed from event logs)");
    let mine: Vec<&Logon> = all.iter().filter(|l| l.mine).collect();
    if mine.is_empty() {
        r.line(format!(
            "No sign-ins for this profile were found in the last {} days of event logs.",
            days
        ));
        r.line("(If the logs were readable, the profile may not have signed in during that period,");
        r.line(" or the 'User Profile Service/Operational' log has been cleared or disabled.)");
        return;
    }
    let recent: Vec<&Logon> = mine.iter().rev().take(show).rev().cloned().collect();

    r.line(format!(
        "{:<20} {:>12} {:>12} {:>12}   {}",
        "When", "To desktop", "Profile", "Grp Policy", "Slowest Winlogon subscriber"
    ));
    for l in &recent {
        let sub = l
            .slowest_sub()
            .map(|s| format!("{} / {} ({})", s.name, code_name(&s.code), opt(s.ms)))
            .unwrap_or_else(|| "-".into());
        let total = match (l.total_ms(), l.ready) {
            (Some(t), Some(_)) => fmt_ms(t),
            (Some(t), None) => format!(">={}", fmt_ms(t)),
            _ => "?".into(),
        };
        r.line(format!(
            "{:<20} {:>12} {:>12} {:>12}   {}",
            local(l.start),
            total,
            opt(l.profile_ms()),
            opt(l.gp_ms()),
            sub
        ));
    }
    r.line("");
    r.line("To desktop = Winlogon starts the logon -> Explorer begins running startup items.");
    r.line("Profile    = User Profile Service loading the profile (registry hive, roaming copy).");
    r.line("Grp Policy = user Group Policy incl. synchronous logon scripts.");

    let latest = *recent.last().unwrap();
    detail(r, latest, "Latest sign-in");
    let worst = recent.iter().max_by_key(|l| l.total_ms().unwrap_or(0)).cloned().unwrap();
    if !std::ptr::eq(worst, latest) && worst.total_ms().unwrap_or(0) > latest.total_ms().unwrap_or(0) + 5000 {
        detail(r, worst, "Slowest recent sign-in");
    }

    findings(r, &recent);
    timeline(r, latest);
}

fn detail(r: &mut Report, l: &Logon, title: &str) {
    r.line("");
    r.line(format!("--- {}: {} (session {}) ---", title, local(l.start), l.session));
    if let Some(p) = l.profile_end {
        r.line(format!("  Profile load          {:>12}", fmt_ms(span(l.start, p))));
        if let Some(h) = l.hive_at {
            r.line(format!("      registry hives loaded after   {:>10}", fmt_ms(span(l.start, h))));
            r.line(format!("      then inside profile service   {:>10}", fmt_ms(span(h, p))));
        }
    } else {
        r.line("  Profile load          never logged as finished (!)");
    }
    match l.gp {
        Some((a, Some(b))) => r.line(format!("  User Group Policy     {:>12}", fmt_ms(span(a, b)))),
        Some((_, None)) => r.line("  User Group Policy     started but no completion event found (!)"),
        None => r.line("  User Group Policy     no events (normal on a PC with no policies)"),
    }
    for (name, ms) in l.cses.iter().take(6) {
        r.line(format!("      extension {:<32} {:>10}", trunc(name, 32), fmt_ms(*ms)));
    }
    if !l.subs.is_empty() {
        r.line("  Winlogon subscribers (slowest first):");
        let mut subs: Vec<&Sub> = l.subs.iter().collect();
        subs.sort_by(|a, b| b.ms.unwrap_or(u64::MAX).cmp(&a.ms.unwrap_or(u64::MAX)));
        for s in subs.iter().take(8) {
            let t = s.ms.map(fmt_ms).unwrap_or_else(|| "NEVER FINISHED".into());
            r.line(format!("      {:<22} {:<16} {:>12}", trunc(&s.name, 22), code_name(&s.code), t));
        }
    }
    if let Some(ready) = l.ready {
        r.line(format!(
            "  Desktop/Explorer up   {:>12} after sign-in began",
            fmt_ms(span(l.win_start, ready))
        ));
    }
    if !l.cmds.is_empty() {
        r.line("  Startup commands that took longest to launch:");
        for (cmd, ms) in l.cmds.iter().take(5) {
            r.line(format!("      {:>10}  {}", fmt_ms(*ms), trunc(cmd, 90)));
        }
    }
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n.saturating_sub(3)).collect::<String>() + "..."
    } else {
        s.to_string()
    }
}

fn findings(r: &mut Report, recent: &[&Logon]) {
    let n = recent.len();
    let latest = recent[n - 1];

    // How long the worst and the latest took for a given phase.
    let stat = |f: &dyn Fn(&Logon) -> Option<u64>| -> (u64, u64, usize) {
        let vals: Vec<u64> = recent.iter().filter_map(|l| f(l)).collect();
        let worst = vals.iter().cloned().max().unwrap_or(0);
        let slow = vals.iter().filter(|v| **v >= 5000).count();
        (f(latest).unwrap_or(0), worst, slow)
    };

    let (last, worst, slow) = stat(&|l| l.profile_ms());
    if worst >= 5000 && last < 5000 {
        // It was slow, and the most recent sign-in is fine: say so rather than raising an alarm.
        r.find(
            Sev::Info,
            format!("Profile load is healthy now ({}), down from {} at worst", fmt_ms(last), fmt_ms(worst)),
            format!(
                "The latest sign-in loaded the profile in {}. It took over 5 s in {} of the last {} sign-ins, so whatever was slowing it has been dealt with.",
                fmt_ms(last), slow, n
            ),
            "Nothing to do. If it creeps back up, check the Temp folder line in the Profile section first.",
        );
    } else if worst >= 5000 {
        let sev = if last >= 15_000 || (worst >= 15_000 && slow * 2 >= n) { Sev::High } else { Sev::Medium };
        // Split the load: registry hives first, then everything the service does afterwards.
        let hive_ms = latest.hive_at.map(|h| span(latest.start, h));
        if matches!(hive_ms, Some(h) if h < 3000 && last >= 10_000) {
            r.suggest_capture = true;
        }
        let (detail, fix) = match hive_ms {
            Some(h) if h < 3000 && last >= 10_000 => (
                format!(
                    "The User Profile Service took over 5 s in {} of the last {} sign-ins. In the latest one the registry hives were loaded after only {}, \
                     so hive size and corruption are NOT the cause. The remaining {} was spent inside the profile service after that point, where Windows logs nothing: \
                     it is either waiting on another service/component it notifies about the profile load, or working through files itself.",
                    slow, n, fmt_ms(h), fmt_ms(last.saturating_sub(h))
                ),
                if r.have_capture {
                    "A live capture has already been taken: read the 'Live capture of a sign-in' section below. It shows whether the profile service was waiting or computing, \
                     which functions were on its busy thread, and which folders it was working in. If another finding in this list names a folder or key, start there."
                } else {
                    "Capture the next sign-in live: run 'logon-doctor.exe --capture' from an elevated prompt, sign out, sign back in, then run logon-doctor.exe again. \
                     It records what the profile service is waiting on or computing, second by second, and shows the result in this report."
                }.to_string(),
            ),
            _ => (
                format!(
                    "The User Profile Service took over 5 s in {} of the last {} sign-ins. A healthy local profile loads in well under 2 s. \
                     This phase is: loading NTUSER.DAT/UsrClass.dat, copying a roaming profile, and reaching any redirected folders or home drive.",
                    slow, n
                ),
                "See the 'Profile' section below: oversized registry hives, a roaming profile, and unreachable network paths are the usual culprits. \
                 Antivirus scanning the hive on load is another - try a temporary exclusion for NTUSER.DAT to test.".to_string(),
            ),
        };
        r.find(
            sev,
            format!("Loading the user profile is slow ({} latest, {} worst)", fmt_ms(last), fmt_ms(worst)),
            detail,
            fix,
        );
    }

    let (last, worst, slow) = stat(&|l| l.gp_ms());
    if worst >= 8000 {
        let sev = if last >= 30_000 || (worst >= 30_000 && slow * 2 >= n) { Sev::High } else { Sev::Medium };
        let cse = latest
            .cses
            .first()
            .filter(|c| c.1 >= 2000)
            .map(|c| format!(" In the latest sign-in the slowest extension was '{}' at {}.", c.0, fmt_ms(c.1)))
            .unwrap_or_default();
        r.find(
            sev,
            format!("Group Policy processing is slow ({} latest, {} worst)", fmt_ms(last), fmt_ms(worst)),
            format!(
                "User Group Policy took over 5 s in {} of the last {} sign-ins.{} Slow policy is nearly always network: \
                 a domain controller that is slow to find, a logon script or drive map waiting on a dead server, or a WMI filter.",
                slow, n, cse
            ),
            "Run 'gpresult /h gp.html' and look at the slowest extension. If it is 'Scripts', the logon script is the problem; \
             if 'Group Policy Drive Maps' / 'Folder Redirection', check those servers resolve and respond. Check DNS points at a reachable DC.",
        );
    }
    if recent.iter().any(|l| matches!(l.gp, Some((_, None)))) {
        r.find(
            Sev::Medium,
            "Group Policy started but never logged completion in at least one sign-in",
            "A 4001 (start) event had no matching 8001 (completed) event. Policy processing probably timed out or failed.",
            "Open Event Viewer > Applications and Services Logs > Microsoft > Windows > GroupPolicy > Operational and look for errors around that time.",
        );
    }

    // Winlogon subscribers other than the two we already reported on.
    let mut worst_sub: Option<(&Logon, &Sub)> = None;
    for l in recent {
        for s in &l.subs {
            let n = s.name.to_lowercase();
            if n == "profiles" || n == "gpclient" {
                continue;
            }
            let ms = s.ms.unwrap_or(u64::MAX);
            if worst_sub.map(|(_, w)| ms > w.ms.unwrap_or(u64::MAX)).unwrap_or(true) {
                worst_sub = Some((l, s));
            }
        }
    }
    if let Some((l, s)) = worst_sub {
        let ms = s.ms.unwrap_or(u64::MAX);
        if ms >= 3000 {
            let t = s.ms.map(fmt_ms).unwrap_or_else(|| "never finished".into());
            r.find(
                if ms >= 10_000 { Sev::High } else { Sev::Medium },
                format!("Winlogon subscriber '{}' held up sign-in ({})", s.name, t),
                format!(
                    "On {} Winlogon waited {} for '{}' to handle the '{}' notification. Winlogon calls these components one at a time and \
                     cannot continue until each returns.",
                    local(l.start), t, s.name, code_name(&s.code)
                ),
                subscriber_hint(&s.name),
            );
        }
    }

    // Time unaccounted for between the phases we can name.
    if let (Some(total), Some(_)) = (latest.total_ms(), latest.ready) {
        let named = latest.profile_ms().unwrap_or(0) + latest.gp_ms().unwrap_or(0);
        // Half a minute from credentials to Explorer running startup items is ordinary on a
        // well-used PC; only call it out when a full minute is unexplained.
        if total >= 60_000 && total > named * 2 + 10_000 {
            r.find(
                Sev::Medium,
                format!("{} of the latest sign-in is outside profile load and Group Policy", fmt_ms(total - named)),
                format!(
                    "The latest sign-in took {} to reach the desktop but profile + policy only explain {}. The remainder is typically \
                     another Winlogon subscriber, the shell (Explorer) starting, or app/AppX registration.",
                    fmt_ms(total), fmt_ms(named)
                ),
                "Look at the 'Biggest silent gaps' list and the timeline in the report file: the event logged right AFTER a long gap names what Windows was waiting for.",
            );
        }
        if total < 15_000 && recent.iter().all(|l| l.total_ms().unwrap_or(0) < 15_000) {
            r.find(
                Sev::Info,
                "Sign-in itself reaches the desktop quickly according to the logs",
                format!(
                    "Every recent sign-in got from credentials to Explorer in under 15 s (latest {}). If it still feels slow, the delay is \
                     either BEFORE this (boot, or authentication waiting for a domain controller) or AFTER it (startup programs hammering the disk).",
                    fmt_ms(total)
                ),
                "Check the 'Startup programs' and 'Boot performance' sections. Task Manager > Startup shows the measured impact of each item.",
            );
        }
    }

    if let Some((cmd, ms)) = latest.cmds.first() {
        if *ms >= 5000 {
            r.find(
                Sev::Low,
                format!("A startup command took {} to launch", fmt_ms(*ms)),
                format!("Explorer spent {} starting: {}", fmt_ms(*ms), cmd),
                "Disable it in Task Manager > Startup to see whether sign-in feels faster.",
            );
        }
    }
}

fn subscriber_hint(name: &str) -> String {
    match name.to_lowercase().as_str() {
        "sessionenv" | "termsrv" => "These are Remote Desktop components. Check the Remote Desktop Services / Remote Desktop Configuration services start cleanly, and look for display-driver problems.".into(),
        "sens" => "SENS (System Event Notification Service) is waiting on something registered with COM+ Event System. Check both services are running; a broken third-party SENS subscriber is the usual cause.".into(),
        "trustedinstaller" => "Windows servicing is finishing an update at sign-in. If it happens every time, run 'DISM /Online /Cleanup-Image /RestoreHealth' then 'sfc /scannow'.".into(),
        "schedule" => "Task Scheduler is slow to respond - look for a corrupt or very large number of scheduled tasks.".into(),
        "igfxcui" | "igfxtray" => "Intel graphics helper. Update or cleanly reinstall the Intel display driver.".into(),
        _ => format!("Search for the service or DLL named '{}'. If it belongs to third-party software (VPN, security, sync client), update or temporarily uninstall it to confirm.", name),
    }
}

/// Channels worth merging into a timeline of the latest sign-in.
const TIMELINE_CHANNELS: &[&str] = &[
    evt::WINLOGON,
    evt::UPS,
    evt::GP,
    evt::SHELL,
    "Microsoft-Windows-Folder Redirection/Operational",
    "Microsoft-Windows-OfflineFiles/Operational",
    "Microsoft-Windows-AppReadiness/Admin",
    "Microsoft-Windows-AppXDeploymentServer/Operational",
    "Microsoft-Windows-NetworkProfile/Operational",
    "Microsoft-Windows-Wcmsvc/Operational",
    "System",
    "Application",
];

fn short(channel: &str) -> String {
    channel
        .trim_start_matches("Microsoft-Windows-")
        .trim_end_matches("/Operational")
        .to_string()
}

fn known(e: &Event) -> &'static str {
    match (e.channel.as_str(), e.id) {
        (evt::UPS, 1) => "profile service: logon notification received",
        (evt::UPS, 2) => "profile service: logon processing finished",
        (evt::UPS, 5) => "profile service: registry hive loaded",
        (evt::UPS, 67) => "profile service: profile type decided",
        (evt::GP, 4001) => "group policy: user logon processing starts",
        (evt::GP, 8001) => "group policy: user logon processing done",
        (evt::GP, 4016) => "group policy: extension starts",
        (evt::GP, 5016) => "group policy: extension done",
        (evt::GP, 5326) => "group policy: domain controller located",
        (evt::GP, 4018) => "group policy: logon script starts",
        (evt::GP, 5018) => "group policy: logon script done",
        (evt::WINLOGON, 811) => "winlogon: subscriber began",
        (evt::WINLOGON, 812) => "winlogon: subscriber finished",
        (evt::SHELL, 9705) => "explorer: starts processing startup items",
        (evt::SHELL, 9706) => "explorer: finished a startup location",
        (evt::SHELL, 9707) => "explorer: launching startup command",
        (evt::SHELL, 9708) => "explorer: startup command launched",
        _ => "",
    }
}

/// Merge every relevant channel for the latest sign-in and point at where the clock ran with
/// nothing being logged. This works even when the cause is something this tool has never heard of.
fn timeline(r: &mut Report, l: &Logon) {
    let from = l.win_start - chrono::Duration::seconds(2);
    let to = l
        .ready
        .map(|t| t + chrono::Duration::seconds(5))
        .unwrap_or_else(|| (l.start + chrono::Duration::minutes(10)).min(l.end));
    let mut evs: Vec<Event> = Vec::new();
    for ch in TIMELINE_CHANNELS {
        let q = format!("*[System[{}]]", evt::between(from, to));
        if let Ok(v) = evt::query(ch, &q, 3000) {
            evs.extend(v);
        }
    }
    if evs.len() < 2 {
        return;
    }
    evs.sort_by_key(|e| e.time);

    let mut gaps: Vec<(u64, usize)> = evs
        .windows(2)
        .enumerate()
        .map(|(i, w)| (span(w[0].time, w[1].time), i))
        .filter(|(ms, _)| *ms >= 2000)
        .collect();
    gaps.sort_by(|a, b| b.0.cmp(&a.0));

    let describe = |e: &Event| {
        let k = known(e);
        format!(
            "{} {}[{} #{}] {}{}",
            local_ms(e.time),
            match e.level {
                1 | 2 => "ERROR ",
                3 => "WARN ",
                _ => "",
            },
            short(&e.channel),
            e.id,
            if k.is_empty() { String::new() } else { format!("{} - ", k) },
            e.brief(110)
        )
    };

    r.line("");
    r.line(format!(
        "--- Biggest silent gaps in the latest sign-in ({} events examined) ---",
        evs.len()
    ));
    if gaps.is_empty() {
        r.line("  None over 2 s - events were logged continuously.");
    }
    for (ms, i) in gaps.iter().take(5) {
        r.line(format!("  {} of silence", fmt_ms(*ms)));
        r.line(format!("      before: {}", describe(&evs[*i])));
        r.line(format!("      after : {}", describe(&evs[*i + 1])));
    }
    if !gaps.is_empty() {
        r.line("  The 'before' event is usually the thing that was running; 'after' is what finally unblocked.");
    }

    r.file_only("");
    r.file_only("--- Full timeline of the latest sign-in (report file only) ---");
    let mut prev = evs[0].time;
    for e in evs.iter().take(1500) {
        let d = span(prev, e.time);
        let mark = if d >= 2000 { format!("  <-- {} gap", fmt_ms(d)) } else { String::new() };
        r.file_only(format!("  {}{}", describe(e), mark));
        prev = e.time;
    }
}
