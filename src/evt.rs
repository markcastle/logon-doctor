//! Thin wrapper over the Windows Event Log API (wevtapi).
//!
//! Everything interesting about a slow sign-in is already written down by Windows in a handful of
//! "Operational" event channels. We pull events out as XML and flatten them into a simple struct
//! so the analysis code never has to touch FFI.

use chrono::{DateTime, SecondsFormat, Utc};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml,
};

pub const UPS: &str = "Microsoft-Windows-User Profile Service/Operational";
pub const WINLOGON: &str = "Microsoft-Windows-Winlogon/Operational";
pub const GP: &str = "Microsoft-Windows-GroupPolicy/Operational";
pub const SHELL: &str = "Microsoft-Windows-Shell-Core/Operational";
pub const DIAGPERF: &str = "Microsoft-Windows-Diagnostics-Performance/Operational";

pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

pub type Dt = DateTime<Utc>;

#[derive(Debug, Clone)]
pub struct Event {
    pub channel: String,
    pub provider: String,
    pub id: u32,
    pub level: u8,
    pub time: Dt,
    /// Flattened EventData / UserData payload as (name, value). Names can be empty.
    pub data: Vec<(String, String)>,
}

impl Event {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.data
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn num(&self, name: &str) -> Option<u64> {
        self.get(name).and_then(|v| v.trim().parse().ok())
    }

    /// First payload value that is purely numeric (field names vary between Windows builds,
    /// so several callers identify fields by shape rather than by name).
    pub fn first_numeric(&self) -> Option<&str> {
        self.data
            .iter()
            .map(|(_, v)| v.as_str())
            .find(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()))
    }

    pub fn first_text(&self) -> Option<&str> {
        self.data
            .iter()
            .map(|(_, v)| v.as_str())
            .find(|v| !v.is_empty() && !v.chars().all(|c| c.is_ascii_digit()))
    }

    /// Compact one-line payload for timelines.
    pub fn brief(&self, max: usize) -> String {
        let mut s = String::new();
        for (k, v) in &self.data {
            if v.is_empty() {
                continue;
            }
            if !s.is_empty() {
                s.push_str(", ");
            }
            if !k.is_empty() {
                s.push_str(k);
                s.push('=');
            }
            s.push_str(&v.replace(['\r', '\n'], " "));
            if s.chars().count() > max {
                break;
            }
        }
        if s.chars().count() > max {
            s = s.chars().take(max).collect::<String>() + "...";
        }
        s
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// XPath fragment: events from the last `days` days.
pub fn last_days(days: u32) -> String {
    format!(
        "TimeCreated[timediff(@SystemTime) <= {}]",
        days as u64 * 86_400_000
    )
}

/// XPath fragment: events between two instants.
pub fn between(a: Dt, b: Dt) -> String {
    format!(
        "TimeCreated[@SystemTime>='{}' and @SystemTime<='{}']",
        a.to_rfc3339_opts(SecondsFormat::Millis, true),
        b.to_rfc3339_opts(SecondsFormat::Millis, true)
    )
}

/// Run an XPath query against a channel. Returns events oldest-first, keeping only the newest
/// `limit`. The error is a raw Win32 error code (5 = access denied, 15007 = no such channel).
pub fn query(channel: &str, xpath: &str, limit: usize) -> Result<Vec<Event>, u32> {
    let wchannel = wide(channel);
    let wquery = wide(xpath);
    let mut out = Vec::new();
    unsafe {
        let h = EvtQuery(
            0 as _,
            wchannel.as_ptr(),
            wquery.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        );
        if h == 0 as _ {
            return Err(GetLastError());
        }
        let mut buf: Vec<u16> = vec![0; 32 * 1024];
        'outer: loop {
            let mut handles = [0isize; 64];
            let mut returned: u32 = 0;
            let ok = EvtNext(
                h,
                handles.len() as u32,
                handles.as_mut_ptr() as _,
                2000,
                0,
                &mut returned,
            );
            if ok == 0 || returned == 0 {
                break;
            }
            for (i, &eh) in handles[..returned as usize].iter().enumerate() {
                if let Some(xml) = render(eh as _, &mut buf) {
                    if let Some(ev) = parse(&xml, channel) {
                        out.push(ev);
                    }
                }
                EvtClose(eh as _);
                if out.len() >= limit {
                    for &rest in &handles[i + 1..returned as usize] {
                        EvtClose(rest as _);
                    }
                    break 'outer;
                }
            }
        }
        EvtClose(h);
    }
    out.reverse();
    Ok(out)
}

unsafe fn render(event: isize, buf: &mut Vec<u16>) -> Option<String> {
    let mut used: u32 = 0;
    let mut props: u32 = 0;
    for _ in 0..2 {
        let ok = EvtRender(
            0 as _,
            event as _,
            EvtRenderEventXml,
            (buf.len() * 2) as u32,
            buf.as_mut_ptr() as _,
            &mut used,
            &mut props,
        );
        if ok != 0 {
            let n = (used as usize / 2).min(buf.len());
            let slice = &buf[..n];
            let end = slice.iter().position(|&c| c == 0).unwrap_or(n);
            return Some(String::from_utf16_lossy(&slice[..end]));
        }
        // ERROR_INSUFFICIENT_BUFFER: `used` holds the byte count we need.
        if GetLastError() != 122 {
            return None;
        }
        buf.resize(used as usize / 2 + 2, 0);
    }
    None
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn parse(xml: &str, channel: &str) -> Option<Event> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();
    let sys = child(root, "System")?;
    let id: u32 = child(sys, "EventID")?.text()?.trim().parse().ok()?;
    let level: u8 = child(sys, "Level")
        .and_then(|n| n.text())
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(4);
    let time = child(sys, "TimeCreated")?.attribute("SystemTime")?;
    let time = DateTime::parse_from_rfc3339(time).ok()?.with_timezone(&Utc);
    let provider = child(sys, "Provider")
        .and_then(|n| n.attribute("Name"))
        .unwrap_or("")
        .to_string();

    let mut data = Vec::new();
    if let Some(ed) = child(root, "EventData") {
        for d in ed.children().filter(|c| c.is_element()) {
            data.push((
                d.attribute("Name").unwrap_or("").to_string(),
                d.text().unwrap_or("").trim().to_string(),
            ));
        }
    }
    if let Some(ud) = child(root, "UserData") {
        // UserData is free-form: take every leaf element.
        for d in ud.descendants().filter(|c| c.is_element()) {
            if !d.children().any(|c| c.is_element()) {
                data.push((
                    d.tag_name().name().to_string(),
                    d.text().unwrap_or("").trim().to_string(),
                ));
            }
        }
    }
    Some(Event {
        channel: channel.to_string(),
        provider,
        id,
        level,
        time,
        data,
    })
}
