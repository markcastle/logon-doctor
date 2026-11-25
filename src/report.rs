//! Output plumbing: everything goes to the console and into a text report, and anything that
//! looks like a cause of slowness is collected as a `Finding` so it can be ranked at the end.

use chrono::{DateTime, Local, Utc};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sev {
    High,
    Medium,
    Low,
    Info,
}

impl Sev {
    pub fn label(self) -> &'static str {
        match self {
            Sev::High => "HIGH  ",
            Sev::Medium => "MEDIUM",
            Sev::Low => "LOW   ",
            Sev::Info => "INFO  ",
        }
    }
}

pub struct Finding {
    pub sev: Sev,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

#[derive(Default)]
pub struct Report {
    pub text: String,
    pub findings: Vec<Finding>,
    /// Things we could not look at (usually: not elevated).
    pub blind_spots: Vec<String>,
    /// The logs cannot explain the delay; a live capture of the next sign-in would.
    pub suggest_capture: bool,
}

impl Report {
    pub fn line(&mut self, s: impl AsRef<str>) {
        println!("{}", s.as_ref());
        self.text.push_str(s.as_ref());
        self.text.push_str("\r\n");
    }

    /// Written to the report file only - for bulky detail that would drown the console.
    pub fn file_only(&mut self, s: impl AsRef<str>) {
        self.text.push_str(s.as_ref());
        self.text.push_str("\r\n");
    }

    pub fn section(&mut self, title: &str) {
        self.line("");
        self.line(format!("=== {} {}", title, "=".repeat(74usize.saturating_sub(title.len()))));
    }

    pub fn find(&mut self, sev: Sev, title: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) {
        self.findings.push(Finding {
            sev,
            title: title.into(),
            detail: detail.into(),
            fix: fix.into(),
        });
    }
}

pub fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{} ms", ms)
    } else if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{} min {:02} s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

pub fn fmt_bytes(b: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    let f = b as f64;
    if f >= 1024.0 * MB {
        format!("{:.2} GB", f / (1024.0 * MB))
    } else if f >= MB {
        format!("{:.1} MB", f / MB)
    } else {
        format!("{:.0} KB", f / 1024.0)
    }
}

pub fn local(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn local_ms(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%H:%M:%S%.3f").to_string()
}

/// Milliseconds from a to b, clamped at zero.
pub fn span(a: DateTime<Utc>, b: DateTime<Utc>) -> u64 {
    (b - a).num_milliseconds().max(0) as u64
}

/// Word-wrap for the findings list.
pub fn wrap(s: &str, indent: &str, width: usize) -> String {
    let mut out = String::new();
    for para in s.split('\n') {
        let mut col = 0;
        out.push_str(indent);
        for word in para.split_whitespace() {
            if col > 0 && col + 1 + word.len() > width {
                out.push_str("\r\n");
                out.push_str(indent);
                col = 0;
            } else if col > 0 {
                out.push(' ');
                col += 1;
            }
            out.push_str(word);
            col += word.len();
        }
        out.push_str("\r\n");
    }
    out.trim_end().to_string()
}
