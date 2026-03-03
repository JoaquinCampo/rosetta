use crate::detect::Detection;
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, Utc};

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    if let Some(r) = try_iso8601_datetime(input) {
        return Some(r);
    }
    if let Some(r) = try_rfc2822(input) {
        return Some(r);
    }
    if let Some(r) = try_iso8601_date(input) {
        return Some(r);
    }
    if let Some(r) = try_common_datetime(input) {
        return Some(r);
    }
    if let Some(r) = try_common_date(input) {
        return Some(r);
    }

    None
}

fn build_detection(dt: DateTime<Utc>, format_name: &str, confidence: f64) -> Detection {
    let now = Utc::now();
    let diff = now.signed_duration_since(dt).num_seconds();
    let relative = format_relative(diff);

    let fields = vec![
        ("Format".into(), format_name.to_string()),
        ("ISO 8601".into(), dt.to_rfc3339()),
        ("RFC 2822".into(), dt.to_rfc2822()),
        ("UTC".into(), dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        ("Day of Week".into(), dt.format("%A").to_string()),
        ("Unix Timestamp".into(), dt.timestamp().to_string()),
        ("Relative".into(), relative),
    ];

    Detection {
        label: "Date/Time".into(),
        confidence,
        fields,
    }
}

fn build_date_detection(date: NaiveDate, format_name: &str, confidence: f64) -> Detection {
    let dt = date.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let now = Utc::now();
    let diff_days = now.signed_duration_since(dt).num_days();

    let relative = if diff_days == 0 {
        "today".into()
    } else if diff_days == 1 {
        "yesterday".into()
    } else if diff_days == -1 {
        "tomorrow".into()
    } else if diff_days > 0 {
        format!("{} days ago", diff_days)
    } else {
        format!("in {} days", -diff_days)
    };

    let fields = vec![
        ("Format".into(), format_name.to_string()),
        ("Date".into(), date.format("%Y-%m-%d").to_string()),
        ("ISO 8601".into(), dt.to_rfc3339()),
        ("Day of Week".into(), date.format("%A").to_string()),
        ("Unix Timestamp".into(), dt.timestamp().to_string()),
        ("Relative".into(), relative),
    ];

    Detection {
        label: "Date/Time".into(),
        confidence,
        fields,
    }
}

fn try_iso8601_datetime(input: &str) -> Option<Detection> {
    let dt = DateTime::parse_from_rfc3339(input).ok()?;
    Some(build_detection(dt.to_utc(), "ISO 8601 date-time", 0.9))
}

fn try_rfc2822(input: &str) -> Option<Detection> {
    let dt = DateTime::parse_from_rfc2822(input).ok()?;
    Some(build_detection(dt.to_utc(), "RFC 2822", 0.9))
}

fn try_iso8601_date(input: &str) -> Option<Detection> {
    if input.len() != 10 {
        return None;
    }
    let date = NaiveDate::parse_from_str(input, "%Y-%m-%d").ok()?;
    Some(build_date_detection(date, "ISO 8601 date", 0.85))
}

fn try_common_datetime(input: &str) -> Option<Detection> {
    let formats = [
        ("%Y-%m-%d %H:%M:%S", "YYYY-MM-DD HH:MM:SS"),
        ("%Y/%m/%d %H:%M:%S", "YYYY/MM/DD HH:MM:SS"),
        ("%d/%m/%Y %H:%M:%S", "DD/MM/YYYY HH:MM:SS"),
        ("%m/%d/%Y %H:%M:%S", "MM/DD/YYYY HH:MM:SS"),
    ];

    for (fmt, name) in &formats {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(input, fmt) {
            let dt = ndt.and_utc();
            return Some(build_detection(dt, name, 0.85));
        }
    }
    None
}

fn try_common_date(input: &str) -> Option<Detection> {
    let formats = [
        ("%b %d, %Y", "Mon DD, YYYY"),
        ("%B %d, %Y", "Month DD, YYYY"),
        ("%d/%m/%Y", "DD/MM/YYYY"),
        ("%m/%d/%Y", "MM/DD/YYYY"),
        ("%Y/%m/%d", "YYYY/MM/DD"),
    ];

    for (fmt, name) in &formats {
        if let Ok(date) = NaiveDate::parse_from_str(input, fmt) {
            if date.year() < 1900 || date.year() > 2200 {
                continue;
            }
            return Some(build_date_detection(date, name, 0.8));
        }
    }
    None
}

fn format_relative(total_secs: i64) -> String {
    if total_secs.abs() < 60 {
        return "just now".into();
    }

    let abs = total_secs.unsigned_abs() as i64;
    let (val, unit) = if abs < 3600 {
        (abs / 60, "minute")
    } else if abs < 86400 {
        (abs / 3600, "hour")
    } else if abs < 2_592_000 {
        (abs / 86400, "day")
    } else if abs < 31_536_000 {
        (abs / 2_592_000, "month")
    } else {
        (abs / 31_536_000, "year")
    };

    let plural = if val == 1 { "" } else { "s" };
    if total_secs > 0 {
        format!("{} {}{} ago", val, unit, plural)
    } else {
        format!("in {} {}{}", val, unit, plural)
    }
}
