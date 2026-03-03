use crate::detect::Detection;
use chrono::{DateTime, Local, Utc};

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();
    let value: i64 = input.parse().ok()?;

    if value < 0 {
        return None;
    }

    // Only match values that look like real timestamps (after year 2000)
    let (dt, kind, confidence) = if (946_684_800..=4_102_444_800).contains(&value) {
        let dt = DateTime::from_timestamp(value, 0)?;
        (dt, "seconds", 0.8)
    } else if (1_000_000_000_000..=4_102_444_800_000).contains(&value) {
        let secs = value / 1000;
        let millis = (value % 1000) as u32 * 1_000_000;
        let dt = DateTime::from_timestamp(secs, millis)?;
        (dt, "milliseconds", 0.7)
    } else {
        return None;
    };

    let utc = dt.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string();
    let local: DateTime<Local> = dt.into();
    let local_str = local.format("%Y-%m-%d %H:%M:%S %Z").to_string();
    let iso = dt.to_rfc3339();
    let day_of_week = dt.format("%A").to_string();
    let relative = format_relative(dt);

    let mut fields = vec![
        ("Format".into(), format!("Unix timestamp ({})", kind)),
        ("UTC".into(), utc),
        ("Local".into(), local_str),
        ("ISO 8601".into(), iso),
        ("Day of Week".into(), day_of_week),
        ("Relative".into(), relative),
    ];

    if kind == "milliseconds" {
        fields.push(("Seconds".into(), format!("{}", value / 1000)));
    }

    Some(Detection {
        label: "Unix Timestamp".into(),
        confidence,
        fields,
    })
}

fn format_relative(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let total_secs = now.signed_duration_since(dt).num_seconds();

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
