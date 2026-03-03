use crate::detect::Detection;
use chrono::{Datelike, Duration, NaiveDate, Timelike, Utc};

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() != 5 {
        return None;
    }

    let ranges = [(0u32, 59u32), (0, 23), (1, 31), (1, 12), (0, 7)];
    let names = ["minute", "hour", "day of month", "month", "day of week"];

    for (i, part) in parts.iter().enumerate() {
        if !validate_field(part, ranges[i].0, ranges[i].1) {
            return None;
        }
    }

    let description = describe_cron(&parts);
    let next_runs = compute_next_runs(&parts, 5);

    let mut fields = vec![
        ("Expression".into(), input.to_string()),
        ("Description".into(), description),
    ];

    for (i, field) in parts.iter().enumerate() {
        fields.push((names[i].into(), describe_field(field, names[i])));
    }

    if !next_runs.is_empty() {
        let runs_str = next_runs
            .iter()
            .map(|r| r.format("%Y-%m-%d %H:%M UTC").to_string())
            .collect::<Vec<_>>()
            .join("\n");
        fields.push(("Next 5 runs".into(), runs_str));
    }

    Some(Detection {
        label: "Cron Expression".into(),
        confidence: 0.95,
        fields,
    })
}

fn validate_field(field: &str, min: u32, max: u32) -> bool {
    if field == "*" {
        return true;
    }

    for item in field.split(',') {
        if let Some(step_part) = item.strip_prefix("*/") {
            match step_part.parse::<u32>() {
                Ok(n) if n > 0 && n <= max => {}
                _ => return false,
            }
        } else if item.contains('/') {
            let parts: Vec<&str> = item.splitn(2, '/').collect();
            if parts.len() != 2 {
                return false;
            }
            if !validate_range_or_value(parts[0], min, max) {
                return false;
            }
            if parts[1].parse::<u32>().is_err() {
                return false;
            }
        } else if item.contains('-') {
            let bounds: Vec<&str> = item.splitn(2, '-').collect();
            if bounds.len() != 2 {
                return false;
            }
            let lo: u32 = match bounds[0].parse() {
                Ok(v) if v >= min && v <= max => v,
                _ => return false,
            };
            let hi: u32 = match bounds[1].parse() {
                Ok(v) if v >= min && v <= max => v,
                _ => return false,
            };
            if lo > hi {
                return false;
            }
        } else {
            match item.parse::<u32>() {
                Ok(n) if n >= min && n <= max => {}
                _ => return false,
            }
        }
    }
    true
}

fn validate_range_or_value(s: &str, min: u32, max: u32) -> bool {
    if s == "*" {
        return true;
    }
    if s.contains('-') {
        let bounds: Vec<&str> = s.splitn(2, '-').collect();
        if bounds.len() != 2 {
            return false;
        }
        let lo: u32 = match bounds[0].parse() {
            Ok(v) => v,
            _ => return false,
        };
        let hi: u32 = match bounds[1].parse() {
            Ok(v) => v,
            _ => return false,
        };
        lo >= min && hi <= max && lo <= hi
    } else {
        match s.parse::<u32>() {
            Ok(n) => n >= min && n <= max,
            _ => false,
        }
    }
}

fn describe_field(field: &str, name: &str) -> String {
    if field == "*" {
        return format!("every {}", name);
    }
    if let Some(step) = field.strip_prefix("*/") {
        return format!("every {} {}s", step, name);
    }
    if field.contains('-') && !field.contains(',') && !field.contains('/') {
        return format!("{} (range)", field);
    }
    if field.contains(',') {
        return format!("{} (list)", field);
    }
    field.to_string()
}

fn describe_cron(parts: &[&str]) -> String {
    let expr = parts.join(" ");
    match expr.as_str() {
        "* * * * *" => return "Every minute".into(),
        "0 * * * *" => return "Every hour".into(),
        "0 0 * * *" => return "Every day at midnight".into(),
        "0 0 * * 0" => return "Every Sunday at midnight".into(),
        "0 0 1 * *" => return "First day of every month at midnight".into(),
        "0 0 1 1 *" => return "Every year on January 1st at midnight".into(),
        _ => {}
    }

    if parts[0].starts_with("*/") && parts[1..] == ["*", "*", "*", "*"] {
        return format!("Every {} minutes", &parts[0][2..]);
    }
    if parts[0] == "0" && parts[1].starts_with("*/") && parts[2..] == ["*", "*", "*"] {
        return format!("Every {} hours", &parts[1][2..]);
    }

    let mut pieces = Vec::new();

    // Time part
    let time_desc = match (parts[0], parts[1]) {
        ("*", "*") => "Every minute".to_string(),
        (m, "*") if m.starts_with("*/") => format!("Every {} minutes", &m[2..]),
        (m, "*") => format!("At minute {}", m),
        ("*", h) => format!("Every minute during hour {}", describe_hour_range(h)),
        ("0", h) if h.contains('-') || h.contains(',') || h.starts_with("*/") => {
            format!("Every hour from {}", describe_hour_range(h))
        }
        ("0", h) => format!("At {:0>2}:00", h),
        (m, h) if m.starts_with("*/") => {
            format!("Every {} minutes during hour {}", &m[2..], describe_hour_range(h))
        }
        (m, h) => format!("At {}:{:0>2}", describe_hour_range(h), m),
    };
    pieces.push(time_desc);

    // Day of month
    if parts[2] != "*" {
        pieces.push(format!("on day {} of the month", parts[2]));
    }

    // Month
    if parts[3] != "*" {
        pieces.push(format!("in {}", describe_month(parts[3])));
    }

    // Day of week
    if parts[4] != "*" {
        pieces.push(describe_dow(parts[4]));
    }

    pieces.join(", ")
}

fn describe_hour_range(h: &str) -> String {
    if h.starts_with("*/") {
        return format!("every {} hours", &h[2..]);
    }
    if h.contains('-') {
        let bounds: Vec<&str> = h.splitn(2, '-').collect();
        return format!("{}:00-{}:00", bounds[0], bounds[1]);
    }
    h.to_string()
}

fn month_name(s: &str) -> &'static str {
    match s {
        "1" => "January",
        "2" => "February",
        "3" => "March",
        "4" => "April",
        "5" => "May",
        "6" => "June",
        "7" => "July",
        "8" => "August",
        "9" => "September",
        "10" => "October",
        "11" => "November",
        "12" => "December",
        _ => "unknown",
    }
}

fn describe_month(m: &str) -> String {
    if m.contains('-') {
        let bounds: Vec<&str> = m.splitn(2, '-').collect();
        format!("{}-{}", month_name(bounds[0]), month_name(bounds[1]))
    } else {
        month_name(m).to_string()
    }
}

fn dow_name(s: &str) -> &'static str {
    match s {
        "0" | "7" => "Sunday",
        "1" => "Monday",
        "2" => "Tuesday",
        "3" => "Wednesday",
        "4" => "Thursday",
        "5" => "Friday",
        "6" => "Saturday",
        _ => "unknown",
    }
}

fn describe_dow(d: &str) -> String {
    if d.contains('-') {
        let bounds: Vec<&str> = d.splitn(2, '-').collect();
        format!("{} through {}", dow_name(bounds[0]), dow_name(bounds[1]))
    } else {
        format!("on {}", dow_name(d))
    }
}

fn expand_field(field: &str, min: u32, max: u32) -> Vec<u32> {
    let mut values = Vec::new();
    for item in field.split(',') {
        if item.contains('/') {
            let parts: Vec<&str> = item.splitn(2, '/').collect();
            let step: u32 = parts[1].parse().unwrap_or(1);
            let (start, end) = if parts[0] == "*" {
                (min, max)
            } else if parts[0].contains('-') {
                let bounds: Vec<&str> = parts[0].splitn(2, '-').collect();
                (
                    bounds[0].parse().unwrap_or(min),
                    bounds[1].parse().unwrap_or(max),
                )
            } else {
                let s = parts[0].parse().unwrap_or(min);
                (s, max)
            };
            let mut v = start;
            while v <= end {
                values.push(v);
                v += step;
            }
        } else if item.contains('-') {
            let bounds: Vec<&str> = item.splitn(2, '-').collect();
            let lo: u32 = bounds[0].parse().unwrap_or(min);
            let hi: u32 = bounds[1].parse().unwrap_or(max);
            for v in lo..=hi {
                values.push(v);
            }
        } else if item == "*" {
            for v in min..=max {
                values.push(v);
            }
        } else if let Ok(v) = item.parse() {
            values.push(v);
        }
    }
    values.sort();
    values.dedup();
    values
}

fn compute_next_runs(parts: &[&str], count: usize) -> Vec<chrono::DateTime<Utc>> {
    let minutes = expand_field(parts[0], 0, 59);
    let hours = expand_field(parts[1], 0, 23);
    let doms = expand_field(parts[2], 1, 31);
    let months = expand_field(parts[3], 1, 12);
    let dows_raw = expand_field(parts[4], 0, 7);
    let dows: Vec<u32> = dows_raw
        .into_iter()
        .map(|d| if d == 7 { 0 } else { d })
        .collect();

    let now = Utc::now();
    let mut results = Vec::new();
    let mut current = now + Duration::minutes(1);
    current = current
        .with_second(0)
        .unwrap_or(current)
        .with_nanosecond(0)
        .unwrap_or(current);

    let limit = now + Duration::days(366 * 2);

    while results.len() < count && current < limit {
        let month = current.month();
        if !months.contains(&month) {
            current = advance_month(current, &months);
            continue;
        }

        let dom = current.day();
        if !doms.contains(&dom) {
            current = (current + Duration::days(1))
                .with_hour(0)
                .and_then(|d| d.with_minute(0))
                .unwrap_or(current + Duration::days(1));
            continue;
        }

        let dow = current.weekday().num_days_from_sunday();
        if !dows.contains(&dow) {
            current = (current + Duration::days(1))
                .with_hour(0)
                .and_then(|d| d.with_minute(0))
                .unwrap_or(current + Duration::days(1));
            continue;
        }

        let hour = current.hour();
        if !hours.contains(&hour) {
            current = (current + Duration::hours(1))
                .with_minute(0)
                .unwrap_or(current + Duration::hours(1));
            continue;
        }

        let minute = current.minute();
        if !minutes.contains(&minute) {
            current = current + Duration::minutes(1);
            continue;
        }

        results.push(current);
        current = current + Duration::minutes(1);
    }

    results
}

fn advance_month(
    dt: chrono::DateTime<Utc>,
    valid_months: &[u32],
) -> chrono::DateTime<Utc> {
    let mut year = dt.year();
    let mut month = dt.month() + 1;
    if month > 12 {
        month = 1;
        year += 1;
    }

    for _ in 0..24 {
        if valid_months.contains(&month) {
            if let Some(date) = NaiveDate::from_ymd_opt(year, month, 1) {
                return date.and_hms_opt(0, 0, 0).unwrap().and_utc();
            }
        }
        month += 1;
        if month > 12 {
            month = 1;
            year += 1;
        }
    }
    dt + Duration::days(366)
}
