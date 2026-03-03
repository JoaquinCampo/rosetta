use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    if let Some(r) = try_iso8601_duration(input) {
        return Some(r);
    }
    if let Some(r) = try_informal_duration(input) {
        return Some(r);
    }

    None
}

fn build_detection(total_secs: f64, human: &str, format_name: &str, confidence: f64) -> Detection {
    let total_mins = total_secs / 60.0;
    let total_hours = total_secs / 3600.0;

    let fields = vec![
        ("Format".into(), format_name.to_string()),
        ("Human Readable".into(), human.to_string()),
        ("Total Seconds".into(), format_number(total_secs)),
        ("Total Minutes".into(), format_number(total_mins)),
        ("Total Hours".into(), format_number(total_hours)),
    ];

    Detection {
        label: "Duration".into(),
        confidence,
        fields,
    }
}

fn format_number(n: f64) -> String {
    if n == n.floor() {
        format!("{}", n as i64)
    } else {
        format!("{:.2}", n)
    }
}

fn try_iso8601_duration(input: &str) -> Option<Detection> {
    if !input.starts_with('P') {
        return None;
    }

    let rest = &input[1..];
    if rest.is_empty() {
        return None;
    }

    let (date_part, time_part) = if let Some(t_pos) = rest.find('T') {
        (&rest[..t_pos], &rest[t_pos + 1..])
    } else {
        (rest, "")
    };

    let mut total_secs: f64 = 0.0;
    let mut parts_desc = Vec::new();

    // Parse date portion: Y, M, W, D
    if !date_part.is_empty() {
        let mut num_buf = String::new();
        for ch in date_part.chars() {
            if ch.is_ascii_digit() || ch == '.' {
                num_buf.push(ch);
            } else {
                let val: f64 = num_buf.parse().ok()?;
                num_buf.clear();
                match ch {
                    'Y' => {
                        total_secs += val * 365.25 * 86400.0;
                        parts_desc.push(format_part(val, "year"));
                    }
                    'M' => {
                        total_secs += val * 30.44 * 86400.0;
                        parts_desc.push(format_part(val, "month"));
                    }
                    'W' => {
                        total_secs += val * 7.0 * 86400.0;
                        parts_desc.push(format_part(val, "week"));
                    }
                    'D' => {
                        total_secs += val * 86400.0;
                        parts_desc.push(format_part(val, "day"));
                    }
                    _ => return None,
                }
            }
        }
        if !num_buf.is_empty() {
            return None;
        }
    }

    // Parse time portion: H, M, S
    if !time_part.is_empty() {
        let mut num_buf = String::new();
        for ch in time_part.chars() {
            if ch.is_ascii_digit() || ch == '.' {
                num_buf.push(ch);
            } else {
                let val: f64 = num_buf.parse().ok()?;
                num_buf.clear();
                match ch {
                    'H' => {
                        total_secs += val * 3600.0;
                        parts_desc.push(format_part(val, "hour"));
                    }
                    'M' => {
                        total_secs += val * 60.0;
                        parts_desc.push(format_part(val, "minute"));
                    }
                    'S' => {
                        total_secs += val;
                        parts_desc.push(format_part(val, "second"));
                    }
                    _ => return None,
                }
            }
        }
        if !num_buf.is_empty() {
            return None;
        }
    }

    if parts_desc.is_empty() {
        return None;
    }

    let human = parts_desc.join(", ");
    Some(build_detection(total_secs, &human, "ISO 8601 duration", 0.9))
}

fn try_informal_duration(input: &str) -> Option<Detection> {
    // Match patterns like "1h30m", "2d12h", "90s", "3h", "45m30s"
    let lower = input.to_lowercase();

    // Must contain at least one digit followed by a unit letter
    if !lower.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }

    let valid_units = ['d', 'h', 'm', 's'];
    if !lower.chars().any(|c| valid_units.contains(&c)) {
        return None;
    }

    // Must not contain spaces or other non-duration chars
    for ch in lower.chars() {
        if !ch.is_ascii_digit() && !valid_units.contains(&ch) && ch != '.' {
            return None;
        }
    }

    let mut total_secs: f64 = 0.0;
    let mut parts_desc = Vec::new();
    let mut num_buf = String::new();
    let mut found_unit = false;

    for ch in lower.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            num_buf.push(ch);
        } else {
            if num_buf.is_empty() {
                return None;
            }
            let val: f64 = num_buf.parse().ok()?;
            num_buf.clear();
            found_unit = true;
            match ch {
                'd' => {
                    total_secs += val * 86400.0;
                    parts_desc.push(format_part(val, "day"));
                }
                'h' => {
                    total_secs += val * 3600.0;
                    parts_desc.push(format_part(val, "hour"));
                }
                'm' => {
                    total_secs += val * 60.0;
                    parts_desc.push(format_part(val, "minute"));
                }
                's' => {
                    total_secs += val;
                    parts_desc.push(format_part(val, "second"));
                }
                _ => return None,
            }
        }
    }

    // Trailing digits without a unit
    if !num_buf.is_empty() {
        return None;
    }

    if !found_unit || parts_desc.is_empty() {
        return None;
    }

    let human = parts_desc.join(", ");
    Some(build_detection(total_secs, &human, "informal duration", 0.85))
}

fn format_part(val: f64, unit: &str) -> String {
    let int_val = val as i64;
    if val == int_val as f64 {
        if int_val == 1 {
            format!("{} {}", int_val, unit)
        } else {
            format!("{} {}s", int_val, unit)
        }
    } else if val == 1.0 {
        format!("{} {}", val, unit)
    } else {
        format!("{} {}s", val, unit)
    }
}
