use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    if !input.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let (special_bits, owner, group, other, confidence) = match input.len() {
        3 => {
            let o = parse_octal_digit(input.as_bytes()[0])?;
            let g = parse_octal_digit(input.as_bytes()[1])?;
            let t = parse_octal_digit(input.as_bytes()[2])?;
            (0u8, o, g, t, 0.75)
        }
        4 => {
            let s = parse_octal_digit(input.as_bytes()[0])?;
            let o = parse_octal_digit(input.as_bytes()[1])?;
            let g = parse_octal_digit(input.as_bytes()[2])?;
            let t = parse_octal_digit(input.as_bytes()[3])?;
            if s > 7 {
                return None;
            }
            let confidence = if input.starts_with('0') { 0.85 } else { 0.85 };
            (s, o, g, t, confidence)
        }
        _ => return None,
    };

    let symbolic = format_symbolic(special_bits, owner, group, other);

    let mut fields = Vec::new();
    fields.push(("Symbolic".into(), symbolic));
    fields.push(("Owner".into(), describe_perms(owner)));
    fields.push(("Group".into(), describe_perms(group)));
    fields.push(("Other".into(), describe_perms(other)));

    if special_bits != 0 {
        let mut specials = Vec::new();
        if special_bits & 4 != 0 {
            specials.push("setuid");
        }
        if special_bits & 2 != 0 {
            specials.push("setgid");
        }
        if special_bits & 1 != 0 {
            specials.push("sticky bit");
        }
        fields.push(("Special Bits".into(), specials.join(", ")));
    }

    if let Some(name) = common_permission_name(special_bits, owner, group, other) {
        fields.push(("Common Name".into(), name.to_string()));
    }

    Some(Detection {
        label: "Unix Permissions".into(),
        confidence,
        fields,
    })
}

fn parse_octal_digit(b: u8) -> Option<u8> {
    if b >= b'0' && b <= b'7' {
        Some(b - b'0')
    } else {
        None
    }
}

fn format_symbolic(special: u8, owner: u8, group: u8, other: u8) -> String {
    let mut s = String::with_capacity(9);

    // Owner
    s.push(if owner & 4 != 0 { 'r' } else { '-' });
    s.push(if owner & 2 != 0 { 'w' } else { '-' });
    if special & 4 != 0 {
        s.push(if owner & 1 != 0 { 's' } else { 'S' });
    } else {
        s.push(if owner & 1 != 0 { 'x' } else { '-' });
    }

    // Group
    s.push(if group & 4 != 0 { 'r' } else { '-' });
    s.push(if group & 2 != 0 { 'w' } else { '-' });
    if special & 2 != 0 {
        s.push(if group & 1 != 0 { 's' } else { 'S' });
    } else {
        s.push(if group & 1 != 0 { 'x' } else { '-' });
    }

    // Other
    s.push(if other & 4 != 0 { 'r' } else { '-' });
    s.push(if other & 2 != 0 { 'w' } else { '-' });
    if special & 1 != 0 {
        s.push(if other & 1 != 0 { 't' } else { 'T' });
    } else {
        s.push(if other & 1 != 0 { 'x' } else { '-' });
    }

    s
}

fn describe_perms(bits: u8) -> String {
    let mut parts = Vec::new();
    if bits & 4 != 0 {
        parts.push("read");
    }
    if bits & 2 != 0 {
        parts.push("write");
    }
    if bits & 1 != 0 {
        parts.push("execute");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

fn common_permission_name(special: u8, owner: u8, group: u8, other: u8) -> Option<&'static str> {
    let full = (special as u16) * 1000 + (owner as u16) * 100 + (group as u16) * 10 + other as u16;
    match full {
        755 => Some("Standard directory / executable"),
        644 => Some("Standard file"),
        600 => Some("Private file (owner only)"),
        700 => Some("Private directory / executable (owner only)"),
        777 => Some("Full permissions (world-writable)"),
        666 => Some("Read/write for everyone"),
        444 => Some("Read-only for everyone"),
        555 => Some("Read/execute for everyone"),
        775 => Some("Group-writable directory"),
        664 => Some("Group-writable file"),
        750 => Some("Group-accessible directory"),
        640 => Some("Group-readable file"),
        400 => Some("Read-only by owner"),
        744 => Some("Owner-executable, others read-only"),
        4755 => Some("Setuid executable"),
        2755 => Some("Setgid directory"),
        1777 => Some("Sticky bit directory (e.g., /tmp)"),
        1755 => Some("Sticky bit directory"),
        _ => None,
    }
}
