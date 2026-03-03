use crate::detect::Detection;

fn parse_ipv4(input: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        octets[i] = part.parse::<u8>().ok()?;
    }
    Some(octets)
}

fn ipv4_type(octets: [u8; 4]) -> &'static str {
    match octets {
        [255, 255, 255, 255] => "Broadcast",
        [127, ..] => "Loopback",
        [10, ..] => "Private (RFC 1918)",
        [172, b, ..] if (16..=31).contains(&b) => "Private (RFC 1918)",
        [192, 168, ..] => "Private (RFC 1918)",
        [169, 254, ..] => "Link-Local",
        [a, ..] if (224..=239).contains(&a) => "Multicast",
        [a, ..] if a >= 240 => "Reserved",
        _ => "Public",
    }
}

fn ipv4_class(octets: [u8; 4]) -> &'static str {
    match octets[0] {
        0..=127 => "A",
        128..=191 => "B",
        192..=223 => "C",
        224..=239 => "D (Multicast)",
        240..=255 => "E (Reserved)",
    }
}

fn ipv4_to_decimal(octets: [u8; 4]) -> u32 {
    (octets[0] as u32) << 24
        | (octets[1] as u32) << 16
        | (octets[2] as u32) << 8
        | (octets[3] as u32)
}

fn detect_ipv4(input: &str) -> Option<Detection> {
    let octets = parse_ipv4(input)?;
    let decimal = ipv4_to_decimal(octets);

    Some(Detection {
        label: "IPv4 Address".to_string(),
        confidence: 0.95,
        fields: vec![
            ("Address".to_string(), input.to_string()),
            ("Type".to_string(), ipv4_type(octets).to_string()),
            ("Class".to_string(), ipv4_class(octets).to_string()),
            ("Decimal".to_string(), decimal.to_string()),
        ],
    })
}

fn parse_ipv6(input: &str) -> Option<[u16; 8]> {
    let input = input.trim();

    // Handle :: expansion
    let parts: Vec<&str> = if input.contains("::") {
        let halves: Vec<&str> = input.splitn(2, "::").collect();
        if halves.len() != 2 {
            return None;
        }
        let left: Vec<&str> = if halves[0].is_empty() {
            vec![]
        } else {
            halves[0].split(':').collect()
        };
        let right: Vec<&str> = if halves[1].is_empty() {
            vec![]
        } else {
            halves[1].split(':').collect()
        };
        if left.len() + right.len() > 8 {
            return None;
        }
        let missing = 8 - left.len() - right.len();
        let mut full = left;
        for _ in 0..missing {
            full.push("0");
        }
        full.extend(right);
        full
    } else {
        input.split(':').collect()
    };

    if parts.len() != 8 {
        return None;
    }

    let mut groups = [0u16; 8];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 4 {
            return None;
        }
        groups[i] = u16::from_str_radix(part, 16).ok()?;
    }
    Some(groups)
}

fn ipv6_expanded(groups: [u16; 8]) -> String {
    groups
        .iter()
        .map(|g| format!("{:04x}", g))
        .collect::<Vec<_>>()
        .join(":")
}

fn ipv6_abbreviated(groups: [u16; 8]) -> String {
    let mut best_start = None;
    let mut best_len = 0usize;
    let mut cur_start = None;
    let mut cur_len = 0usize;

    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if cur_start.is_none() {
                cur_start = Some(i);
                cur_len = 1;
            } else {
                cur_len += 1;
            }
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_start = None;
            cur_len = 0;
        }
    }

    if best_len < 2 {
        return groups
            .iter()
            .map(|g| format!("{:x}", g))
            .collect::<Vec<_>>()
            .join(":");
    }

    let start = best_start.unwrap();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < 8 {
        if i == start {
            if i == 0 {
                parts.push(String::new());
            }
            parts.push(String::new());
            i += best_len;
            if i == 8 {
                parts.push(String::new());
            }
        } else {
            parts.push(format!("{:x}", groups[i]));
            i += 1;
        }
    }
    parts.join(":")
}

fn ipv6_type(groups: [u16; 8]) -> &'static str {
    if groups == [0; 8] {
        return "Unspecified (::)";
    }
    if groups == [0, 0, 0, 0, 0, 0, 0, 1] {
        return "Loopback (::1)";
    }
    if groups[0] & 0xffc0 == 0xfe80 {
        return "Link-Local";
    }
    if groups[0] & 0xfe00 == 0xfc00 {
        return "Unique Local (ULA)";
    }
    if groups[0] >> 8 == 0xff {
        return "Multicast";
    }
    if groups[0] & 0xe000 == 0x2000 {
        return "Global Unicast";
    }
    "Other"
}

fn detect_ipv6(input: &str) -> Option<Detection> {
    let groups = parse_ipv6(input)?;

    Some(Detection {
        label: "IPv6 Address".to_string(),
        confidence: 0.95,
        fields: vec![
            ("Abbreviated".to_string(), ipv6_abbreviated(groups)),
            ("Expanded".to_string(), ipv6_expanded(groups)),
            ("Type".to_string(), ipv6_type(groups).to_string()),
        ],
    })
}

pub fn detect(input: &str) -> Option<Detection> {
    let trimmed = input.trim();

    if let Some(d) = detect_ipv4(trimmed) {
        return Some(d);
    }

    if trimmed.contains(':') {
        return detect_ipv6(trimmed);
    }

    None
}
