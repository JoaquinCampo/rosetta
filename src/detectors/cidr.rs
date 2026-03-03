use crate::detect::Detection;

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
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

fn octets_to_u32(o: [u8; 4]) -> u32 {
    (o[0] as u32) << 24 | (o[1] as u32) << 16 | (o[2] as u32) << 8 | (o[3] as u32)
}

fn u32_to_dotted(v: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xff,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff
    )
}

pub fn detect(input: &str) -> Option<Detection> {
    let trimmed = input.trim();
    let slash_pos = trimmed.find('/')?;
    let ip_str = &trimmed[..slash_pos];
    let prefix_str = &trimmed[slash_pos + 1..];

    let octets = parse_ipv4(ip_str)?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }

    let ip = octets_to_u32(octets);
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let wildcard = !mask;
    let network = ip & mask;
    let broadcast = network | wildcard;

    let usable_hosts = if prefix >= 31 {
        if prefix == 32 {
            1u64
        } else {
            2u64
        }
    } else {
        (1u64 << (32 - prefix)) - 2
    };

    let first_usable = if prefix >= 31 {
        network
    } else {
        network + 1
    };
    let last_usable = if prefix >= 31 {
        broadcast
    } else {
        broadcast - 1
    };

    Some(Detection {
        label: "CIDR Notation".to_string(),
        confidence: 0.95,
        fields: vec![
            (
                "Network".to_string(),
                format!("{}/{}", u32_to_dotted(network), prefix),
            ),
            ("Subnet Mask".to_string(), u32_to_dotted(mask)),
            ("Wildcard Mask".to_string(), u32_to_dotted(wildcard)),
            ("Broadcast".to_string(), u32_to_dotted(broadcast)),
            ("First Usable".to_string(), u32_to_dotted(first_usable)),
            ("Last Usable".to_string(), u32_to_dotted(last_usable)),
            ("Usable Hosts".to_string(), usable_hosts.to_string()),
        ],
    })
}
