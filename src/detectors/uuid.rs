use crate::detect::Detection;

fn is_hex(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn parse_hex_bytes(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| is_hex(*b)).collect();
    hex.chunks(2)
        .map(|pair| (hex_val(pair[0]) << 4) | hex_val(pair[1]))
        .collect()
}

pub fn detect(input: &str) -> Option<Detection> {
    let trimmed = input.trim();

    if trimmed.len() != 36 {
        return None;
    }

    let bytes = trimmed.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return None;
    }

    for &(start, end) in &[(0, 8), (9, 13), (14, 18), (19, 23), (24, 36)] {
        for i in start..end {
            if !is_hex(bytes[i]) {
                return None;
            }
        }
    }

    let raw_bytes = parse_hex_bytes(trimmed);
    if raw_bytes.len() != 16 {
        return None;
    }

    let is_nil = raw_bytes.iter().all(|&b| b == 0);
    let is_max = raw_bytes.iter().all(|&b| b == 0xff);

    let version_nibble = (raw_bytes[6] >> 4) & 0x0f;
    let variant_byte = raw_bytes[8];

    let mut fields = vec![("UUID".to_string(), trimmed.to_lowercase())];

    if is_nil {
        fields.push(("Type".to_string(), "Nil UUID (all zeros)".to_string()));
        return Some(Detection {
            label: "UUID".to_string(),
            confidence: 0.95,
            fields,
        });
    }

    if is_max {
        fields.push(("Type".to_string(), "Max UUID (all ones)".to_string()));
        return Some(Detection {
            label: "UUID".to_string(),
            confidence: 0.95,
            fields,
        });
    }

    let version = match version_nibble {
        1 => "1 (Timestamp + MAC)",
        2 => "2 (DCE Security)",
        3 => "3 (MD5 Hash)",
        4 => "4 (Random)",
        5 => "5 (SHA-1 Hash)",
        6 => "6 (Sortable Timestamp + MAC)",
        7 => "7 (Unix Epoch Timestamp)",
        8 => "8 (Custom)",
        _ => "Unknown",
    };
    fields.push(("Version".to_string(), version.to_string()));

    let variant = if variant_byte & 0x80 == 0 {
        "NCS (Reserved)"
    } else if variant_byte & 0xc0 == 0x80 {
        "RFC 4122"
    } else if variant_byte & 0xe0 == 0xc0 {
        "Microsoft (COM/DCOM)"
    } else {
        "Future (Reserved)"
    };
    fields.push(("Variant".to_string(), variant.to_string()));

    if version_nibble == 1 {
        let time_low =
            u32::from_be_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
        let time_mid = u16::from_be_bytes([raw_bytes[4], raw_bytes[5]]);
        let time_hi = u16::from_be_bytes([raw_bytes[6], raw_bytes[7]]) & 0x0fff;
        let timestamp = (time_hi as u64) << 48 | (time_mid as u64) << 32 | (time_low as u64);
        let uuid_epoch_offset = 122_192_928_000_000_000u64;
        if timestamp >= uuid_epoch_offset {
            let unix_100ns = timestamp - uuid_epoch_offset;
            let unix_secs = unix_100ns / 10_000_000;
            fields.push(("Unix Timestamp".to_string(), unix_secs.to_string()));
        }

        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            raw_bytes[10], raw_bytes[11], raw_bytes[12], raw_bytes[13], raw_bytes[14],
            raw_bytes[15]
        );
        fields.push(("MAC Address".to_string(), mac));
    }

    if version_nibble == 7 {
        let ts_ms = (raw_bytes[0] as u64) << 40
            | (raw_bytes[1] as u64) << 32
            | (raw_bytes[2] as u64) << 24
            | (raw_bytes[3] as u64) << 16
            | (raw_bytes[4] as u64) << 8
            | (raw_bytes[5] as u64);
        fields.push(("Unix Timestamp (ms)".to_string(), ts_ms.to_string()));
        fields.push((
            "Unix Timestamp (s)".to_string(),
            (ts_ms / 1000).to_string(),
        ));
    }

    Some(Detection {
        label: "UUID".to_string(),
        confidence: 0.95,
        fields,
    })
}
