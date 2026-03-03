use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    let (hex_str, has_prefix) = if let Some(stripped) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
        (stripped, true)
    } else {
        (input, false)
    };

    // Must be valid hex characters
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Must have even length and at least 4 hex chars
    if hex_str.len() < 4 || hex_str.len() % 2 != 0 {
        return None;
    }

    // Decode hex to bytes
    let bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect();

    if bytes.len() != hex_str.len() / 2 {
        return None;
    }

    let mut fields = Vec::new();
    fields.push(("Byte count".into(), bytes.len().to_string()));

    if let Ok(text) = std::str::from_utf8(&bytes) {
        let printable = text.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t').count();
        if printable == text.len() && !text.is_empty() {
            fields.push(("As UTF-8".into(), text.to_string()));
        }
    }

    // Show decimal value if short enough (up to 8 bytes / 16 hex chars)
    if hex_str.len() <= 16 {
        if let Ok(val) = u64::from_str_radix(hex_str, 16) {
            fields.push(("Decimal".into(), val.to_string()));
        }
    }

    let confidence = if has_prefix { 0.9 } else { 0.5 };

    Some(Detection {
        label: "Hex String".into(),
        confidence,
        fields,
    })
}
