use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    // Must be at least 4 characters
    if input.len() < 4 {
        return None;
    }

    // Skip things that look like simple words, numbers, or hex with 0x prefix
    if input.starts_with("0x") || input.starts_with("0X") {
        return None;
    }

    // Skip if it looks like a UUID
    if is_uuid_like(input) {
        return None;
    }

    // Skip if it's a plain number
    if input.parse::<f64>().is_ok() {
        return None;
    }

    // Skip if it's a simple lowercase/uppercase word with no base64-special chars
    if input.chars().all(|c| c.is_ascii_lowercase()) && input.len() < 20 {
        return None;
    }
    if input.chars().all(|c| c.is_ascii_uppercase()) && input.len() < 20 {
        return None;
    }

    // Skip if all hex chars and even length (likely a hex string)
    if input.len() % 2 == 0 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Try URL-safe first, then standard
    let (decoded, variant) = if input.contains('-') || input.contains('_') {
        let bytes = URL_SAFE.decode(input).ok()?;
        (bytes, "URL-safe (RFC 4648)")
    } else {
        let bytes = STANDARD.decode(input).ok()?;
        (bytes, "Standard (RFC 4648)")
    };

    if decoded.is_empty() {
        return None;
    }

    let byte_len = decoded.len();
    let mut fields = Vec::new();

    let confidence = if let Ok(text) = std::str::from_utf8(&decoded) {
        // Check if decoded content looks like meaningful text
        let printable_ratio = text.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t').count() as f64
            / text.len() as f64;

        if printable_ratio > 0.9 && text.len() > 1 {
            fields.push(("Decoded".into(), text.to_string()));
            // Higher confidence for clearly meaningful text
            if text.contains(' ') || text.contains('{') || text.contains('<') {
                0.75
            } else {
                0.6
            }
        } else {
            fields.push(("Decoded".into(), format!("(binary data, {} bytes)", byte_len)));
            0.5
        }
    } else {
        fields.push(("Decoded".into(), format!("(binary data, {} bytes)", byte_len)));
        0.5
    };

    fields.push(("Byte length".into(), byte_len.to_string()));
    fields.push(("Encoding".into(), variant.to_string()));

    Some(Detection {
        label: "Base64".into(),
        confidence,
        fields,
    })
}

fn is_uuid_like(s: &str) -> bool {
    if s.len() == 36 {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 5 {
            return parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
    false
}
