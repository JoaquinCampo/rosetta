use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let trimmed = input.trim();

    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        return None;
    }

    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    let len = trimmed.len();
    let algorithm = match len {
        32 => "MD5",
        40 => "SHA-1",
        56 => "SHA-224",
        64 => "SHA-256",
        96 => "SHA-384",
        128 => "SHA-512",
        _ => return None,
    };

    Some(Detection {
        label: "Hash".to_string(),
        confidence: 0.7,
        fields: vec![
            ("Algorithm (likely)".to_string(), algorithm.to_string()),
            ("Hex".to_string(), trimmed.to_lowercase()),
            ("Byte Length".to_string(), (len / 2).to_string()),
        ],
    })
}
