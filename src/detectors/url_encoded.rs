use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    // Must contain at least one percent-encoded sequence
    if !input.contains('%') {
        return None;
    }

    // Verify there's at least one valid %XX sequence
    let has_valid_encoding = input
        .as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1..].iter().all(|b| (*b as char).is_ascii_hexdigit()));

    if !has_valid_encoding {
        return None;
    }

    let decoded = percent_decode(input);

    // If nothing changed, it wasn't actually encoded
    if decoded == input {
        return None;
    }

    let mut fields = Vec::new();
    fields.push(("Decoded".into(), decoded));

    Some(Detection {
        label: "URL Encoded".into(),
        confidence: 0.9,
        fields,
    })
}

fn percent_decode(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = bytes[i + 1] as char;
            let lo = bytes[i + 2] as char;
            if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() {
                let byte = u8::from_str_radix(&input[i + 1..i + 3], 16).unwrap();
                result.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(b' ');
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }

    String::from_utf8(result).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}
