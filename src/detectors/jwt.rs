use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();
    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Each part must be non-empty base64url
    for part in &parts {
        if part.is_empty() {
            return None;
        }
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    // Signature just needs to be valid base64url
    URL_SAFE_NO_PAD.decode(parts[2]).ok()?;

    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    // Must have "alg" in header to be a JWT
    let alg = header.get("alg")?.as_str()?;

    let mut fields = Vec::new();
    fields.push(("Algorithm".into(), alg.to_string()));

    if let Some(typ) = header.get("typ").and_then(|v| v.as_str()) {
        fields.push(("Type".into(), typ.to_string()));
    }

    // Standard claims
    if let Some(sub) = payload.get("sub").and_then(|v| v.as_str()) {
        fields.push(("Subject".into(), sub.to_string()));
    }
    if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
        fields.push(("Issuer".into(), iss.to_string()));
    }
    if let Some(aud) = payload.get("aud") {
        let aud_str = match aud {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            _ => aud.to_string(),
        };
        fields.push(("Audience".into(), aud_str));
    }

    let now = chrono::Utc::now().timestamp();

    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        let dt = chrono::DateTime::from_timestamp(iat, 0);
        let formatted = dt.map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| iat.to_string());
        fields.push(("Issued At".into(), formatted));
    }

    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        let dt = chrono::DateTime::from_timestamp(nbf, 0);
        let formatted = dt.map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| nbf.to_string());
        fields.push(("Not Before".into(), formatted));
    }

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        let dt = chrono::DateTime::from_timestamp(exp, 0);
        let formatted = dt.map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| exp.to_string());
        fields.push(("Expires".into(), formatted));

        if exp < now {
            let ago = format_duration(now - exp);
            fields.push(("Status".into(), format!("Expired ({} ago)", ago)));
        } else {
            let until = format_duration(exp - now);
            fields.push(("Status".into(), format!("Valid (expires in {})", until)));
        }
    }

    // Show all payload claims pretty-printed
    let pretty = serde_json::to_string_pretty(&payload).unwrap_or_default();
    fields.push(("Payload".into(), pretty));

    Some(Detection {
        label: "JWT Token".into(),
        confidence: 0.95,
        fields,
    })
}

fn format_duration(secs: i64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    if secs < 3600 {
        return format!("{}m {}s", secs / 60, secs % 60);
    }
    if secs < 86400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        return format!("{}h {}m", h, m);
    }
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    format!("{}d {}h", d, h)
}
