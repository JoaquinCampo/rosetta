use crate::detect::Detection;

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        "ftp" => Some(21),
        "ssh" => Some(22),
        "telnet" => Some(23),
        "smtp" => Some(25),
        "imap" => Some(143),
        "ldap" => Some(389),
        "mqtt" => Some(1883),
        _ => None,
    }
}

pub fn detect(input: &str) -> Option<Detection> {
    let trimmed = input.trim();

    let scheme_end = trimmed.find("://")?;
    let scheme = &trimmed[..scheme_end];

    if scheme.is_empty() || !scheme.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }
    if !scheme
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return None;
    }

    let after_scheme = &trimmed[scheme_end + 3..];
    if after_scheme.is_empty() {
        return None;
    }

    // Split off fragment
    let (before_fragment, fragment) = match after_scheme.find('#') {
        Some(i) => (&after_scheme[..i], Some(&after_scheme[i + 1..])),
        None => (after_scheme, None),
    };

    // Split off query
    let (before_query, query) = match before_fragment.find('?') {
        Some(i) => (&before_fragment[..i], Some(&before_fragment[i + 1..])),
        None => (before_fragment, None),
    };

    // Split authority and path
    let (authority, path) = match before_query.find('/') {
        Some(i) => (&before_query[..i], &before_query[i..]),
        None => (before_query, ""),
    };

    if authority.is_empty() {
        return None;
    }

    // Parse authority: [userinfo@]host[:port]
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };

    // Parse host and port - handle IPv6 bracket notation
    let (host, port) = if hostport.starts_with('[') {
        match hostport.find(']') {
            Some(i) => {
                let h = &hostport[..i + 1];
                let rest = &hostport[i + 1..];
                let p = if rest.starts_with(':') {
                    rest[1..].parse::<u16>().ok()
                } else {
                    None
                };
                (h, p)
            }
            None => return None,
        }
    } else {
        match hostport.rfind(':') {
            Some(i) => {
                let potential_port = &hostport[i + 1..];
                match potential_port.parse::<u16>() {
                    Ok(p) => (&hostport[..i], Some(p)),
                    Err(_) => (hostport, None),
                }
            }
            None => (hostport, None),
        }
    };

    let scheme_lower = scheme.to_lowercase();

    let mut fields = vec![
        ("Scheme".to_string(), scheme_lower.clone()),
        ("Host".to_string(), host.to_string()),
    ];

    if let Some(port) = port {
        let is_default = default_port(&scheme_lower) == Some(port);
        if is_default {
            fields.push(("Port".to_string(), format!("{} (default)", port)));
        } else {
            fields.push(("Port".to_string(), port.to_string()));
        }
    }

    if let Some(userinfo) = userinfo {
        fields.push(("User Info".to_string(), userinfo.to_string()));
    }

    if !path.is_empty() && path != "/" {
        fields.push(("Path".to_string(), path.to_string()));
    }

    if let Some(q) = query {
        fields.push(("Query String".to_string(), q.to_string()));
        for param in q.split('&') {
            if param.is_empty() {
                continue;
            }
            match param.find('=') {
                Some(eq) => {
                    let key = &param[..eq];
                    let val = &param[eq + 1..];
                    fields.push((format!("  {}", key), val.to_string()));
                }
                None => {
                    fields.push((format!("  {}", param), "(no value)".to_string()));
                }
            }
        }
    }

    if let Some(f) = fragment {
        fields.push(("Fragment".to_string(), f.to_string()));
    }

    Some(Detection {
        label: "URL".to_string(),
        confidence: 0.95,
        fields,
    })
}
