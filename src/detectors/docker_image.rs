use crate::detect::Detection;

fn is_valid_component(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn looks_like_registry(s: &str) -> bool {
    s.contains('.') || s.contains(':')
}

pub fn detect(input: &str) -> Option<Detection> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.contains(' ') {
        return None;
    }

    if trimmed.contains("://") {
        return None;
    }

    // Reject CIDR notation (e.g., 192.168.1.0/24)
    if let Some(slash_idx) = trimmed.find('/') {
        let after_slash = &trimmed[slash_idx + 1..];
        if let Some(first_part) = after_slash.split('/').next() {
            if first_part.parse::<u32>().is_ok() && trimmed[..slash_idx].contains('.') {
                // Looks like IP/prefix, not registry/repo
                if trimmed[..slash_idx]
                    .split('.')
                    .all(|p| p.parse::<u8>().is_ok())
                {
                    return None;
                }
            }
        }
    }

    // Split off @digest first
    let (before_digest, digest) = match trimmed.find('@') {
        Some(i) => {
            let d = &trimmed[i + 1..];
            if !d.contains(':') {
                return None;
            }
            (&trimmed[..i], Some(d))
        }
        None => (trimmed, None),
    };

    // Split off :tag (last colon not part of a registry port)
    let (before_tag, tag) = if let Some(last_colon) = before_digest.rfind(':') {
        let after_colon = &before_digest[last_colon + 1..];
        if after_colon.contains('/') {
            (before_digest, None)
        } else if !after_colon.is_empty()
            && after_colon
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        {
            (&before_digest[..last_colon], Some(after_colon))
        } else {
            (before_digest, None)
        }
    } else {
        (before_digest, None)
    };

    let segments: Vec<&str> = before_tag.split('/').collect();
    if segments.is_empty() || segments.len() > 10 {
        return None;
    }

    for seg in &segments {
        if !is_valid_component(seg) {
            return None;
        }
    }

    let (registry, repository) = if segments.len() >= 2 && looks_like_registry(segments[0]) {
        (Some(segments[0]), segments[1..].join("/"))
    } else {
        (None, segments.join("/"))
    };

    if repository.is_empty() {
        return None;
    }

    // Single bare word without tag/digest is too ambiguous unless known image
    if segments.len() == 1 && tag.is_none() && digest.is_none() {
        let lower = repository.to_lowercase();
        let known = [
            "nginx",
            "redis",
            "postgres",
            "mysql",
            "mongo",
            "node",
            "python",
            "ruby",
            "golang",
            "alpine",
            "ubuntu",
            "debian",
            "centos",
            "fedora",
            "busybox",
            "httpd",
            "memcached",
            "rabbitmq",
            "elasticsearch",
            "kibana",
            "grafana",
            "prometheus",
            "traefik",
            "caddy",
            "vault",
            "consul",
            "etcd",
            "mariadb",
        ];
        if !known.contains(&lower.as_str()) {
            return None;
        }
    }

    let mut fields = Vec::new();

    if let Some(r) = registry {
        fields.push(("Registry".to_string(), r.to_string()));
    }
    fields.push(("Repository".to_string(), repository));
    if let Some(t) = tag {
        fields.push(("Tag".to_string(), t.to_string()));
    }
    if let Some(d) = digest {
        fields.push(("Digest".to_string(), d.to_string()));
    }
    if tag.is_none() && digest.is_none() {
        fields.push(("Tag".to_string(), "latest (implied)".to_string()));
    }

    Some(Detection {
        label: "Docker Image".to_string(),
        confidence: 0.7,
        fields,
    })
}
