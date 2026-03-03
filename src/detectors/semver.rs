use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    // Optional "v" or "V" prefix
    let (version_str, has_v_prefix) = if let Some(rest) = input
        .strip_prefix('v')
        .or_else(|| input.strip_prefix('V'))
    {
        (rest, true)
    } else {
        (input, false)
    };

    // Split off build metadata first (+...)
    let (version_pre, build_metadata) = if let Some(pos) = version_str.find('+') {
        (&version_str[..pos], Some(&version_str[pos + 1..]))
    } else {
        (version_str, None)
    };

    // Split off pre-release (-...)
    let (version_core, pre_release) = if let Some(pos) = version_pre.find('-') {
        (&version_pre[..pos], Some(&version_pre[pos + 1..]))
    } else {
        (version_pre, None)
    };

    // Parse MAJOR.MINOR.PATCH
    let parts: Vec<&str> = version_core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let major: u64 = parts[0].parse().ok()?;
    let minor: u64 = parts[1].parse().ok()?;
    let patch: u64 = parts[2].parse().ok()?;

    // Reject leading zeros (semver spec) unless the value is 0
    for part in &parts {
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
    }

    // Validate pre-release identifiers
    if let Some(pre) = pre_release {
        if pre.is_empty() {
            return None;
        }
        for ident in pre.split('.') {
            if ident.is_empty() {
                return None;
            }
            if !ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return None;
            }
        }
    }

    // Validate build metadata identifiers
    if let Some(build) = build_metadata {
        if build.is_empty() {
            return None;
        }
        for ident in build.split('.') {
            if ident.is_empty() {
                return None;
            }
            if !ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return None;
            }
        }
    }

    let mut fields = Vec::new();
    fields.push(("Major".into(), major.to_string()));
    fields.push(("Minor".into(), minor.to_string()));
    fields.push(("Patch".into(), patch.to_string()));

    if let Some(pre) = pre_release {
        fields.push(("Pre-release".into(), pre.to_string()));
    }

    if let Some(build) = build_metadata {
        fields.push(("Build Metadata".into(), build.to_string()));
    }

    let is_prerelease = pre_release.is_some();
    fields.push((
        "Is Pre-release".into(),
        if is_prerelease { "Yes" } else { "No" }.to_string(),
    ));

    let stability = if major == 0 {
        "Initial development — public API not stable"
    } else if is_prerelease {
        "Pre-release — may be unstable"
    } else {
        "Stable release"
    };
    fields.push(("Stability".into(), stability.to_string()));

    let confidence = if has_v_prefix { 0.9 } else { 0.8 };

    Some(Detection {
        label: "Semantic Version".into(),
        confidence,
        fields,
    })
}
