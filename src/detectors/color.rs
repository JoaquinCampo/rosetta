use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    let (r, g, b, a, format_name, confidence) = if let Some(parsed) = parse_hex(input) {
        parsed
    } else if let Some(parsed) = parse_rgb(input) {
        parsed
    } else if let Some(parsed) = parse_hsl(input) {
        parsed
    } else {
        return None;
    };

    let mut fields = Vec::new();
    fields.push(("Format".into(), format_name));

    // Hex representation
    if a < 1.0 {
        let alpha_byte = (a * 255.0).round() as u8;
        fields.push(("Hex".into(), format!("#{:02x}{:02x}{:02x}{:02x}", r, g, b, alpha_byte)));
    } else {
        fields.push(("Hex".into(), format!("#{:02x}{:02x}{:02x}", r, g, b)));
    }

    // RGB representation
    if a < 1.0 {
        fields.push(("RGB".into(), format!("rgba({}, {}, {}, {:.2})", r, g, b, a)));
    } else {
        fields.push(("RGB".into(), format!("rgb({}, {}, {})", r, g, b)));
    }

    // HSL representation
    let (h, s, l) = rgb_to_hsl(r, g, b);
    if a < 1.0 {
        fields.push(("HSL".into(), format!("hsla({}, {}%, {}%, {:.2})", h, s, l, a)));
    } else {
        fields.push(("HSL".into(), format!("hsl({}, {}%, {}%)", h, s, l)));
    }

    // Closest named color
    let named = closest_named_color(r, g, b);
    fields.push(("Closest Name".into(), named));

    // Contrast ratios and WCAG compliance
    let lum = relative_luminance(r, g, b);
    let white_lum = 1.0;
    let black_lum = 0.0;

    let contrast_white = contrast_ratio(lum, white_lum);
    let contrast_black = contrast_ratio(lum, black_lum);

    fields.push((
        "Contrast vs White".into(),
        format!("{:.2}:1 ({})", contrast_white, wcag_level(contrast_white)),
    ));
    fields.push((
        "Contrast vs Black".into(),
        format!("{:.2}:1 ({})", contrast_black, wcag_level(contrast_black)),
    ));

    Some(Detection {
        label: "Color Value".into(),
        confidence,
        fields,
    })
}

fn parse_hex(input: &str) -> Option<(u8, u8, u8, f64, String, f64)> {
    let (hex, has_hash) = if let Some(stripped) = input.strip_prefix('#') {
        (stripped, true)
    } else {
        (input, false)
    };

    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let (r, g, b, a) = match hex.len() {
        3 if has_hash => {
            // Only match #rgb, not bare 3-char hex (too many false positives)
            let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
            (r, g, b, 1.0)
        }
        6 => {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            (r, g, b, 1.0)
        }
        8 => {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            let a_byte = u8::from_str_radix(&hex[6..8], 16).ok()?;
            (r, g, b, a_byte as f64 / 255.0)
        }
        _ => return None,
    };

    let format_name = if has_hash {
        format!("Hex (#{} chars)", hex.len())
    } else {
        format!("Bare hex ({} chars)", hex.len())
    };

    let confidence = if has_hash { 0.95 } else { 0.6 };

    Some((r, g, b, a, format_name, confidence))
}

fn parse_rgb(input: &str) -> Option<(u8, u8, u8, f64, String, f64)> {
    let (inner, has_alpha) = if let Some(inner) = input
        .strip_prefix("rgba(")
        .and_then(|s| s.strip_suffix(')'))
    {
        (inner, true)
    } else if let Some(inner) = input
        .strip_prefix("rgb(")
        .and_then(|s| s.strip_suffix(')'))
    {
        (inner, false)
    } else {
        return None;
    };

    let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();

    if has_alpha && parts.len() != 4 {
        return None;
    }
    if !has_alpha && parts.len() != 3 {
        return None;
    }

    let r: u8 = parts[0].parse().ok()?;
    let g: u8 = parts[1].parse().ok()?;
    let b: u8 = parts[2].parse().ok()?;
    let a: f64 = if has_alpha {
        parts[3].parse().ok()?
    } else {
        1.0
    };

    if a < 0.0 || a > 1.0 {
        return None;
    }

    let format_name = if has_alpha { "RGBA" } else { "RGB" }.to_string();
    Some((r, g, b, a, format_name, 0.95))
}

fn parse_hsl(input: &str) -> Option<(u8, u8, u8, f64, String, f64)> {
    let (inner, has_alpha) = if let Some(inner) = input
        .strip_prefix("hsla(")
        .and_then(|s| s.strip_suffix(')'))
    {
        (inner, true)
    } else if let Some(inner) = input
        .strip_prefix("hsl(")
        .and_then(|s| s.strip_suffix(')'))
    {
        (inner, false)
    } else {
        return None;
    };

    let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();

    if has_alpha && parts.len() != 4 {
        return None;
    }
    if !has_alpha && parts.len() != 3 {
        return None;
    }

    let h: f64 = parts[0].parse().ok()?;
    let s: f64 = parts[1].strip_suffix('%')?.parse().ok()?;
    let l: f64 = parts[2].strip_suffix('%')?.parse().ok()?;
    let a: f64 = if has_alpha {
        parts[3].parse().ok()?
    } else {
        1.0
    };

    if h < 0.0 || h > 360.0 || s < 0.0 || s > 100.0 || l < 0.0 || l > 100.0 || a < 0.0 || a > 1.0
    {
        return None;
    }

    let (r, g, b) = hsl_to_rgb(h, s, l);
    let format_name = if has_alpha { "HSLA" } else { "HSL" }.to_string();
    Some((r, g, b, a, format_name, 0.95))
}

fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let s = s / 100.0;
    let l = l / 100.0;

    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;

    let (r1, g1, b1) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r1 + m) * 255.0).round() as u8,
        ((g1 + m) * 255.0).round() as u8,
        ((b1 + m) * 255.0).round() as u8,
    )
}

fn rgb_to_hsl(r: u8, g: u8, b: u8) -> (u16, u16, u16) {
    let r = r as f64 / 255.0;
    let g = g as f64 / 255.0;
    let b = b as f64 / 255.0;

    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let l = (max + min) / 2.0;

    if (max - min).abs() < f64::EPSILON {
        return (0, 0, (l * 100.0).round() as u16);
    }

    let d = max - min;
    let s = if l > 0.5 {
        d / (2.0 - max - min)
    } else {
        d / (max + min)
    };

    let h = if (max - r).abs() < f64::EPSILON {
        let mut h = (g - b) / d;
        if g < b {
            h += 6.0;
        }
        h
    } else if (max - g).abs() < f64::EPSILON {
        (b - r) / d + 2.0
    } else {
        (r - g) / d + 4.0
    };

    let h = (h * 60.0).round() as u16;
    let s = (s * 100.0).round() as u16;
    let l = (l * 100.0).round() as u16;

    (h, s, l)
}

fn relative_luminance(r: u8, g: u8, b: u8) -> f64 {
    let convert = |c: u8| -> f64 {
        let c = c as f64 / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };

    0.2126 * convert(r) + 0.7152 * convert(g) + 0.0722 * convert(b)
}

fn contrast_ratio(l1: f64, l2: f64) -> f64 {
    let lighter = l1.max(l2);
    let darker = l1.min(l2);
    (lighter + 0.05) / (darker + 0.05)
}

fn wcag_level(ratio: f64) -> &'static str {
    if ratio >= 7.0 {
        "AAA"
    } else if ratio >= 4.5 {
        "AA"
    } else if ratio >= 3.0 {
        "AA-large"
    } else {
        "Fail"
    }
}

fn color_distance(r1: u8, g1: u8, b1: u8, r2: u8, g2: u8, b2: u8) -> f64 {
    let dr = r1 as f64 - r2 as f64;
    let dg = g1 as f64 - g2 as f64;
    let db = b1 as f64 - b2 as f64;
    (dr * dr + dg * dg + db * db).sqrt()
}

fn closest_named_color(r: u8, g: u8, b: u8) -> String {
    let colors: &[(&str, u8, u8, u8)] = &[
        // 16 basic CSS colors
        ("Black", 0, 0, 0),
        ("White", 255, 255, 255),
        ("Red", 255, 0, 0),
        ("Lime", 0, 255, 0),
        ("Blue", 0, 0, 255),
        ("Yellow", 255, 255, 0),
        ("Cyan", 0, 255, 255),
        ("Magenta", 255, 0, 255),
        ("Silver", 192, 192, 192),
        ("Gray", 128, 128, 128),
        ("Maroon", 128, 0, 0),
        ("Olive", 128, 128, 0),
        ("Green", 0, 128, 0),
        ("Purple", 128, 0, 128),
        ("Teal", 0, 128, 128),
        ("Navy", 0, 0, 128),
        // Extended common colors
        ("Orange", 255, 165, 0),
        ("Pink", 255, 192, 203),
        ("HotPink", 255, 105, 180),
        ("Coral", 255, 127, 80),
        ("Tomato", 255, 99, 71),
        ("OrangeRed", 255, 69, 0),
        ("Gold", 255, 215, 0),
        ("Khaki", 240, 230, 140),
        ("Violet", 238, 130, 238),
        ("Orchid", 218, 112, 214),
        ("Indigo", 75, 0, 130),
        ("SlateBlue", 106, 90, 205),
        ("SteelBlue", 70, 130, 180),
        ("DodgerBlue", 30, 144, 255),
        ("SkyBlue", 135, 206, 235),
        ("Turquoise", 64, 224, 208),
        ("SeaGreen", 46, 139, 87),
        ("ForestGreen", 34, 139, 34),
        ("LimeGreen", 50, 205, 50),
        ("DarkGreen", 0, 100, 0),
        ("Chocolate", 210, 105, 30),
        ("SaddleBrown", 139, 69, 19),
        ("Sienna", 160, 82, 45),
        ("Peru", 205, 133, 63),
        ("Tan", 210, 180, 140),
        ("Beige", 245, 245, 220),
        ("Ivory", 255, 255, 240),
        ("Lavender", 230, 230, 250),
        ("MistyRose", 255, 228, 225),
        ("Snow", 255, 250, 250),
        ("DimGray", 105, 105, 105),
        ("DarkGray", 169, 169, 169),
        ("LightGray", 211, 211, 211),
        ("Crimson", 220, 20, 60),
        ("FireBrick", 178, 34, 34),
        ("DarkRed", 139, 0, 0),
    ];

    let mut best_name = "Unknown";
    let mut best_dist = f64::MAX;

    for &(name, cr, cg, cb) in colors {
        let dist = color_distance(r, g, b, cr, cg, cb);
        if dist < best_dist {
            best_dist = dist;
            best_name = name;
        }
    }

    best_name.to_string()
}
