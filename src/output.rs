use crate::detect::Detection;

// ANSI color codes
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const WHITE: &str = "\x1b[37m";

pub fn print_results(results: &[Detection]) {
    for (i, result) in results.iter().enumerate() {
        if i > 0 {
            println!();
            println!("{DIM}───────────────────────────────────{RESET}");
            println!();
        }

        // Header with label and confidence
        let confidence_bar = confidence_indicator(result.confidence);
        println!("{BOLD}{CYAN}{}{RESET}  {}", result.label, confidence_bar);
        println!();

        // Fields
        let max_key_len = result
            .fields
            .iter()
            .map(|(k, _)| k.len())
            .max()
            .unwrap_or(0);

        for (key, value) in &result.fields {
            if value.contains('\n') {
                // Multi-line values get their own block
                println!("  {GREEN}{:>width$}{RESET}:", key, width = max_key_len);
                for line in value.lines() {
                    println!("    {WHITE}{}{RESET}", line);
                }
            } else {
                println!(
                    "  {GREEN}{:>width$}{RESET}  {WHITE}{}{RESET}",
                    key,
                    value,
                    width = max_key_len
                );
            }
        }
    }
    println!();
}

pub fn print_no_match(input: &str) {
    let preview = if input.len() > 60 {
        format!("{}...", &input[..60])
    } else {
        input.to_string()
    };
    eprintln!(
        "{YELLOW}No known format detected{RESET} for: {DIM}{}{RESET}",
        preview
    );
    eprintln!();
    eprintln!("{DIM}Rosetta recognizes: JWT, Base64, Unix timestamps, UUIDs,{RESET}");
    eprintln!("{DIM}cron expressions, IPs/CIDR, colors, semver, HTTP status{RESET}");
    eprintln!("{DIM}codes, file permissions, URLs, hex, hashes, dates, and more.{RESET}");
}

fn confidence_indicator(confidence: f64) -> String {
    if confidence >= 0.9 {
        format!("{GREEN}●●●{RESET}")
    } else if confidence >= 0.7 {
        format!("{GREEN}●●{RESET}{DIM}○{RESET}")
    } else if confidence >= 0.5 {
        format!("{YELLOW}●{RESET}{DIM}○○{RESET}")
    } else {
        format!("{DIM}○○○{RESET}")
    }
}
