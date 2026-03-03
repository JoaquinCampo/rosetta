mod detect;
mod detectors;
mod output;

use std::env;
use std::io::{self, Read};

fn main() {
    let input = get_input();
    let input = input.trim();

    if input.is_empty() {
        eprintln!("Usage: rosetta <data>");
        eprintln!("       echo <data> | rosetta");
        eprintln!();
        eprintln!("Pipe in or pass any opaque data — timestamps, JWTs, base64,");
        eprintln!("UUIDs, cron expressions, colors, IPs, and more.");
        eprintln!("Rosetta figures out what it is and explains it.");
        std::process::exit(1);
    }

    let results = detect::run_all(input);

    if results.is_empty() {
        output::print_no_match(input);
    } else {
        output::print_results(&results);
    }
}

fn get_input() -> String {
    let args: Vec<String> = env::args().skip(1).collect();

    if !args.is_empty() {
        return args.join(" ");
    }

    // Check if stdin has data (not a TTY)
    if atty_check() {
        return String::new();
    }

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap_or_default();
    buffer
}

/// Check if stdin is a terminal (no piped data)
fn atty_check() -> bool {
    unsafe { libc_isatty(0) != 0 }
}

extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}
