// src/ui/log.rs

use super::theme::{
    accent, bold, bold_primary, error as theme_error, hr, hr_thin,
    muted, primary, success as theme_success, warning as theme_warning,
};

pub fn info(msg: &str) {
    println!("  {} {}", primary("ℹ"), msg);
}

pub fn success(msg: &str) {
    println!("  {} {}", theme_success("✔"), msg);
}

pub fn warn(msg: &str) {
    println!("  {} {}", theme_warning("⚠"), msg);
}

pub fn error(msg: &str) {
    eprintln!("  {} {}", theme_error("✘"), msg);
}

pub fn debug(msg: &str) {
    println!("  {} {}", muted("·"), muted(msg));
}

pub fn step(n: u32, total: u32, msg: &str) {
    println!();
    println!(
        "  {} {}",
        bold_primary(&format!("┃ [{}/{}]", n, total)),
        bold(msg)
    );
    hr_thin();
}

pub fn header(msg: &str) {
    println!();
    println!("  {}", bold_primary(&format!("▶ {}", msg)));
    hr();
}

pub fn item_done(msg: &str) {
    println!("    {} {}", theme_success("✓"), msg);
}

pub fn item_fail(msg: &str) {
    println!("    {} {}", theme_error("✗"), msg);
}

pub fn item_skip(msg: &str) {
    println!("    {} {}", theme_warning("○"), msg);
}

pub fn sub_step(msg: &str) {
    println!("    {} {}", primary("→"), msg);
}

pub fn bullet(msg: &str) {
    println!("    {} {}", muted("•"), msg);
}
