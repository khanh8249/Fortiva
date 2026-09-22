use super::theme::{
    error as theme_error,
    success as theme_success,
    warning as theme_warning,
};

pub fn success(msg: &str) {
    println!("  {} {}", theme_success("✔"), msg);
}

pub fn error(msg: &str) {
    eprintln!("  {} {}", theme_error("✘"), msg);
}

pub fn warning(msg: &str) {
    println!("  {} {}", theme_warning("⚠"), msg);
}

pub fn info(msg: &str) {
    println!("  {} {}", "•", msg);
}

pub fn step(msg: &str) {
    println!("  {} {}", "→", msg);
}

pub fn detail(msg: &str) {
    println!("    {}", msg);
}

pub fn step_success(msg: &str) {
    println!("    {} {}", theme_success("✓"), msg);
}

pub fn step_error(msg: &str) {
    println!("    {} {}", theme_error("✗"), msg);
}
