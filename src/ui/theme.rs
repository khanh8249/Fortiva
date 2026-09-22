// src/ui/theme.rs
// Màu sắc + style + helper clear screen.

use std::io::Write;

// ANSI escape codes
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const ITALIC: &str = "\x1b[3m";

// 256-color palette
pub const PRIMARY: &str = "\x1b[38;5;39m";
pub const SUCCESS: &str = "\x1b[38;5;46m";
pub const WARNING: &str = "\x1b[38;5;220m";
pub const ERROR: &str = "\x1b[38;5;196m";
pub const MUTED: &str = "\x1b[38;5;240m";
pub const ACCENT: &str = "\x1b[38;5;213m";
pub const CYAN: &str = "\x1b[38;5;51m";

// Background
pub const BG_DARK: &str = "\x1b[48;5;234m";
pub const BG_RESET: &str = "\x1b[49m";

// ============================================================
// CLEAR SCREEN
// ============================================================

/// Clear toàn bộ màn hình + đưa cursor về góc trên trái.
pub fn clear_screen() {
    print!("\x1b[2J\x1b[1;1H");
    std::io::stdout().flush().ok();
}

/// Clear từ cursor đến cuối màn hình.
pub fn clear_below() {
    print!("\x1b[0J");
    std::io::stdout().flush().ok();
}

/// Đưa cursor về vị trí (x, y) — 1-indexed.
pub fn move_cursor(x: u32, y: u32) {
    print!("\x1b[{};{}H", y, x);
}

// ============================================================
// FORMAT HELPERS
// ============================================================

pub fn primary(s: &str) -> String {
    format!("{}{}{}", PRIMARY, s, RESET)
}

pub fn success(s: &str) -> String {
    format!("{}{}{}", SUCCESS, s, RESET)
}

pub fn warning(s: &str) -> String {
    format!("{}{}{}", WARNING, s, RESET)
}

pub fn error(s: &str) -> String {
    format!("{}{}{}", ERROR, s, RESET)
}

pub fn muted(s: &str) -> String {
    format!("{}{}{}", MUTED, s, RESET)
}

pub fn accent(s: &str) -> String {
    format!("{}{}{}", ACCENT, s, RESET)
}

pub fn cyan(s: &str) -> String {
    format!("{}{}{}", CYAN, s, RESET)
}

pub fn bold(s: &str) -> String {
    format!("{}{}{}", BOLD, s, RESET)
}

pub fn bold_primary(s: &str) -> String {
    format!("{}{}{}{}", BOLD, PRIMARY, s, RESET)
}

pub fn bold_success(s: &str) -> String {
    format!("{}{}{}{}", BOLD, SUCCESS, s, RESET)
}

pub fn bold_error(s: &str) -> String {
    format!("{}{}{}{}", BOLD, ERROR, s, RESET)
}

pub fn bold_warning(s: &str) -> String {
    format!("{}{}{}{}", BOLD, WARNING, s, RESET)
}

// ============================================================
// DECORATION
// ============================================================

pub fn hr() {
    println!("{}", muted(&"─".repeat(64)));
}

pub fn hr_thin() {
    println!("{}", muted(&"┄".repeat(64)));
}

pub fn box_section(title: &str, lines: &[String]) {
    let width: usize = 62;

    let remaining = width.saturating_sub(title.len() + 5);

    println!(
        "{}╭─ {} {}╮{}",
        MUTED,
        bold_primary(title),
        muted(&"─".repeat(remaining)),
        RESET
    );

    for line in lines {
        println!("{}│{}  {}", MUTED, RESET, line);
    }

    println!(
        "{}╰{}╯{}",
        MUTED,
        muted(&"─".repeat(width + 1)),
        RESET
    );
}

pub fn success_box(title: &str, lines: &[String]) {
    let width: usize = 55;

    println!();

    println!(
        "  {}╭─ {} ─╮{}",
        SUCCESS,
        bold_success(title),
        RESET
    );

    for line in lines {
        println!("  {}│{}  {}", SUCCESS, RESET, line);
    }

    println!(
        "  {}╰{}╯{}",
        SUCCESS,
        muted(&"─".repeat(width)),
        RESET
    );
}

pub fn error_box(title: &str, lines: &[String]) {
    let width: usize = 55;

    println!();

    println!(
        "  {}╭─ {} ─╮{}",
        ERROR,
        bold_error(title),
        RESET
    );

    for line in lines {
        println!("  {}│{}  {}", ERROR, RESET, line);
    }

    println!(
        "  {}╰{}╯{}",
        ERROR,
        muted(&"─".repeat(width)),
        RESET
    );
}
