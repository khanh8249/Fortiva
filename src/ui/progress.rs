// src/ui/progress.rs
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn new_bar(total: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {msg}\n  {prefix:>12.cyan.bold} [{bar:45.cyan/blue}] {pos:>3}/{len:>3} {percent:>3}% ({eta})")
            .unwrap()
            .progress_chars("█▓▒░ ")
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    pb.set_prefix("Đang chạy");
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

pub fn new_install_bar(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {msg}\n  {prefix:>12.cyan.bold} [{bar:45.cyan/blue}] {pos:>3}% ({eta})")
            .unwrap()
            .progress_chars("█▓▒░ ")
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    pb.set_prefix("Cài đặt");
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}
