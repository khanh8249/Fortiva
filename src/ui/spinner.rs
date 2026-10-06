// src/ui/spinner.rs
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn new(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏✓")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

pub fn finish_success(pb: &ProgressBar, msg: &str) {
    pb.finish_with_message(format!("✅ {}", msg));
}

pub fn finish_error(pb: &ProgressBar, msg: &str) {
    pb.finish_with_message(format!("❌ {}", msg));
}
