// src/ui/menu.rs
use super::theme::*;

pub fn print_logo() {
    println!();
    println!("{}{}  ╭─────────────────────────────────────────────────╮{}", PRIMARY, BOLD, RESET);
    println!("{}{}  │{}                                                 {}{}│{}", PRIMARY, BOLD, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}███████╗ ██████╗ ██████╗ ████████╗██╗██╗   ██╗{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██║   ██║{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}█████╗  ██║   ██║██████╔╝   ██║   ██║██║   ██║{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}██╔══╝  ██║   ██║██╔══██╗   ██║   ██║╚██╗ ██╔╝{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}██║     ╚██████╔╝██║  ██║   ██║   ██║ ╚████╔╝ {}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝  {}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}                                                 {}{}│{}", PRIMARY, BOLD, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}      {}iOS Sideload Tool written in Rust{}          {}{}│{}",
        PRIMARY, BOLD, RESET, MUTED, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}      {}v0.1.0 — Termux Edition{}                   {}{}│{}",
        PRIMARY, BOLD, RESET, MUTED, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  ╰─────────────────────────────────────────────────╯{}", PRIMARY, BOLD, RESET);
    println!();
}

pub fn print_menu() {
    println!("{}┌─────────────────────────────────────────────┐{}", MUTED, RESET);
    println!("{}│{}  [{}1{}]  🔐  Login Apple ID                     {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}2{}]  🌐  Test anisette server               {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}3{}]  📜  Test tạo CSR                       {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}4{}]  📦  Sign IPA (chỉ ký)                  {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}5{}]  🚀  Sign + Auto Install                {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}6{}]  🔗  Setup SideStore pairing               {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}7{}]  📱  Quản lý thiết b devị                   {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}8{}]  🔑  Thu hồi certificate                {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}9{}]  🚪  Thoát                              {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}└─────────────────────────────────────────────┘{}", MUTED, RESET);
    println!();
}


pub fn print_status(iphone_status: &str) {
    println!("  {} 📱 iPhone: {}", primary("Status"), iphone_status);
    println!();
}
