// src/dev/session_helper.rs
use anyhow::anyhow;

/// Kiem tra error co phai session expired.
pub fn is_session_expired(err: &anyhow::Error) -> bool {
    let msg = format!("{:#}", err).to_lowercase();
    msg.contains("session has expired")
        || msg.contains("session expired")
        || msg.contains("session het han")
        || msg.contains("1100")
        || msg.contains("not_authorized")
        || msg.contains("401")
        || msg.contains("unauthorized")
        || msg.contains("token can refresh")
}

/// In huong dan login lai.
pub fn print_session_expired_help() {
    println!();
    println!("==================================================");
    println!("  SESSION DA HET HAN");
    println!("==================================================");
    println!();
    println!("  Apple bao session (token) da het han.");
    println!("  Day la BINH THUONG — token co TTL ngan.");
    println!();
    println!("  CACH XU LY:");
    println!("     1. Nhan Enter de ve menu chinh");
    println!("     2. Chon menu [1] Login Apple ID");
    println!("     3. Nhap lai Apple ID + password");
    println!("     4. Quay lai thao tac nay");
    println!();
    println!("  LUU Y:");
    println!("     - Khong login lien tuc — Apple se chan (429)");
    println!("     - Doi vai phut neu bi chan");
    println!();
}

/// Wrapper de xu ly session expired.
pub fn handle_session_error<T>(
    result: Result<T, anyhow::Error>,
) -> Result<T, anyhow::Error> {
    match result {
        Ok(v) => Ok(v),
        Err(e) if is_session_expired(&e) => {
            print_session_expired_help();
            Err(e)
        }
        Err(e) => Err(e),
    }
}
