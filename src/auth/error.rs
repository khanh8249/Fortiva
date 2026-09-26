// src/auth/error.rs
use std::fmt;

#[derive(Debug)]
pub struct SessionExpiredError {
    pub reason: String,
}

impl SessionExpiredError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into() }
    }
}

impl fmt::Display for SessionExpiredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Apple session da het han: {}", self.reason)
    }
}

impl std::error::Error for SessionExpiredError {}

pub fn is_session_expired_response(
    status: u16,
    result_code: Option<i64>,
    user_string: &str,
) -> bool {
    if status == 401 || status == 403 {
        return true;
    }
    if let Some(code) = result_code {
        if matches!(code, -20101 | -22406 | -22407 | 1100) {
            return true;
        }
    }
    let s = user_string.to_lowercase();
    let markers = [
        "session has expired", "session expired",
        "you must sign in", "please sign in",
        "sign in again", "authentication required",
        "gsa token", "invalid session",
        "not authenticated", "session is invalid",
    ];
    markers.iter().any(|m| s.contains(m))
}

pub fn is_session_expired_error(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<SessionExpiredError>())
}
