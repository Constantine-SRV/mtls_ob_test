//! Small shared helpers.

use chrono::Local;

/// Current local time as "YYYY-MM-DD HH:MM:SS.mmm".
/// Used both in console logs and in JSON responses so they can be correlated.
pub fn now_ts() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}
