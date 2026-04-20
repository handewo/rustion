pub const MAX_POPUP_WINDOW_COL: u16 = 60;
pub const MAX_POPUP_WINDOW_ROW: u16 = 40;
pub const MIN_WINDOW_COL: u16 = 25;
pub const MIN_WINDOW_ROW: u16 = 15;
pub const DATETIME_LENGTH: u16 = 19;

pub fn format_timestamp(ts: i64) -> String {
    use chrono::{TimeZone, Utc};
    match Utc.timestamp_millis_opt(ts) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        chrono::LocalResult::Ambiguous(dt, _) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        chrono::LocalResult::None => ts.to_string(),
    }
}
