pub const MAX_POPUP_WINDOW_COL: u16 = 60;
pub const MAX_POPUP_WINDOW_ROW: u16 = 40;
pub const MIN_WINDOW_COL: u16 = 35;
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

pub fn print_short_uuid(id: uuid::Uuid) -> String {
    let mut s = id.to_string();
    let mut tail = s.split_off(8);
    format!("{}...{}", s, tail.split_off(20))
}

#[test]
fn test_print_short_uuid() {
    let uuid = uuid::Uuid::parse_str("936DA01f9abd4d9d80c702af85c822a8").unwrap();
    assert_eq!(print_short_uuid(uuid), "936da01f...85c822a8".to_string());
    assert_eq!(print_short_uuid(uuid).len(), 19);
}
