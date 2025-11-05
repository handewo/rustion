mod v3;

use super::Result;
use std::collections::HashMap;
pub use v3::V3Encoder;

pub struct Header {
    pub term_cols: u16,
    pub term_rows: u16,
    pub term_type: Option<String>,
    pub term_version: Option<String>,
    pub timestamp: Option<u64>,
    pub idle_time_limit: Option<f64>,
    pub command: Option<String>,
    pub title: Option<String>,
    pub env: Option<HashMap<String, String>>,
}

pub struct Event {
    pub time: u64,
    pub data: EventData,
}

pub enum EventData {
    Output(String),
    Input(String),
    Resize(u16, u16),
    Marker(String),
    Exit(i32),
}

impl Default for Header {
    fn default() -> Self {
        Self {
            term_cols: 80,
            term_rows: 24,
            term_type: None,
            term_version: None,
            timestamp: None,
            idle_time_limit: None,
            command: None,
            title: None,
            env: None,
        }
    }
}

impl Event {
    pub fn output(time: u64, text: String) -> Self {
        Event {
            time,
            data: EventData::Output(text),
        }
    }

    pub fn input(time: u64, text: String) -> Self {
        Event {
            time,
            data: EventData::Input(text),
        }
    }

    pub fn resize(time: u64, size: (u16, u16)) -> Self {
        Event {
            time,
            data: EventData::Resize(size.0, size.1),
        }
    }

    pub fn marker(time: u64, label: String) -> Self {
        Event {
            time,
            data: EventData::Marker(label),
        }
    }

    pub fn exit(time: u64, status: i32) -> Self {
        Event {
            time,
            data: EventData::Exit(status),
        }
    }
}
