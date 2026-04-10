mod util;
mod v3;

use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use super::{Error, Result};
use std::collections::HashMap;
use std::time::Duration;
pub use v3::V3Encoder;

pub struct Asciicast<'a> {
    pub header: Header,
    pub events: Box<dyn Iterator<Item = Result<Event>> + Send + 'a>,
}

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
    pub time: Duration,
    pub data: EventData,
}

pub enum EventData {
    Output(String),
    Input(String),
    Resize(u16, u16),
    Marker(String),
    Exit(i32),
    Other(char, String),
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
    pub fn output(time: Duration, text: String) -> Self {
        Event {
            time,
            data: EventData::Output(text),
        }
    }

    pub fn input(time: Duration, text: String) -> Self {
        Event {
            time,
            data: EventData::Input(text),
        }
    }

    pub fn resize(time: Duration, size: (u16, u16)) -> Self {
        Event {
            time,
            data: EventData::Resize(size.0, size.1),
        }
    }

    pub fn marker(time: Duration, label: String) -> Self {
        Event {
            time,
            data: EventData::Marker(label),
        }
    }

    pub fn exit(time: Duration, status: i32) -> Self {
        Event {
            time,
            data: EventData::Exit(status),
        }
    }
}

pub fn open_from_path<S: AsRef<Path>>(path: S) -> Result<Asciicast<'static>> {
    fs::File::open(&path)
        .map(io::BufReader::new)
        .map_err(Error::Io)
        .and_then(open)
}

pub fn open<'a, R: BufRead + Send + 'a>(reader: R) -> Result<Asciicast<'a>> {
    let mut lines = reader.lines();
    let first_line = lines.next().ok_or(super::error::Error::EmptyFile)??;

    if let Ok(parser) = v3::open(&first_line) {
        Ok(parser.parse(lines))
    } else {
        Err(Error::InvalidVersion)
    }
}

pub fn limit_idle_time(
    events: impl Iterator<Item = Result<Event>> + Send,
    limit: f64,
) -> impl Iterator<Item = Result<Event>> + Send {
    let limit = Duration::from_micros((limit * 1_000_000.0) as u64);
    let mut prev_time = Duration::from_micros(0);
    let mut offset = Duration::from_micros(0);

    events.map(move |event| {
        event.map(|event| {
            let delay = event.time - prev_time;

            if delay > limit {
                offset += delay - limit;
            }

            prev_time = event.time;
            let time = event.time - offset;

            Event { time, ..event }
        })
    })
}

pub fn accelerate(
    events: impl Iterator<Item = Result<Event>> + Send,
    speed: f64,
) -> impl Iterator<Item = Result<Event>> + Send {
    events.map(move |event| {
        event.map(|event| {
            let time = event.time.div_f64(speed);

            Event { time, ..event }
        })
    })
}
