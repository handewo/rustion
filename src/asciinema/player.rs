use crate::asciinema::Result;
use tokio::sync::mpsc;

use super::asciicast::{self, Event};

pub fn emit_session_events(
    recording: asciicast::Asciicast<'static>,
    speed: f64,
    idle_time_limit_override: Option<f64>,
) -> Result<mpsc::Receiver<Result<Event>>> {
    let idle_time_limit = idle_time_limit_override
        .or(recording.header.idle_time_limit)
        .unwrap_or(f64::MAX);

    let events = asciicast::limit_idle_time(recording.events, idle_time_limit);
    let events = asciicast::accelerate(events, speed);
    let (tx, rx) = mpsc::channel::<Result<Event>>(1024);

    tokio::task::spawn_blocking(move || {
        for event in events {
            if tx.blocking_send(event).is_err() {
                break;
            }
        }
    });

    Ok(rx)
}
