use std::collections::HashMap;

use async_trait::async_trait;
use futures_util::future;
use tokio::io;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::asciinema::tty::{Tty, TtySize};
use crate::asciinema::util::Utf8Decoder;
use crate::asciinema::Result;

#[derive(Clone)]
pub enum Event {
    Output(u64, String),
    Input(u64, String),
    Resize(u64, TtySize),
    Marker(u64, String),
    Exit(u64, i32),
}

#[derive(Clone)]
pub struct Metadata {
    pub time: chrono::DateTime<chrono::Utc>,
    pub term: TermInfo,
    pub idle_time_limit: Option<f64>,
    pub command: Option<String>,
    pub title: Option<String>,
    pub env: HashMap<String, String>,
}

#[derive(Clone)]
pub struct TermInfo {
    pub type_: Option<String>,
    pub version: Option<String>,
    pub size: TtySize,
}

#[derive(Clone)]
pub struct Session {
    epoch: Instant,
    events_tx: mpsc::Sender<Event>,
    input_decoder: Utf8Decoder,
    output_decoder: Utf8Decoder,
    pause_time: Option<u64>,
    prefix_mode: bool,
    record_input: bool,
    time_offset: u64,
    tty_size: TtySize,
}

#[async_trait]
pub trait Output: Send {
    async fn event(&mut self, event: Event) -> io::Result<()>;
    async fn flush(&mut self) -> io::Result<()>;
}

pub async fn new<T: Tty + ?Sized>(
    tty: &mut T,
    record_input: bool,
    outputs: Vec<Box<dyn Output>>,
) -> Result<Session> {
    let epoch = Instant::now();
    let (events_tx, events_rx) = mpsc::channel::<Event>(1024);
    let winsize = tty.get_size();
    tokio::spawn(async { forward_events(events_rx, outputs).await });

    let session = Session {
        epoch,
        events_tx,
        input_decoder: Utf8Decoder::new(),
        output_decoder: Utf8Decoder::new(),
        pause_time: None,
        prefix_mode: false,
        record_input,
        time_offset: 0,
        tty_size: winsize.into(),
    };
    Ok(session)
}

async fn forward_events(mut events_rx: mpsc::Receiver<Event>, outputs: Vec<Box<dyn Output>>) {
    let mut outputs = outputs;

    while let Some(event) = events_rx.recv().await {
        let futs: Vec<_> = outputs
            .into_iter()
            .map(|output| forward_event(output, event.clone()))
            .collect();

        outputs = future::join_all(futs).await.into_iter().flatten().collect();
    }

    for mut output in outputs {
        if let Err(e) = output.flush().await {
            log::error!("Asciinema output flush failed: {e:?}");
        }
    }
}

async fn forward_event(mut output: Box<dyn Output>, event: Event) -> Option<Box<dyn Output>> {
    match output.event(event).await {
        Ok(()) => Some(output),

        Err(e) => {
            log::error!("Asciinema output event handler failed: {e:?}");
            None
        }
    }
}

impl Session {
    pub async fn handle_output(&mut self, data: &[u8]) {
        if self.pause_time.is_none() {
            let text = self.output_decoder.feed(data);

            if !text.is_empty() {
                let event = Event::Output(self.elapsed_time(), text);
                self.send_session_event(event).await;
            }
        }
    }

    pub async fn handle_input(&mut self, data: &[u8]) -> bool {
        let prefix_key: Option<&Vec<u8>> = None.as_ref();
        let pause_key: Option<&Vec<u8>> = None.as_ref();
        let add_marker_key: Option<&Vec<u8>> = None.as_ref();

        if !self.prefix_mode && prefix_key.is_some_and(|key| data == key) {
            self.prefix_mode = true;
            return false;
        }

        if self.prefix_mode || prefix_key.is_none() {
            self.prefix_mode = false;

            if pause_key.is_some_and(|key| data == key) {
                if let Some(pt) = self.pause_time {
                    self.pause_time = None;
                    self.time_offset += self.elapsed_time() - pt;
                } else {
                    self.pause_time = Some(self.elapsed_time());
                }

                return false;
            } else if add_marker_key.is_some_and(|key| data == key) {
                let event = Event::Marker(self.elapsed_time(), "".to_owned());
                self.send_session_event(event).await;
                return false;
            }
        }

        if self.record_input && self.pause_time.is_none() {
            let text = self.input_decoder.feed(data);

            if !text.is_empty() {
                let event = Event::Input(self.elapsed_time(), text);
                self.send_session_event(event).await;
            }
        }

        true
    }

    pub async fn handle_resize(&mut self, tty_size: TtySize) {
        if tty_size != self.tty_size {
            let event = Event::Resize(self.elapsed_time(), tty_size);
            self.send_session_event(event).await;
            self.tty_size = tty_size;
        }
    }

    pub async fn handle_exit(&mut self, status: i32) {
        let event = Event::Exit(self.elapsed_time(), status);
        self.send_session_event(event).await;
    }

    pub async fn handle_marker(&mut self, label: String) {
        let event = Event::Marker(self.elapsed_time(), label);
        self.send_session_event(event).await;
    }

    fn elapsed_time(&self) -> u64 {
        if let Some(pause_time) = self.pause_time {
            pause_time
        } else {
            self.epoch.elapsed().as_micros() as u64 - self.time_offset
        }
    }

    async fn send_session_event(&mut self, event: Event) {
        self.events_tx
            .send(event)
            .await
            .expect("session event send should succeed");
    }
}
