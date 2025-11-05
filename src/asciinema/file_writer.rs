use async_trait::async_trait;
use tokio::io::{self, AsyncWrite, AsyncWriteExt};

use crate::asciinema::asciicast;
use crate::asciinema::encoder::Encoder;
use crate::asciinema::session::{self, Metadata};

pub struct FileWriter {
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    encoder: Box<dyn Encoder + Send>,
    metadata: Metadata,
}

pub struct LiveFileWriter {
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    encoder: Box<dyn Encoder + Send>,
}

impl FileWriter {
    pub fn new(
        writer: Box<dyn AsyncWrite + Send + Unpin>,
        encoder: Box<dyn Encoder + Send>,
        metadata: Metadata,
    ) -> Self {
        FileWriter {
            writer,
            encoder,
            metadata,
        }
    }

    pub async fn start(mut self) -> io::Result<LiveFileWriter> {
        let timestamp = self.metadata.time.timestamp() as u64;

        let header = asciicast::Header {
            term_cols: self.metadata.term.size.0,
            term_rows: self.metadata.term.size.1,
            term_type: self.metadata.term.type_.clone(),
            term_version: self.metadata.term.version.clone(),
            timestamp: Some(timestamp),
            idle_time_limit: self.metadata.idle_time_limit,
            command: self.metadata.command.as_ref().cloned(),
            title: self.metadata.title.as_ref().cloned(),
            env: Some(self.metadata.env.clone()),
        };

        self.writer.write_all(&self.encoder.header(&header)).await?;

        Ok(LiveFileWriter {
            writer: self.writer,
            encoder: self.encoder,
        })
    }
}

#[async_trait]
impl session::Output for LiveFileWriter {
    async fn event(&mut self, event: session::Event) -> io::Result<()> {
        match self
            .writer
            .write_all(&self.encoder.event(event.into()))
            .await
        {
            Ok(_) => Ok(()),

            Err(e) => Err(e),
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.writer.write_all(&self.encoder.flush()).await
    }
}

impl From<session::Event> for asciicast::Event {
    fn from(event: session::Event) -> Self {
        match event {
            session::Event::Output(time, text) => asciicast::Event::output(time, text),
            session::Event::Input(time, text) => asciicast::Event::input(time, text),
            session::Event::Resize(time, tty_size) => {
                asciicast::Event::resize(time, tty_size.into())
            }
            session::Event::Marker(time, label) => asciicast::Event::marker(time, label),
            session::Event::Exit(time, status) => asciicast::Event::exit(time, status),
        }
    }
}
