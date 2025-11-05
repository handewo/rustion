mod asciicast;
mod encoder;
mod error;
mod file_writer;
mod session;
mod tty;
mod util;

use encoder::AsciicastV3Encoder;
pub use error::Error;
use file_writer::FileWriter;
pub use session::Session;
use session::{Metadata, TermInfo};
use std::collections::HashMap;
use std::path::Path;
pub use tty::TtySize;
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn new_recorder(
    term_type: Option<String>,
    file_path: &str,
    size: (u16, u16),
    title: Option<String>,
    record_input: bool,
) -> Result<Session> {
    let term = get_term_info(term_type, size).await?;
    let metadata = get_session_metadata(title, term).await?;
    let file_writer = get_file_writer(file_path, &metadata).await?;

    let mut outputs: Vec<Box<dyn session::Output>> = Vec::new();

    if let Some(writer) = file_writer {
        let output = writer.start().await?;
        outputs.push(Box::new(output));
    }
    let mut tty = Box::new(tty::FixedSizeTty::new(
        tty::NullTty,
        Some(size.0),
        Some(size.1),
    ));

    session::new(tty.as_mut(), record_input, outputs).await
}

async fn get_session_metadata(title: Option<String>, term: TermInfo) -> Result<Metadata> {
    Ok(Metadata {
        time: chrono::Utc::now(),
        term,
        idle_time_limit: None,
        command: None,
        title,
        env: HashMap::new(),
    })
}

async fn get_term_info(term_type: Option<String>, size: (u16, u16)) -> Result<TermInfo> {
    Ok(TermInfo {
        type_: term_type,
        version: None,
        size: size.into(),
    })
}

async fn get_file_writer(file_path: &str, metadata: &Metadata) -> Result<Option<FileWriter>> {
    let path = Path::new(file_path);

    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let file = tokio::fs::File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await?;

    let writer = Box::new(file);
    let encoder = Box::new(AsciicastV3Encoder::new(false));

    Ok(Some(FileWriter::new(writer, encoder, metadata.clone())))
}
