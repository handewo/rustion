mod asciicast;

use crate::asciinema::asciicast::{Event, Header};
pub use asciicast::AsciicastV3Encoder;

pub trait Encoder {
    fn header(&mut self, header: &Header) -> Vec<u8>;
    fn event(&mut self, event: Event) -> Vec<u8>;
    fn flush(&mut self) -> Vec<u8>;
}
