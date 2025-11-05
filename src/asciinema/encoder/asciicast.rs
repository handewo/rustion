use crate::asciinema::asciicast::{Event, Header, V3Encoder};

pub struct AsciicastV3Encoder {
    inner: V3Encoder,
    append: bool,
}

impl AsciicastV3Encoder {
    pub fn new(append: bool) -> Self {
        let inner = V3Encoder::new();

        Self { inner, append }
    }
}

impl super::Encoder for AsciicastV3Encoder {
    fn header(&mut self, header: &Header) -> Vec<u8> {
        if self.append {
            let size = (header.term_cols, header.term_rows);
            self.inner.event(&Event::resize(0, size))
        } else {
            self.inner.header(header)
        }
    }

    fn event(&mut self, event: Event) -> Vec<u8> {
        self.inner.event(&event)
    }

    fn flush(&mut self) -> Vec<u8> {
        Vec::new()
    }
}
