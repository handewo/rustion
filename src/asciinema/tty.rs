use async_trait::async_trait;
use rgb::RGB8;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TtySize(pub u16, pub u16);

#[derive(Clone)]
pub struct TtyTheme {
    pub fg: RGB8,
    pub bg: RGB8,
    pub palette: Vec<RGB8>,
}

pub struct NullTty;

pub struct FixedSizeTty<T> {
    inner: T,
    cols: Option<u16>,
    rows: Option<u16>,
}

#[async_trait(?Send)]
pub trait Tty {
    fn get_size(&self) -> (u16, u16);
}

impl Default for TtySize {
    fn default() -> Self {
        TtySize(80, 24)
    }
}

impl From<(u16, u16)> for TtySize {
    fn from(winsize: (u16, u16)) -> Self {
        TtySize(winsize.0, winsize.1)
    }
}

impl From<(usize, usize)> for TtySize {
    fn from((cols, rows): (usize, usize)) -> Self {
        TtySize(cols as u16, rows as u16)
    }
}

impl From<TtySize> for (u16, u16) {
    fn from(tty_size: TtySize) -> Self {
        (tty_size.0, tty_size.1)
    }
}

impl<T: Tty> FixedSizeTty<T> {
    pub fn new(inner: T, cols: Option<u16>, rows: Option<u16>) -> Self {
        Self { inner, cols, rows }
    }
}

#[async_trait(?Send)]
impl Tty for NullTty {
    fn get_size(&self) -> (u16, u16) {
        (80, 24)
    }
}

#[async_trait(?Send)]
impl<T: Tty> Tty for FixedSizeTty<T> {
    fn get_size(&self) -> (u16, u16) {
        let mut winsize = self.inner.get_size();

        if let Some(cols) = self.cols {
            winsize.0 = cols;
        }

        if let Some(rows) = self.rows {
            winsize.1 = rows;
        }

        winsize
    }
}
