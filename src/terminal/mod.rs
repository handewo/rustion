use crossterm::{event::NoTtyEvent, terminal::WindowSize};

mod completion;

pub use completion::BastionCompleter;

pub fn window_change(
    tty: &mut NoTtyEvent,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
) -> Vec<u8> {
    *tty.window_size.lock() = WindowSize {
        rows: row_height as u16,
        columns: col_width as u16,
        width: pix_width as u16,
        height: pix_height as u16,
    };

    //     \x1B[W20;10R
    let mut win_raw = Vec::from(b"\x1B[W");
    let col = (col_width as u16).to_string();
    let row = (row_height as u16).to_string();
    win_raw.extend_from_slice(col.as_bytes());
    win_raw.push(b';');
    win_raw.extend_from_slice(row.as_bytes());
    win_raw.push(b'R');
    win_raw
}
