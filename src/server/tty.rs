use bytes::Bytes;
use crossterm::event::NoTtyEvent;
use tokio::sync::mpsc::{Receiver, Sender, channel};

#[derive(Clone)]
pub struct Tty {
    pub tty: NoTtyEvent,
    pub send_to_tty: Sender<Bytes>,
}

impl Tty {
    pub fn window_size(&mut self, window_size: (u32, u32, u32, u32)) {
        let _ = crate::terminal::window_change(
            &mut self.tty,
            window_size.0,
            window_size.1,
            window_size.2,
            window_size.3,
        );
    }
    pub fn new() -> (Self, Receiver<Bytes>) {
        let (send_to_tty, recv_from_session) = channel(16);
        let (tty, recv_from_tty) = NoTtyEvent::new(recv_from_session);

        (Self { tty, send_to_tty }, recv_from_tty)
    }

    pub fn split(self) -> (NoTtyEvent, Sender<Bytes>) {
        (self.tty, self.send_to_tty)
    }
}
