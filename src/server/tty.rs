use crossbeam_channel::{Receiver, Sender, unbounded};
use crossterm::event::NoTtyEvent;

#[derive(Clone)]
pub struct Tty {
    pub tty: NoTtyEvent,
    pub send_to_tty: Sender<Vec<u8>>,
    pub recv_from_tty: Receiver<Vec<u8>>,
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
    pub fn new() -> Self {
        let (send_to_tty, recv_from_session) = unbounded();
        let (tty, recv_from_tty) = NoTtyEvent::new(recv_from_session);

        Self {
            tty,
            send_to_tty,
            recv_from_tty,
        }
    }

    pub fn split(self) -> (NoTtyEvent, Sender<Vec<u8>>, Receiver<Vec<u8>>) {
        (self.tty, self.send_to_tty, self.recv_from_tty)
    }
}
