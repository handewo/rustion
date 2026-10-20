//! The user's side of the proxy, built from the handler's callbacks.
//!
//! The handler does not keep the `Channel` russh hands to
//! `channel_open_session`. russh queues every message for that `Channel` before
//! it calls the handler, and once a queue nobody reads is full the whole
//! connection stops. So the proxy is fed like every other app: the client's
//! bytes arrive in `Handler::data` and go to the [`Sender`] returned by
//! [`stream`], and replies go out through the session's [`Handle`].

use bytes::Bytes;
use russh::ChannelId;
use russh::server::Handle;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{self, Receiver, Sender};

type Reply = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// Where replies go: the user's channel, or a recorder in tests.
trait Outlet: Send + Unpin + 'static {
    fn data(&self, data: Bytes) -> Reply;
    fn close(&self) -> Reply;
}

struct Channel {
    handle: Handle,
    id: ChannelId,
}

impl Outlet for Channel {
    fn data(&self, data: Bytes) -> Reply {
        let (handle, id) = (self.handle.clone(), self.id);
        Box::pin(async move { handle.data(id, data).await.map_err(|_| gone()) })
    }

    fn close(&self) -> Reply {
        let (handle, id) = (self.handle.clone(), self.id);
        Box::pin(async move { handle.close(id).await.map_err(|_| gone()) })
    }
}

fn gone() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}

/// The stream the proxy serves, and the sender the handler feeds it through.
/// Dropping the sender is EOF; dropping the stream closes the channel.
///
/// `capacity` bounds the client's bytes not yet read by the proxy. Pass the
/// session's `channel_buffer_size`: it is the bound russh's own queue had.
pub(crate) fn stream(
    handle: Handle,
    id: ChannelId,
    capacity: usize,
) -> (
    Sender<Bytes>,
    impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) {
    let (input, rx) = mpsc::channel(capacity);
    (input, ClientStream::new(rx, Channel { handle, id }))
}

struct ClientStream<O: Outlet> {
    input: Receiver<Bytes>,
    /// What is left of the last message once `buf` was full.
    unread: Bytes,
    outlet: O,
    /// The reply accepted by `poll_write` and not yet handed to the session.
    sending: Option<Reply>,
}

impl<O: Outlet> ClientStream<O> {
    fn new(input: Receiver<Bytes>, outlet: O) -> Self {
        Self {
            input,
            unread: Bytes::new(),
            outlet,
            sending: None,
        }
    }
}

impl<O: Outlet> AsyncRead for ClientStream<O> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // An empty message is not EOF; only a dropped sender is.
        while self.unread.is_empty() {
            match ready!(self.input.poll_recv(cx)) {
                Some(data) => self.unread = data,
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = buf.remaining().min(self.unread.len());
        let chunk = self.unread.split_to(n);
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl<O: Outlet> AsyncWrite for ClientStream<O> {
    /// One reply in flight: a write first finishes the one before it.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.as_mut().poll_flush(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let reply = self.outlet.data(Bytes::copy_from_slice(buf));
        self.sending = Some(reply);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(reply) = self.sending.as_mut() {
            let sent = ready!(reply.as_mut().poll(cx));
            self.sending = None;
            sent?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// The proxy is done with the user: close the channel, after any reply still
/// on its way.
impl<O: Outlet> Drop for ClientStream<O> {
    fn drop(&mut self) {
        let sending = self.sending.take();
        let close = self.outlet.close();
        // No runtime means the process is shutting down; nothing can be sent.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Some(reply) = sending {
                    let _ = reply.await;
                }
                let _ = close.await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Records replies as `Some(data)` and the close as `None`, through a
    /// queue of `capacity`, so a full one holds a reply back.
    struct Recorder(Sender<Option<Bytes>>);

    impl Outlet for Recorder {
        fn data(&self, data: Bytes) -> Reply {
            let tx = self.0.clone();
            Box::pin(async move { tx.send(Some(data)).await.map_err(|_| gone()) })
        }

        fn close(&self) -> Reply {
            let tx = self.0.clone();
            Box::pin(async move { tx.send(None).await.map_err(|_| gone()) })
        }
    }

    fn pair(
        capacity: usize,
    ) -> (
        Sender<Bytes>,
        ClientStream<Recorder>,
        Receiver<Option<Bytes>>,
    ) {
        let (input, rx) = mpsc::channel(8);
        let (tx, sent) = mpsc::channel(capacity);
        (input, ClientStream::new(rx, Recorder(tx)), sent)
    }

    #[tokio::test]
    async fn reads_across_messages_until_the_sender_drops() {
        let (input, mut stream, _sent) = pair(8);
        for part in ["abc", "", "defgh"] {
            input.send(Bytes::from(part)).await.unwrap();
        }
        drop(input);

        let mut two = [0; 2];
        assert_eq!(stream.read(&mut two).await.unwrap(), 2);
        assert_eq!(&two, b"ab");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"cdefgh");
    }

    #[tokio::test]
    async fn a_flush_sends_the_reply() {
        let (_input, mut stream, mut sent) = pair(8);
        stream.write_all(b"one").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(sent.recv().await, Some(Some(Bytes::from("one"))));
    }

    #[tokio::test]
    async fn a_flush_waits_until_the_session_takes_the_reply() {
        let (_input, mut stream, mut sent) = pair(1);
        stream.write_all(b"a").await.unwrap();
        stream.flush().await.unwrap();
        stream.write_all(b"b").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.flush())
                .await
                .is_err(),
            "flushed while the session had no room"
        );

        assert_eq!(sent.recv().await, Some(Some(Bytes::from("a"))));
        stream.flush().await.unwrap();
        assert_eq!(sent.recv().await, Some(Some(Bytes::from("b"))));
    }

    #[tokio::test]
    async fn dropping_the_stream_closes_after_the_last_reply() {
        let (_input, mut stream, mut sent) = pair(8);
        stream.write_all(b"last").await.unwrap();
        drop(stream);
        assert_eq!(sent.recv().await, Some(Some(Bytes::from("last"))));
        assert_eq!(sent.recv().await, Some(None));
    }

    #[tokio::test]
    async fn a_closed_session_fails_the_flush() {
        let (_input, mut stream, sent) = pair(8);
        drop(sent);
        stream.write_all(b"lost").await.unwrap();
        let err = stream.flush().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
