use super::{ExecParams, PtyParams};
use crate::database::common as db_common;
use crate::error::Error;
use crate::server::error::ServerError;
use crate::server::event_log::EventKind;
use crate::server::extend_policy;
use bytes::Bytes;

use crate::database::Uuid;
use log::{debug, warn};
use tokio::sync::mpsc;

use russh::ChannelId;
use russh::server as ru_server;

mod common;
mod database;
pub mod error;
mod manage;
mod shell;
mod validate;

pub async fn check_permission<B>(
    user_id: Uuid,
    backend: &B,
    object: Uuid,
    action: Uuid,
    ip: Option<std::net::IpAddr>,
) -> Result<bool, Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    backend
        .enforce(
            user_id,
            object,
            action,
            extend_policy::ExtendPolicyReq::new(ip),
        )
        .await
}

pub(crate) async fn exec_request_with_pty<B>(
    params: PtyParams<B>,
    _channel: ChannelId,
    _data: &[u8],
    _session: &mut ru_server::Session,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let (_handler_id, user_id, client_ip, backend, _tty, _recv, _log, _) = params.split();
    let uuids = db_common::InternalUuids::get();
    if !check_permission(
        user_id,
        backend.as_ref(),
        uuids.obj_admin,
        uuids.act_exec,
        client_ip,
    )
    .await?
    {
        return Err(ServerError::PermissionDeny.into());
    }
    Ok(())
}

pub(crate) async fn exec_request_without_pty<B>(
    params: ExecParams<B>,
    channel: ChannelId,
    data: &[u8],
    session: &mut ru_server::Session,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let (handler_id, user_id, client_ip, backend, mut recv, _log) = params.split();
    let uuids = db_common::InternalUuids::get();
    if !check_permission(
        user_id,
        backend.as_ref(),
        uuids.obj_admin,
        uuids.act_exec,
        client_ip,
    )
    .await?
    {
        return Err(ServerError::PermissionDeny.into());
    }
    let handle_session = session.handle();

    match String::from_utf8_lossy(data).to_string().as_str() {
        "demo" => {
            let info = r#"This demo is used to test interactive with admin
Input "exit" or "quit" will exit demo gracefully.
"#;
            let _ = handle_session.data(channel, info).await;
            tokio::spawn(async move {
                while let Some(data) = recv.recv().await {
                    let line = String::from_utf8_lossy(&data).to_string();
                    match line.trim() {
                        "exit" | "quit" => break,
                        _ => {}
                    }
                    let output = format!("Your input: {}", line);
                    if handle_session.data(channel, output).await.is_err() {
                        debug!("[{}] Fail to send data to session", handler_id);
                        break;
                    }
                }
                let _ = handle_session.data(channel, "Bye!\r\n").await;
                let _ = handle_session.exit_status_request(channel, 0).await;
                let _ = handle_session.close(channel).await;
            });
        }
        _ => {
            let _ = handle_session.data(channel, "Command not found.\r\n").await;
            let _ = handle_session.exit_status_request(channel, 1).await;
            let _ = handle_session.close(channel).await;
        }
    }

    Ok(())
}

pub(crate) async fn shell_request<B>(
    app_params: PtyParams<B>,
    channel: ChannelId,
    session: &mut ru_server::Session,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let (handler_id, user_id, client_ip, backend, tty, mut recv_from_tty, log, _) =
        app_params.split();
    let uuids = db_common::InternalUuids::get();
    if !check_permission(
        user_id,
        backend.as_ref(),
        uuids.obj_admin,
        uuids.act_shell,
        client_ip,
    )
    .await?
    {
        return Err(ServerError::PermissionDeny.into());
    }
    let handle_session = session.handle();
    let (send_to_session, mut recv_from_shell) = mpsc::channel::<Bytes>(16);
    let (send_status, mut recv_status) = mpsc::channel(1);
    let send_to_session_from_tty = send_to_session.clone();
    let (tty, _) = tty.split();

    tokio::spawn(async move {
        while let Some(data) = recv_from_tty.recv().await {
            if send_to_session_from_tty.send(data).await.is_err() {
                debug!("[{}] Fail to send data to session from tty", handler_id);
                break;
            }
        }
    });

    tokio::spawn(async move {
        loop {
            tokio::select! {
                data = recv_from_shell.recv() => {
                    match data {
                        Some(d) => {
                            if handle_session.data(channel, d).await.is_err() {
                                warn!("[{}] Fail to send data to session from prompt",handler_id);
                                break;
                            }
                        }
                        // Every sender is gone, so nothing more can arrive. Without a
                        // `break` the `select!` re-polls a closed channel, which returns
                        // `None` immediately and spins hot — measured at ~5.8M iterations
                        // in 200ms, i.e. a pinned core for the life of the process.
                        None => break,
                    }
                }
                status = recv_status.recv() => {
                    // `None` means `shell` returned without sending `Terminate`, so
                    // `send_status` dropped. Same hot-spin risk as the data branch, and
                    // nobody else will close the channel, so do both.
                    let Some(Status::Terminate(exit)) = status else {
                        let _ = handle_session.close(channel).await;
                        break;
                    };
                    // Reedline's teardown reaches `recv_from_shell` through
                    // `SenderWriter`, whose `send().await` only waits for buffering, not
                    // for this task to consume it. Both branches are then ready at once
                    // and `select!` picks at random, so without this drain `close` below
                    // discards whatever the prompt wrote last. `try_recv`, not `recv`:
                    // the tty task still holds a `send_to_session` clone, so `recv`
                    // would wait for input that is not coming.
                    while let Ok(d) = recv_from_shell.try_recv() {
                        if handle_session.data(channel, d).await.is_err() {
                            break;
                        }
                    }
                    let _ = handle_session.exit_status_request(channel, exit).await;
                    let _ = handle_session.close(channel).await;
                    break;
                }
            }
        }
    });

    let log = log.scoped(EventKind::Admin);
    let shell_log = log.clone();
    tokio::spawn(async move {
        shell::shell(
            tty,
            send_to_session,
            send_status,
            user_id,
            handler_id,
            backend,
            shell_log,
        )
        .await
    });

    log.record("User login to admin system").await;
    Ok(())
}

pub enum Status {
    Terminate(u32),
}
