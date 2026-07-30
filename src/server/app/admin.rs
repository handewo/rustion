use super::AppParams;
use crate::database::common as db_common;
use crate::error::Error;
use crate::server::error::ServerError;
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

const LOG_TYPE: &str = "admin";

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

pub(crate) async fn shell_request<B>(
    app_params: AppParams<B>,
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
    let (send_to_session, mut recv_from_shell) = mpsc::channel::<Bytes>(1);
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
                    if let Some(d) = data && handle_session.data(channel, d).await.is_err() {
                            warn!("[{}] Fail to send data to session from prompt",handler_id);
                            break;
                    };
                }
                status = recv_status.recv() => {
                    if let Some(Status::Terminate(exit)) = status {
                        let _ = handle_session.exit_status_request(channel, exit).await;
                        let _ = handle_session.close(channel).await;
                        break;
                    }
                }
            }
        }
    });

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

    (log)(LOG_TYPE.into(), "User login to admin system".to_string()).await;
    Ok(())
}

pub enum Status {
    Terminate(u32),
}
