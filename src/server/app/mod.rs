pub(super) mod admin;
pub(super) mod change_password;
pub(super) mod connect_target;
pub mod error;
pub(super) mod player;
pub(super) mod target_selector;

use crate::database::models;
use crate::server::HandlerLog;
use crate::server::tty::Tty;
use russh::ChannelId;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct AppParams<B: 'static + crate::server::HandlerBackend + Send + Sync> {
    pub handler_id: Uuid,
    pub user_id: Uuid,
    pub client_ip: Option<std::net::IpAddr>,
    pub backend: Arc<B>,
    pub tty: Tty,
    pub log: HandlerLog,
    pub app_sender: mpsc::Sender<(ChannelId, NextApplication)>,
}

type Params<B> = (
    Uuid,
    Uuid,
    Option<std::net::IpAddr>,
    Arc<B>,
    Tty,
    HandlerLog,
    mpsc::Sender<(ChannelId, NextApplication)>,
);

impl<B: 'static + crate::server::HandlerBackend + Send + Sync> AppParams<B> {
    fn split(self) -> Params<B> {
        (
            self.handler_id,
            self.user_id,
            self.client_ip,
            self.backend,
            self.tty,
            self.log,
            self.app_sender,
        )
    }
}

#[derive(Default)]
pub enum Application<B: 'static + crate::server::HandlerBackend + Send + Sync> {
    ConnectTarget(Box<connect_target::ConnectTarget<B>>),
    TargetSelector,
    Admin,
    Password,
    Player,
    #[default]
    None,
}

#[derive(Default)]
pub enum NextApplication {
    ConnectTargetShell(Box<(models::Target, models::TargetSecretName)>),
    #[default]
    None,
}
