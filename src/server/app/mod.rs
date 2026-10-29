pub(super) mod admin;
pub(super) mod change_password;
pub(super) mod connect_target;
pub(super) mod sftp;
use bytes::Bytes;
pub mod error;
pub(super) mod player;
pub(super) mod target_selector;

use crate::database::models;
use crate::server::event_log::EventLogger;
use crate::server::tty::Tty;
use russh::ChannelId;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct ExecParams<B: 'static + crate::server::HandlerBackend + Send + Sync> {
    /// The interface language: the client's locale, or the configured one.
    pub lang: crate::i18n::Lang,
    pub handler_id: Uuid,
    pub user_id: Uuid,
    pub client_ip: Option<std::net::IpAddr>,
    pub backend: Arc<B>,
    pub recv: mpsc::Receiver<Bytes>,
    pub log: EventLogger<B>,
}

pub struct PtyParams<B: 'static + crate::server::HandlerBackend + Send + Sync> {
    /// The interface language: the client's locale, or the configured one.
    pub lang: crate::i18n::Lang,
    pub handler_id: Uuid,
    pub user_id: Uuid,
    pub client_ip: Option<std::net::IpAddr>,
    pub backend: Arc<B>,
    pub tty: Tty,
    pub recv_from_tty: mpsc::Receiver<Bytes>,
    pub log: EventLogger<B>,
    pub app_sender: mpsc::Sender<(ChannelId, NextApplication)>,
}

type ScatterExecParams<B> = (
    Uuid,
    Uuid,
    Option<std::net::IpAddr>,
    Arc<B>,
    mpsc::Receiver<Bytes>,
    EventLogger<B>,
);

type ScatterPtyParams<B> = (
    Uuid,
    Uuid,
    Option<std::net::IpAddr>,
    Arc<B>,
    Tty,
    mpsc::Receiver<Bytes>,
    EventLogger<B>,
    mpsc::Sender<(ChannelId, NextApplication)>,
);

impl<B: 'static + crate::server::HandlerBackend + Send + Sync> ExecParams<B> {
    fn split(self) -> ScatterExecParams<B> {
        (
            self.handler_id,
            self.user_id,
            self.client_ip,
            self.backend,
            self.recv,
            self.log,
        )
    }
}

impl<B: 'static + crate::server::HandlerBackend + Send + Sync> PtyParams<B> {
    fn split(self) -> ScatterPtyParams<B> {
        (
            self.handler_id,
            self.user_id,
            self.client_ip,
            self.backend,
            self.tty,
            self.recv_from_tty,
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
    Sftp,
    #[default]
    None,
}

#[derive(Default)]
pub enum NextApplication {
    ConnectTargetShell(Box<(models::Target, models::TargetSecretName)>),
    #[default]
    None,
}
