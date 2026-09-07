pub(super) mod app;
mod bastion_handler;
pub mod bastion_server;
mod casbin;
mod connection_pool;
pub mod error;
mod event_log;
mod extend_policy;
pub mod init_service;
mod test;
mod tty;
mod widgets;

pub use bastion_server::BastionServer;
pub use casbin::{RuleNode, RuleType};

use crate::database::DatabaseRepository;
use crate::database::Uuid;
use crate::database::entity::user;
use crate::database::models::{GroupType, Target, TargetSecretName, User};
use crate::error::Error;
use event_log::Event;
use petgraph::stable_graph::StableDiGraph;
use russh::client as ru_client;
use std::future::Future;
use std::sync::Arc;

//TODO: Remove uneccessary sql query
pub(super) trait HandlerBackend: Send + Clone {
    fn db_repository(&self) -> &dyn DatabaseRepository;
    fn get_user_by_username(
        &self,
        name: &str,
        active_only: bool,
    ) -> impl Future<Output = Result<Option<User>, Error>> + Send;

    fn update_user_password(
        &self,
        password: String,
        user: user::ActiveModel,
    ) -> impl Future<Output = Result<User, Error>> + Send;

    fn list_targets_for_user(
        &self,
        user_id: &Uuid,
        active_only: bool,
    ) -> impl Future<Output = Result<Vec<TargetSecretName>, Error>> + Send;

    /// Best-effort audit write; failures are reported, not returned. Call
    /// sites go through [`EventLogger`] rather than here.
    fn insert_log(&self, event: Event) -> impl Future<Output = ()> + Send;

    fn clear_auth_attempts(
        &self,
        ip: Option<std::net::SocketAddr>,
        username: String,
    ) -> impl Future<Output = ()> + Send;

    fn reject_auth_attempts(
        &self,
        ip: Option<std::net::SocketAddr>,
        username: String,
    ) -> impl Future<Output = bool> + Send;

    /// Connection will be force build without using cache, if `force_build_connect` set `true`
    fn connect_to_target(
        &self,
        target: Target,
        target_secret_id: Uuid,
        force_build_connect: bool,
    ) -> impl Future<Output = Result<Option<Arc<ru_client::Handle<Target>>>, Error>> + Send;

    /// This is a lightweight implementation of Casbin.
    /// It only supports a single-level group structure.
    /// It uses the same data-storage format and table schema as Casbin.
    /// ptype, v0, v1, v2, v3, v4, v5
    ///
    /// Only a fixed model is supported; the model is as follows:
    ///
    /// ```ini
    /// [request_definition]
    /// r = sub, obj, act, ext
    ///
    /// [policy_definition]
    /// p = sub, obj, act, ext
    ///
    /// [role_definition]
    /// g = _, _
    /// g2 = _, _
    /// g3 = _, _
    ///
    /// [policy_effect]
    /// e = some(where (p.eft == allow))
    ///
    /// [matchers]
    /// m = g(r.sub, p.sub) && g2(r.obj, p.obj) && g3(r.act, p.act) && extend_policy(r.ext, p.ext)
    /// ```
    ///
    fn enforce(
        &self,
        sub: Uuid,
        obj: Uuid,
        act: Uuid,
        ext: extend_policy::ExtendPolicyReq,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    fn encrypt_plain_text(&self, text: &str) -> Result<String, Error>;
    fn enable_record(&self) -> bool;
    fn record_input(&self) -> bool;
    fn record_path(&self) -> &str;

    fn set_password(&self, user: &mut user::ActiveModel, password: &str) -> Result<(), Error>;
    fn load_role_manager(&self) -> impl Future<Output = Result<(), Error>> + Send;

    fn get_graph(
        &self,
        rt: GroupType,
    ) -> impl Future<Output = StableDiGraph<casbin::RuleNode, ()>> + Send;
}
