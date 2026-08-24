use super::casbin;
use super::extend_policy::{ExtendPolicyReq, verify_extend_policy};
use crate::database::DatabaseRepository;
use crate::database::Uuid;
use crate::database::entity::{event_log, user};
use crate::server::HandlerBackend;
use crate::server::error::ServerError;
use crate::utils::proxy_connect;
use aes_gcm::aead::OsRng;
use aes_gcm::aead::{Aead, rand_core::RngCore};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use log::{error, info, trace, warn};
use moka::future::Cache;
use moka::ops::compute::{CompResult, Op};
use petgraph::stable_graph::StableDiGraph;
use rand::rng;
use russh::client as ru_client;
use russh::keys::Algorithm;
use russh::server::{Config as RusshConfig, Server};
use sea_orm::ActiveValue::Set;
use std::future::Future;
use std::pin::Pin;

use super::bastion_handler::BastionHandler;
use crate::config::Config;
use crate::database::models;
use crate::database::models::{GroupType, Ptype};
use crate::database::service::DatabaseService;
use crate::error::Error;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{Engine as _, engine::general_purpose};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

type PinBoxStream<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    Option<Pin<Box<dyn crate::database::models::target::Stream>>>,
                    Error,
                >,
            > + Send
            + 'a,
    >,
>;

#[derive(Clone)]
pub struct BastionServer {
    config: Config,
    secret_key: Aes256Gcm,
    database: DatabaseService,
    client_ip_pool: Cache<std::net::IpAddr, u32>,
    client_user_pool: Cache<String, u32>,
    connection_pool: Option<super::connection_pool::ConnectionPool>,
    role_manager: Arc<RwLock<casbin::RoleManage>>,
}

impl Server for BastionServer {
    type Handler = BastionHandler<Self>;
    fn new_client(&mut self, client_ip: Option<std::net::SocketAddr>) -> BastionHandler<Self> {
        BastionHandler::new(
            client_ip,
            self.config.max_auth_attempts_per_conn,
            Arc::new(self.clone()),
        )
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        error!("Session error: {}", error);
    }
}

impl BastionServer {
    pub async fn with_config(mut config: Config) -> Result<Self, Error> {
        let b64_token = match config.take_secret_token() {
            Some(token) => token,
            None => return Err(Error::Server(ServerError::MissingSecretToken)),
        };

        let plain_token = general_purpose::STANDARD
            .decode(b64_token)
            .map_err(|e| Error::Server(ServerError::SecretTokenDecode { source: e }))?;

        let token = aes_gcm::Aes256Gcm::new_from_slice(&plain_token).map_err(|e| {
            Error::Server(ServerError::EncryptionKeyError {
                reason: e.to_string(),
            })
        })?;

        // Initialize database service
        let database = DatabaseService::new(&config.database).await?;

        const MAX_CAPACITY: u64 = 5000;
        let connection_pool = if config.reuse_target_connection {
            let idle = config.target_cache_duration;
            let cache = Cache::builder()
                .max_capacity(MAX_CAPACITY)
                .time_to_idle(idle)
                .build();
            let res = cache.clone();
            tokio::spawn(async move {
                loop {
                    // Expired cache will be removed every 1 minute
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    cache.run_pending_tasks().await;
                }
            });
            Some(res)
        } else {
            None
        };

        let client_ip_pool = Cache::builder().time_to_idle(config.unban_duration).build();
        let cache = client_ip_pool.clone();
        tokio::spawn(async move {
            loop {
                // Expired cache will be removed every 1 minute
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                cache.run_pending_tasks().await;
            }
        });

        let client_user_pool = Cache::builder().time_to_idle(config.unban_duration).build();
        let cache = client_user_pool.clone();
        tokio::spawn(async move {
            loop {
                // Expired cache will be removed every 1 minute
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                cache.run_pending_tasks().await;
            }
        });

        // initial casbin role
        let role_manager = {
            let g1 = database
                .repository()
                .list_casbin_rule_group_by_ptype(Ptype::G1)
                .await?;
            let g2 = database
                .repository()
                .list_casbin_rule_group_by_ptype(Ptype::G2)
                .await?;
            let g3 = database
                .repository()
                .list_casbin_rule_group_by_ptype(Ptype::G3)
                .await?;

            casbin::RoleManage::new(&g1, &g2, &g3)?
        };

        // Initialize global internal UUIDs (only once)
        // TODO: Query once to get all internal uuids.
        if !crate::database::common::InternalUuids::is_initialized() {
            use crate::database::common::*;

            let obj_login = database
                .repository()
                .get_casbin_name_by_name(OBJ_LOGIN)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::InternalObjectNotFound {
                        name: OBJ_LOGIN.to_string(),
                    })
                })?
                .id;
            let obj_admin = database
                .repository()
                .get_casbin_name_by_name(OBJ_ADMIN)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::InternalObjectNotFound {
                        name: OBJ_ADMIN.to_string(),
                    })
                })?
                .id;
            let obj_player = database
                .repository()
                .get_casbin_name_by_name(OBJ_PLAYER)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::InternalObjectNotFound {
                        name: OBJ_PLAYER.to_string(),
                    })
                })?
                .id;
            let act_shell = database
                .repository()
                .get_casbin_name_by_name(ACT_SHELL)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::ActionNotFound {
                        name: ACT_SHELL.to_string(),
                    })
                })?
                .id;
            let act_pty = database
                .repository()
                .get_casbin_name_by_name(ACT_PTY)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::ActionNotFound {
                        name: ACT_PTY.to_string(),
                    })
                })?
                .id;
            let act_exec = database
                .repository()
                .get_casbin_name_by_name(ACT_EXEC)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::ActionNotFound {
                        name: ACT_EXEC.to_string(),
                    })
                })?
                .id;
            let act_login = database
                .repository()
                .get_casbin_name_by_name(ACT_LOGIN)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::ActionNotFound {
                        name: ACT_LOGIN.to_string(),
                    })
                })?
                .id;
            let act_direct_tcpip = database
                .repository()
                .get_casbin_name_by_name(ACT_DIRECT_TCPIP)
                .await?
                .ok_or_else(|| {
                    Error::Server(ServerError::ActionNotFound {
                        name: ACT_DIRECT_TCPIP.to_string(),
                    })
                })?
                .id;

            InternalUuids::init(InternalUuids {
                obj_login,
                obj_admin,
                obj_player,
                act_shell,
                act_pty,
                act_exec,
                act_login,
                act_direct_tcpip,
            });
        }

        Ok(Self {
            config,
            secret_key: token,
            database,
            client_ip_pool,
            client_user_pool,
            connection_pool,
            role_manager: Arc::new(RwLock::new(role_manager)),
        })
    }

    pub async fn do_load_role_manager(&self) -> Result<(), Error> {
        let g1 = self
            .database
            .repository()
            .list_casbin_rule_group_by_ptype(Ptype::G1)
            .await?;
        let g2 = self
            .database
            .repository()
            .list_casbin_rule_group_by_ptype(Ptype::G2)
            .await?;
        let g3 = self
            .database
            .repository()
            .list_casbin_rule_group_by_ptype(Ptype::G3)
            .await?;

        let mut m = self.role_manager.write().await;
        *m = casbin::RoleManage::new(&g1, &g2, &g3)?;
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        // Load server key or generate a random one
        let key_file = Path::new(&self.config.server_key);
        let keys = if key_file.exists() {
            vec![russh::keys::PrivateKey::read_openssh_file(key_file).map_err(russh::Error::from)?]
        } else {
            warn!("Server key file not found, generating a random key",);
            vec![
                russh::keys::PrivateKey::random(&mut rng(), Algorithm::Ed25519)
                    .map_err(russh::Error::from)?,
            ]
        };

        let russh_config = RusshConfig {
            keys,
            server_id: russh::SshId::Standard(self.config.server_id.clone().into()),
            inactivity_timeout: self.config.inactivity_timeout,
            auth_rejection_time: self.config.auth_rejection_time,
            ..Default::default()
        };

        let listen_addr = self.config.parse_listen_addr()?;
        info!("Starting rustion server on {}", listen_addr);

        let socket = tokio::net::TcpListener::bind(listen_addr).await?;
        let server = self.run_on_socket(Arc::new(russh_config), &socket);
        // TODO: gracefully shutdown when catch TERM signal
        let _handle = server.handle();

        server.await?;
        Ok(())
    }

    /// Hash a plain-text password and return a PHC string.
    fn hash_password(&self, password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    fn connect_to_proxy<'a>(
        &'a self,
        dest: &'a models::Target,
        proxy: http::Uri,
    ) -> PinBoxStream<'a> {
        Box::pin(async move {
            match proxy.scheme_str() {
                Some("ssh") => {
                    let host = proxy
                        .host()
                        .ok_or(Error::Server(ServerError::InvalidProxyUrl))?;
                    let id = crate::database::Uuid::parse_str(host)
                        .map_err(|_| Error::Server(ServerError::InvalidProxyUrl))?;
                    let target = if let Some(t) = self
                        .db_repository()
                        .get_target_by_target_secret_id(id, true)
                        .await?
                    {
                        t
                    } else {
                        return Ok(None);
                    };
                    let agent =
                        if let Some(t) = self.connect_to_target(target.clone(), id, false).await? {
                            t
                        } else {
                            return Ok(None);
                        };
                    match agent
                        .as_ref()
                        .channel_open_direct_tcpip(&dest.hostname, dest.port as u32, "127.0.0.1", 0)
                        .await
                    {
                        Ok(ch) => Ok(Some(Box::pin(ch.into_stream())
                            as Pin<Box<dyn crate::database::models::target::Stream>>)),
                        Err(
                            russh::Error::ChannelOpenFailure(
                                russh::ChannelOpenFailure::AdministrativelyProhibited,
                            )
                            | russh::Error::SendError,
                        ) => {
                            let agent =
                                if let Some(t) = self.connect_to_target(target, id, true).await? {
                                    t
                                } else {
                                    return Ok(None);
                                };
                            let ch = agent
                                .as_ref()
                                .channel_open_direct_tcpip(
                                    &dest.hostname,
                                    dest.port as u32,
                                    "127.0.0.1",
                                    0,
                                )
                                .await?;
                            Ok(Some(Box::pin(ch.into_stream())
                                as Pin<Box<dyn crate::database::models::target::Stream>>))
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                Some("http") | Some("https") => {
                    let stream = proxy_connect(proxy, dest.hostname.clone(), dest.port).await?;
                    Ok(Some(
                        Box::pin(stream) as Pin<Box<dyn crate::database::models::target::Stream>>
                    ))
                }
                _ => Err(Error::Server(ServerError::InvalidProxyUrl)),
            }
        })
    }

    fn decrypt_with_secret_key(&self, text: &str) -> Result<String, Error> {
        let encrypt_key = general_purpose::STANDARD
            .decode(text)
            .map_err(|e| Error::Server(ServerError::Base64Decode { source: e }))?;
        let (nonce, ciphertext) = encrypt_key.split_at(12);
        let nonce = Nonce::from_slice(nonce);

        match self.secret_key.decrypt(nonce, ciphertext.as_ref()) {
            Ok(plain) => Ok(String::from_utf8_lossy(&plain).to_string()),
            Err(e) => Err(Error::Server(ServerError::DecryptionFailed {
                reason: e.to_string(),
            })),
        }
    }

    pub async fn generate_random_password(
        &self,
        mut user: user::ActiveModel,
    ) -> Result<String, Error> {
        let password = crate::common::gen_password(12);
        let h = self
            .hash_password(&password)
            .map_err(|_| Error::Server(ServerError::PasswordHashFailed))?;
        user.password_hash = Set(Some(h));
        self.database.repository().update_user(user).await?;
        Ok(password.to_string())
    }
}

impl super::HandlerBackend for BastionServer {
    async fn get_user_by_username(
        &self,
        name: &str,
        active_only: bool,
    ) -> Result<Option<models::User>, Error> {
        self.database
            .repository()
            .get_user_by_username(name, active_only)
            .await
    }

    async fn list_targets_for_user(
        &self,
        user_id: &Uuid,
        active_only: bool,
    ) -> Result<Vec<models::TargetSecretName>, Error> {
        let mut res = Vec::new();
        let policies = self
            .database
            .repository()
            .list_casbin_rules_by_ptype(Ptype::Policy)
            .await?;
        let allowed_policies = self.role_manager.read().await.match_sub(policies, *user_id);

        // NOTE: Duplicate ids of target_secrets due to different policies.
        for pol in allowed_policies {
            // Get all role IDs from object group
            let role_manager = self.role_manager.read().await;
            let role_ids = role_manager.fetch_role_from_start(pol.v1, GroupType::Object);
            drop(role_manager); // Release the lock before awaiting database
            let role_ids_ref: Vec<&Uuid> = role_ids.iter().collect();

            let ts = self
                .database
                .repository()
                .list_targets_by_ids(&role_ids_ref, pol.id, active_only)
                .await?;
            if ts.is_empty() {
                // Try pol.v1 directly as a target_secret ID
                let t = self
                    .database
                    .repository()
                    .list_targets_by_ids(&[&pol.v1], pol.id, active_only)
                    .await?;
                if !t.is_empty() {
                    res.extend_from_slice(&t);
                }
            } else {
                res.extend_from_slice(&ts);
            }
        }
        Ok(res)
    }

    async fn connect_to_target(
        &self,
        target: models::Target,
        target_secret_id: Uuid,
        force_build_connect: bool,
    ) -> Result<Option<Arc<ru_client::Handle<models::Target>>>, Error> {
        if let Some(pool) = self.connection_pool.as_ref() {
            if force_build_connect {
                pool.invalidate(&target_secret_id).await;
            }
            if let Some(t) = pool.get(&target_secret_id).await {
                return Ok(Some(t));
            }
        };
        let mut secret = match self
            .database
            .repository()
            .get_secret_by_target_secret_id(target_secret_id, true)
            .await?
        {
            Some(s) => {
                if !s.is_active {
                    return Ok(None);
                }
                s
            }
            None => return Ok(None),
        };

        let proxy = target
            .proxy
            .as_deref()
            .map(http::Uri::try_from)
            .transpose()
            .map_err(|_| crate::database::error::DatabaseError::InvalidProxy)?;

        let stream = match proxy {
            Some(p) => {
                if let Some(s) = self.connect_to_proxy(&target, p).await? {
                    Some(s)
                } else {
                    return Ok(None);
                }
            }
            None => None,
        };
        let mut handle = target
            .build_connect(self.config.client_id.clone(), stream)
            .await?;

        if let Some(k) = secret.take_private_key() {
            let key = match russh::keys::decode_secret_key(
                self.decrypt_with_secret_key(&k)?.as_str(),
                None,
            ) {
                Ok(k) => k,
                Err(e) => {
                    if matches!(e, russh::keys::Error::KeyIsEncrypted) {
                        let pass = match secret.take_password() {
                            Some(pub_key) => Some(self.decrypt_with_secret_key(&pub_key)?),
                            None => None,
                        };
                        match russh::keys::decode_secret_key(
                            self.decrypt_with_secret_key(&k)?.as_str(),
                            pass.as_deref(),
                        ) {
                            Ok(key) => key,
                            Err(e) => return Err(e.into()),
                        }
                    } else {
                        return Err(e.into());
                    }
                }
            };
            let auth_res = handle
                .authenticate_publickey(
                    secret.user.clone(),
                    russh::keys::PrivateKeyWithHashAlg::new(
                        Arc::new(key),
                        handle.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?;
            if auth_res.success() {
                let handle = Arc::new(handle);
                if let Some(pool) = self.connection_pool.as_ref() {
                    pool.insert(target_secret_id, handle.clone()).await;
                };
                return Ok(Some(handle));
            }
        };

        if let Some(p) = secret.take_password() {
            let pass = self.decrypt_with_secret_key(&p)?;
            let auth_res = handle.authenticate_password(secret.user, pass).await?;
            if auth_res.success() {
                let handle = Arc::new(handle);
                if let Some(pool) = self.connection_pool.as_ref() {
                    pool.insert(target_secret_id, handle.clone()).await;
                };
                return Ok(Some(handle));
            }
        }

        Ok(None)
    }

    async fn update_user_password(
        &self,
        password: String,
        mut user: user::ActiveModel,
    ) -> Result<models::User, Error> {
        let h = self
            .hash_password(&password)
            .map_err(|_| Error::Server(ServerError::PasswordHashFailed))?;
        user.password_hash = Set(Some(h));
        self.database.repository().update_user(user).await
    }

    fn set_password(&self, user: &mut user::ActiveModel, password: &str) -> Result<(), Error> {
        let h = self
            .hash_password(password)
            .map_err(|_| Error::Server(ServerError::PasswordHashFailed))?;
        user.password_hash = Set(Some(h));
        Ok(())
    }

    async fn insert_log(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        log_type: String,
        detail: String,
    ) {
        // `created_at` is stamped by the repository.
        let l = event_log::ActiveModel {
            connection_id: Set(connection_id),
            user_id: Set(user_id),
            log_type: Set(log_type),
            detail: Set(detail),
            ..Default::default()
        };
        if let Err(e) = self.database.repository().insert_log(l).await {
            error!("Insert log to database failed: {}", e);
        };
    }

    async fn clear_auth_attempts(
        &self,
        socket_addr: Option<std::net::SocketAddr>,
        username: String,
    ) {
        if let Some(sa) = socket_addr {
            let ip = sa.ip();
            remove_counter(&self.client_ip_pool, &ip).await;
        }

        remove_counter(&self.client_user_pool, &username).await;
    }

    async fn reject_auth_attempts(
        &self,
        socket_addr: Option<std::net::SocketAddr>,
        username: String,
    ) -> bool {
        let mut res = false;
        if let Some(sa) = socket_addr {
            let ip = sa.ip();
            let result = increment_counter(&self.client_ip_pool, &ip).await;
            if let CompResult::ReplacedWith(entry) = result
                && entry.value() > &self.config.max_ip_attempts
            {
                warn!("Brute-force login detected from {}", ip);
                res = true;
            }
        }

        let result = increment_counter(&self.client_user_pool, &username).await;
        if let CompResult::ReplacedWith(entry) = result
            && entry.value() > &self.config.max_user_attempts
        {
            warn!("Brute-force login detected for user: {}", username);
            res = true;
        }

        res
    }

    fn db_repository(&self) -> &dyn DatabaseRepository {
        self.database.repository()
    }

    async fn enforce(
        &self,
        sub: Uuid,
        obj: Uuid,
        act: Uuid,
        ext: ExtendPolicyReq,
    ) -> Result<bool, Error> {
        // match sub
        let policies = self
            .database
            .repository()
            .list_casbin_rules_by_ptype(Ptype::Policy)
            .await?;
        let allowed_policies = self.role_manager.read().await.match_sub(policies, sub);
        trace!("sub: {} polices: {:?}", sub, allowed_policies);

        for pol in allowed_policies {
            // match obj
            if pol.v1 == obj
                || self
                    .role_manager
                    .read()
                    .await
                    .match_role(pol.v1, obj, GroupType::Object)
            {
                if !self.database.repository().check_object_active(obj).await? {
                    trace!(
                        "Reject due to object not active, sub: {}, act: {}, policy: {:?}",
                        sub, obj, pol
                    );
                    continue;
                }
                // match act
                if pol.v2 == act
                    || self
                        .role_manager
                        .read()
                        .await
                        .match_role(pol.v2, act, GroupType::Action)
                {
                    // match ext
                    if verify_extend_policy(&ext, &pol.v3)? {
                        trace!("Accept sub: {}, policy: {:?}", sub, pol);
                        return Ok(true);
                    } else {
                        trace!(
                            "Reject by extend policy, sub: {}, ext: {:?}, policy: {:?}",
                            sub, ext, pol
                        );
                    }
                } else {
                    trace!(
                        "Reject by action, sub: {}, act: {}, policy: {:?}",
                        sub, act, pol
                    );
                }
            } else {
                trace!(
                    "Reject by object, sub: {}, obj: {}, policy: {:?}",
                    sub, obj, pol
                );
            }
        }

        Ok(false)
    }

    fn enable_record(&self) -> bool {
        self.config.enable_record
    }

    fn record_input(&self) -> bool {
        self.config.record_input
    }

    fn record_path(&self) -> &str {
        &self.config.record_path
    }

    async fn load_role_manager(&self) -> Result<(), Error> {
        self.do_load_role_manager().await
    }

    fn encrypt_plain_text(&self, text: &str) -> Result<String, Error> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .secret_key
            .encrypt(nonce, text.as_bytes())
            .map_err(|e| {
                Error::Server(ServerError::EncryptionFailed {
                    reason: e.to_string(),
                })
            })?;

        let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        Ok(general_purpose::STANDARD.encode(blob))
    }

    async fn get_graph(&self, rt: GroupType) -> StableDiGraph<casbin::RuleGroup, ()> {
        self.role_manager.read().await.get_group(rt)
    }
}

async fn remove_counter<T>(cache: &Cache<T, u32>, key: &T)
where
    T: ToOwned<Owned = T> + std::hash::Hash + Eq + Sized + Send + Sync + 'static,
{
    cache.invalidate(key).await;
}

async fn increment_counter<T>(cache: &Cache<T, u32>, key: &T) -> CompResult<T, u32>
where
    T: ToOwned<Owned = T> + std::hash::Hash + Eq + Sized + Send + Sync + 'static,
{
    cache
        .entry_by_ref(key)
        .and_compute_with(|maybe_entry| {
            let op = if let Some(entry) = maybe_entry {
                let counter = entry.into_value();
                Op::Put(counter.saturating_add(1)) // Update
            } else {
                Op::Put(1) // Insert
            };
            // Return a Future that is resolved to `op` immediately.
            std::future::ready(op)
        })
        .await
}
