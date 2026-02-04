use super::casbin;
use crate::database::DatabaseRepository;
use crate::database::Uuid;
use aes_gcm::aead::Aead;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use log::{error, info, trace, warn};
use moka::future::Cache;
use moka::ops::compute::{CompResult, Op};
use petgraph::stable_graph::StableDiGraph;
use russh::client as ru_client;
use russh::keys::Algorithm;
use russh::server::{Config as RusshConfig, Server};

use super::bastion_handler::BastionHandler;
use crate::config::Config;
use crate::database::models;
use crate::database::service::DatabaseService;
use crate::error::Error;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use rand_core::RngCore;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

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
            None => return Err(Error::Server("Invalid secret token".to_string())),
        };

        let plain_token = general_purpose::STANDARD
            .decode(b64_token)
            .map_err(|e| Error::Server(format!("Failed to parse secret token: {}", e)))?;

        let token = aes_gcm::Aes256Gcm::new_from_slice(&plain_token)
            .map_err(|e| Error::Server(format!("Failed to parse secret token: {}", e)))?;

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
                .list_casbin_rule_group_by_ptype("g1")
                .await?;
            let g2 = database
                .repository()
                .list_casbin_rule_group_by_ptype("g2")
                .await?;
            let g3 = database
                .repository()
                .list_casbin_rule_group_by_ptype("g3")
                .await?;

            casbin::RoleManage::new(&g1, &g2, &g3)?
        };

        // Initialize global internal UUIDs (only once)
        if !crate::database::common::InternalUuids::is_initialized() {
            use crate::database::common::*;

            let obj_login = database
                .repository()
                .get_casbin_name_by_name(OBJ_LOGIN)
                .await?
                .ok_or_else(|| Error::Casbin(format!("Internal object '{}' not found", OBJ_LOGIN)))?
                .id;
            let obj_admin = database
                .repository()
                .get_casbin_name_by_name(OBJ_ADMIN)
                .await?
                .ok_or_else(|| Error::Casbin(format!("Internal object '{}' not found", OBJ_ADMIN)))?
                .id;
            let act_shell = database
                .repository()
                .get_casbin_name_by_name(ACT_SHELL)
                .await?
                .ok_or_else(|| Error::Casbin(format!("Action '{}' not found", ACT_SHELL)))?
                .id;
            let act_pty = database
                .repository()
                .get_casbin_name_by_name(ACT_PTY)
                .await?
                .ok_or_else(|| Error::Casbin(format!("Action '{}' not found", ACT_PTY)))?
                .id;
            let act_exec = database
                .repository()
                .get_casbin_name_by_name(ACT_EXEC)
                .await?
                .ok_or_else(|| Error::Casbin(format!("Action '{}' not found", ACT_EXEC)))?
                .id;
            let act_login = database
                .repository()
                .get_casbin_name_by_name(ACT_LOGIN)
                .await?
                .ok_or_else(|| Error::Casbin(format!("Action '{}' not found", ACT_LOGIN)))?
                .id;
            let act_direct_tcpip = database
                .repository()
                .get_casbin_name_by_name(ACT_DIRECT_TCPIP)
                .await?
                .ok_or_else(|| Error::Casbin(format!("Action '{}' not found", ACT_DIRECT_TCPIP)))?
                .id;

            InternalUuids::init(InternalUuids {
                obj_login,
                obj_admin,
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
            .list_casbin_rule_group_by_ptype("g1")
            .await?;
        let g2 = self
            .database
            .repository()
            .list_casbin_rule_group_by_ptype("g2")
            .await?;
        let g3 = self
            .database
            .repository()
            .list_casbin_rule_group_by_ptype("g3")
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
                russh::keys::PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
                    .map_err(russh::Error::from)?,
            ]
        };

        let russh_config = RusshConfig {
            keys,
            inactivity_timeout: self.config.inactivity_timeout,
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

    fn decrypt_with_secret_key(&self, text: String) -> Result<String, Error> {
        let encrypt_key = general_purpose::STANDARD
            .decode(text)
            .map_err(|e| Error::Server(format!("Failed to decode base64 text: {}", e)))?;
        let (nonce, ciphertext) = encrypt_key.split_at(12);
        let nonce = Nonce::from_slice(nonce);

        match self.secret_key.decrypt(nonce, ciphertext.as_ref()) {
            Ok(plain) => Ok(String::from_utf8_lossy(&plain).to_string()),
            Err(e) => Err(Error::Server(format!("Falied to decrypt secret: {}", e))),
        }
    }

    pub async fn generate_random_password(&self, mut user: models::User) -> Result<String, Error> {
        let password = crate::common::gen_password(12);
        let h = self
            .hash_password(&password)
            .map_err(|_| Error::Server("encrypt user's password failed".to_string()))?;
        user.set_password_hash(h);
        self.database.repository().update_user(&user).await?;
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

    // async fn get_target_by_name(&self, name: &str) -> Result<Option<models::Target>, Error> {
    //     self.database.repository().get_target_by_name(name).await
    // }

    async fn get_target_by_id(
        &self,
        id: &Uuid,
        active_only: bool,
    ) -> Result<Option<models::Target>, Error> {
        self.database
            .repository()
            .get_target_by_id(id, active_only)
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
            .list_casbin_rules_by_ptype("p")
            .await?;
        let allowed_policies = self.role_manager.read().await.match_sub(policies, *user_id);

        // NOTE: Duplicate ids of target_secrets due to different policies.
        for pol in allowed_policies {
            // Get all role IDs from object group
            let role_manager = self.role_manager.read().await;
            let role_ids = role_manager.fetch_role_from_start(pol.v1, casbin::RoleType::Object);
            drop(role_manager); // Release the lock before awaiting database
            let role_ids_ref: Vec<&Uuid> = role_ids.iter().collect();

            let ts = self
                .database
                .repository()
                .list_targets_by_ids(&role_ids_ref, &pol.id, active_only)
                .await?;
            if ts.is_empty() {
                // Try pol.v1 directly as a target_secret ID
                let t = self
                    .database
                    .repository()
                    .list_targets_by_ids(&[&pol.v1], &pol.id, active_only)
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
        target_secret_id: &Uuid,
        force_build_cconnect: bool,
    ) -> Result<Option<Arc<ru_client::Handle<models::Target>>>, Error> {
        let conn_key = format!("{}-{}", target_secret_id, target.id);
        if let Some(pool) = self.connection_pool.as_ref() {
            if force_build_cconnect {
                pool.invalidate(&conn_key).await;
            }
            if let Some(t) = pool.get(&conn_key).await {
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

        let mut handle = target.build_connect().await?;

        if let Some(k) = secret.take_private_key() {
            let key =
                russh::keys::decode_secret_key(self.decrypt_with_secret_key(k)?.as_str(), None)?;
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
                    pool.insert(conn_key, handle.clone()).await;
                };
                return Ok(Some(handle));
            }
        };

        if let Some(p) = secret.take_password() {
            let pass = self.decrypt_with_secret_key(p)?;
            let auth_res = handle.authenticate_password(secret.user, pass).await?;
            if auth_res.success() {
                let handle = Arc::new(handle);
                if let Some(pool) = self.connection_pool.as_ref() {
                    pool.insert(conn_key, handle.clone()).await;
                };
                return Ok(Some(handle));
            }
        }

        Ok(None)
    }

    async fn update_user_password(
        &self,
        password: String,
        mut user: models::User,
    ) -> Result<models::User, Error> {
        let h = self
            .hash_password(&password)
            .map_err(|_| Error::Server("encrypt user's password failed".to_string()))?;
        user.set_password_hash(h);
        self.database.repository().update_user(&user).await?;
        Ok(user)
    }

    fn set_password(&self, user: &mut models::User, password: &str) -> Result<(), Error> {
        let h = self
            .hash_password(password)
            .map_err(|_| Error::Server("encrypt user's password failed".to_string()))?;
        user.set_password_hash(h);
        Ok(())
    }

    // async fn update_user(&self, user: models::User) -> Result<models::User, Error> {
    //     self.database.repository().update_user(&user).await?;
    //     Ok(user)
    // }

    async fn insert_log(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        log_type: String,
        detail: String,
    ) {
        let l = models::Log {
            connection_id,
            user_id,
            log_type,
            detail,
            created_at: chrono::Utc::now().timestamp_millis(),
        };
        if let Err(e) = self.database.repository().insert_log(&l).await {
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
            if let CompResult::ReplacedWith(entry) = result {
                if entry.value() > &self.config.max_ip_attempts {
                    warn!("Brute-force login detected from {}", ip);
                    res = true;
                }
            }
        }

        let result = increment_counter(&self.client_user_pool, &username).await;
        if let CompResult::ReplacedWith(entry) = result {
            if entry.value() > &self.config.max_user_attempts {
                warn!("Brute-force login detected for user: {}", username);
                res = true;
            }
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
        ext: casbin::ExtendPolicyReq,
    ) -> Result<bool, Error> {
        // match sub
        let policies = self
            .database
            .repository()
            .list_casbin_rules_by_ptype("p")
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
                    .match_role(pol.v1, obj, casbin::RoleType::Object)
            {
                if !self.database.repository().check_object_active(&obj).await? {
                    trace!(
                        "Reject due to object not active, sub: {}, act: {}, policy: {:?}",
                        sub,
                        obj,
                        pol
                    );
                    continue;
                }
                // match act
                if let Some(policy_act) = pol.v2 {
                    if policy_act == act
                        || self.role_manager.read().await.match_role(
                            policy_act,
                            act,
                            casbin::RoleType::Action,
                        )
                    {
                        // match ext
                        if casbin::verify_extend_policy(&ext, &pol.v3)? {
                            trace!("Accept sub: {}, policy: {:?}", sub, pol);
                            return Ok(true);
                        }
                    } else {
                        trace!(
                            "Reject by action, sub: {}, act: {}, policy: {:?}",
                            sub,
                            act,
                            pol
                        );
                    }
                }
            } else {
                trace!(
                    "Reject by object, sub: {}, obj: {}, policy: {:?}",
                    sub,
                    obj,
                    pol
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
        let mut nonce_bytes = [0u8; 12]; // 96-bit nonce
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .secret_key
            .encrypt(nonce, text.as_bytes())
            .map_err(|e| Error::Server(format!("Failed to encrypt plain text: {}", e)))?;

        let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext); // already includes 16-byte tag

        Ok(general_purpose::STANDARD.encode(blob))
    }

    async fn get_role_graph(&self, rt: casbin::RoleType) -> StableDiGraph<casbin::RuleGroup, ()> {
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
