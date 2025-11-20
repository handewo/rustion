use async_trait::async_trait;
use chrono::Utc;
use log::{debug, info};
use sqlx::{sqlite::SqlitePool, Pool, Row, Sqlite};

use crate::database::models::{
    Action, AllowedObjects, CasbinRule, InternalObject, Log, Secret, Target, TargetSecret,
    TargetSecretName, User,
};
use crate::database::DatabaseRepository;
use crate::error::Error;

pub struct SqliteRepository {
    pool: Pool<Sqlite>,
}

impl SqliteRepository {
    pub async fn new(database_path: &str) -> Result<Self, Error> {
        let database_url = format!("sqlite:{}", database_path);
        info!("Connecting to SQLite database: {}", database_path);

        let pool = SqlitePool::connect(&database_url)
            .await
            .map_err(|e| Error::Database(format!("Failed to connect to SQLite database: {}", e)))?;

        let repo = Self { pool };
        repo.initialize().await?;

        Ok(repo)
    }

    async fn create_tables(&self) -> Result<(), Error> {
        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password_hash TEXT,
                authorized_keys TEXT,  -- Stores JSON array
                force_init_pass BOOLEAN NOT NULL CHECK (force_init_pass IN (0, 1)),
                is_active BOOLEAN NOT NULL CHECK (is_active IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                CHECK (json_valid(authorized_keys) OR authorized_keys IS NULL)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create users table: {}", e)))?;

        // Create targets table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                server_public_key TEXT NOT NULL,
                description TEXT,
                is_active BOOLEAN NOT NULL CHECK (is_active IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (updated_by) REFERENCES users (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create targets table: {}", e)))?;

        // Create secrets table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                user TEXT NOT NULL,
                password TEXT,
                private_key TEXT,
                public_key TEXT,
                is_active BOOLEAN NOT NULL CHECK (is_active IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (updated_by) REFERENCES users (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create secrets table: {}", e)))?;

        // Create target_secrets table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS target_secrets (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                secret_id TEXT NOT NULL,
                is_active BOOLEAN NOT NULL CHECK (is_active IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (updated_by) REFERENCES users (id)
                FOREIGN KEY (secret_id) REFERENCES secrets (id)
                FOREIGN KEY (target_id) REFERENCES targets (id)
                UNIQUE(target_id, secret_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create target_secrets table: {}", e)))?;

        // Create casbin_rule table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS casbin_rule (
                id TEXT PRIMARY KEY,
                ptype VARCHAR(12) NOT NULL,
                v0 VARCHAR(256) NOT NULL,
                v1 VARCHAR(256) NOT NULL,
                v2 VARCHAR(256) NOT NULL,
                v3 VARCHAR(256) NOT NULL,
                v4 VARCHAR(256) NOT NULL,
                v5 VARCHAR(256) NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (updated_by) REFERENCES users (id)
                CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create log table: {}", e)))?;

        // Create internal_objects table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS internal_objects (
                name TEXT PRIMARY KEY,
                is_active BOOLEAN NOT NULL CHECK (is_active IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create internal_objects table: {}", e)))?;

        // Create log table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS logs (
                connection_id TEXT NOT NULL,
                log_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (created_at, connection_id, detail)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create log table: {}", e)))?;

        // Create indexes for better performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                Error::Database(format!("Failed to create users username index: {}", e))
            })?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_targets_hostname ON targets (hostname)")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                Error::Database(format!("Failed to create targets hostname index: {}", e))
            })?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs (created_at)")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                Error::Database(format!("Failed to create logs created_at index: {}", e))
            })?;

        info!("Database tables and indexes created successfully");
        Ok(())
    }
}

#[async_trait]
impl DatabaseRepository for SqliteRepository {
    async fn initialize(&self) -> Result<(), Error> {
        debug!("Initializing SQLite database");
        self.create_tables().await
    }

    // User operations
    async fn create_user(&self, user: &User) -> Result<User, Error> {
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, authorized_keys, force_init_pass, is_active, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(&user.authorized_keys)
        .bind(user.force_init_pass)
        .bind(user.is_active)
        .bind(&user.updated_by)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create user: {}", e)))?;

        Ok(user.clone())
    }

    async fn get_user_by_id(&self, id: &str) -> Result<Option<User>, Error> {
        let row = sqlx::query_as::<_, User>(
            r#"SELECT id, username, email, password_hash, authorized_keys, force_init_pass, is_active,
            updated_by, updated_at
            FROM users WHERE id = ?"#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to get user by id: {}", e)))?;

        Ok(row)
    }

    async fn get_user_by_username(
        &self,
        username: &str,
        active_only: bool,
    ) -> Result<Option<User>, Error> {
        let mut query =
            r#"SELECT id, username, email, password_hash, authorized_keys, force_init_pass,
        is_active, updated_by, updated_at
            FROM users WHERE username = ?"#
                .to_string();
        if active_only {
            query.push_str(" AND is_active = 1");
        }
        let row = sqlx::query_as::<_, User>(&query)
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to get user by username: {}", e)))?;

        Ok(row)
    }

    async fn update_user(&self, user: &User) -> Result<User, Error> {
        let mut updated_user = user.clone();
        updated_user.updated_at = Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            UPDATE users 
            SET username = ?, email = ?, password_hash = ?, authorized_keys = ?, force_init_pass = ?,
            is_active = ?, updated_by = ?, updated_at = ? WHERE id = ?
            "#,
        )
        .bind(&updated_user.username)
        .bind(&updated_user.email)
        .bind(&updated_user.password_hash)
        .bind(&updated_user.authorized_keys)
        .bind(updated_user.force_init_pass)
        .bind(updated_user.is_active)
        .bind(&updated_user.updated_by)
        .bind(updated_user.updated_at)
        .bind(&updated_user.id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to update user: {}", e)))?;

        Ok(updated_user)
    }

    async fn delete_user(&self, id: &str) -> Result<bool, Error> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete user: {}", e)))?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_users(&self, active_only: bool) -> Result<Vec<User>, Error> {
        let mut query = String::from(
            r#"SELECT id, username, email, password_hash, authorized_keys,
                 force_init_pass, is_active, updated_by, updated_at
          FROM users"#,
        );

        if active_only {
            query.push_str(" WHERE is_active = 1");
        }
        query.push_str(" ORDER BY username");

        sqlx::query_as::<_, User>(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list users: {}", e)))
    }

    // Target operations
    async fn create_target(&self, target: &Target) -> Result<Target, Error> {
        sqlx::query(
            r#"
            INSERT INTO targets
            (id, name, hostname, port, server_public_key, description, is_active, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&target.id)
        .bind(&target.name)
        .bind(&target.hostname)
        .bind(target.port as i64)
        .bind(&target.server_public_key)
        .bind(&target.description)
        .bind(target.is_active)
        .bind(&target.updated_by)
        .bind(target.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create target: {}", e)))?;

        Ok(target.clone())
    }

    async fn get_target_by_id(&self, id: &str, active_only: bool) -> Result<Option<Target>, Error> {
        let mut query = r#"SELECT id, name, hostname, port, server_public_key, description,
            is_active, updated_by, updated_at FROM targets WHERE id = ?"#
            .to_string();
        if active_only {
            query.push_str(" AND is_active = 1");
        }
        let row = sqlx::query_as::<_, Target>(&query)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to get target by id: {}", e)))?;

        Ok(row)
    }

    async fn get_targets_by_ids(&self, ids: &[&str]) -> Result<Vec<Target>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            r#"SELECT id, name, hostname, port, server_public_key, description,
            is_active, updated_by, updated_at FROM targets WHERE id IN ({placeholders})"#
        );

        let mut query = sqlx::query_as::<_, Target>(&sql);

        for id in ids {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to get target by ids: {}", e)))?;

        Ok(rows)
    }

    async fn get_targets_by_target_secret_ids(
        &self,
        ids: &[&str],
        active_only: bool,
    ) -> Result<Vec<Target>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let mut sql = format!(
            r#"SELECT t.id, t.name, t.hostname, t.port, t.server_public_key, t.description,
            t.is_active, t.updated_by, t.updated_at FROM target_secrets ts
            INNER JOIN targets t ON ts.target_id = t.id
            WHERE ts.id IN ({placeholders})"#
        );

        if active_only {
            sql.push_str(" AND ts.is_active = 1 AND t.is_active = 1");
        }

        let mut query = sqlx::query_as::<_, Target>(&sql);

        for id in ids {
            query = query.bind(id);
        }
        let rows = query.fetch_all(&self.pool).await.map_err(|e| {
            Error::Database(format!("Failed to get target by target secret ids: {}", e))
        })?;

        Ok(rows)
    }

    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, Error> {
        let row = sqlx::query_as::<_, Target>(
            r#"SELECT id, name, hostname, port, server_public_key, description,
            is_active, updated_by, updated_at FROM targets WHERE name = ?"#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to get target by name: {}", e)))?;

        Ok(row)
    }

    async fn get_target_by_hostname(&self, hostname: &str) -> Result<Option<Target>, Error> {
        let row = sqlx::query_as::<_, Target>(
            r#"SELECT id, name, hostname, port, server_public_key, description,
            is_active, updated_by, updated_at FROM targets WHERE hostname = ?"#,
        )
        .bind(hostname)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to get target by hostname: {}", e)))?;

        Ok(row)
    }

    async fn update_target(&self, target: &Target) -> Result<Target, Error> {
        let mut updated_target = target.clone();
        updated_target.updated_at = Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            UPDATE targets 
            SET name = ?, hostname = ?, port = ?, server_public_key = ?, description = ?,
            is_active = ?, updated_by = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&updated_target.name)
        .bind(&updated_target.hostname)
        .bind(updated_target.port as i64)
        .bind(&updated_target.server_public_key)
        .bind(&updated_target.description)
        .bind(updated_target.is_active)
        .bind(&updated_target.updated_by)
        .bind(updated_target.updated_at)
        .bind(&updated_target.id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to update target: {}", e)))?;

        Ok(updated_target)
    }

    async fn delete_target(&self, id: &str) -> Result<bool, Error> {
        let result = sqlx::query("DELETE FROM targets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete target: {}", e)))?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_targets(&self, active_only: bool) -> Result<Vec<Target>, Error> {
        let mut query = String::from(
            r#"SELECT id, name, hostname, port, server_public_key, description,
                  is_active, updated_by, updated_at
           FROM targets"#,
        );

        if active_only {
            query.push_str(" WHERE is_active = 1");
        }

        sqlx::query_as::<_, Target>(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list targets: {}", e)))
    }

    async fn list_targets_for_user(
        &self,
        user_id: &str,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error> {
        let mut query = r#"
            SELECT l.pid, ts.id, t.id AS target_id, t.name AS target_name, s.id AS secret_id, s.user AS secret_user
            FROM (WITH all_policy AS (SELECT id, v1 FROM casbin_rule WHERE v0 = ? AND ptype = 'p'
            UNION ALL SELECT id, v1 FROM casbin_rule WHERE ptype = 'p' AND v0 IN
            (SELECT v1 FROM casbin_rule WHERE v0 = ? AND ptype = 'g1'))
            SELECT p.id AS pid, c.v0 AS id FROM (SELECT * FROM casbin_rule WHERE ptype = 'g2') c INNER JOIN all_policy p ON p.v1 = c.v1
            UNION ALL SELECT p.id AS pid, p.v1 AS id FROM all_policy p LEFT JOIN (SELECT * FROM casbin_rule WHERE ptype = 'g2') c
            ON p.v1 = c.v1 WHERE c.v1 IS NULL) l INNER JOIN target_secrets ts ON ts.id = l.id
            INNER JOIN targets t ON ts.target_id = t.id INNER JOIN secrets s ON ts.secret_id = s.id
            "#
            .to_string();
        if active_only {
            query.push_str(" WHERE ts.is_active = 1 AND t.is_active = 1 AND s.is_active = 1");
        }
        let targets = sqlx::query_as::<_, TargetSecretName>(&query)
            .bind(user_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list targets for user: {}", e)))?;

        Ok(targets)
    }

    async fn list_targets_by_ids(
        &self,
        ids: &[&str],
        pid: &str,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let mut sql = format!(
            r#"
            SELECT ? AS pid, ts.id, t.id AS target_id, t.name AS target_name, s.id AS secret_id, s.user AS secret_user
            FROM target_secrets ts INNER JOIN targets t ON ts.target_id = t.id
            INNER JOIN secrets s ON ts.secret_id = s.id
            WHERE ts.id IN ({placeholders})"#
        );

        if active_only {
            sql.push_str(" AND ts.is_active = 1 AND t.is_active = 1 AND s.is_active = 1");
        }

        let mut query = sqlx::query_as::<_, TargetSecretName>(&sql).bind(pid);
        for id in ids {
            query = query.bind(id);
        }

        let targets = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list targets by ids: {}", e)))?;

        Ok(targets)
    }

    async fn get_actions_for_policy(&self, policy_act: &str) -> Result<Vec<Action>, Error> {
        let rules = sqlx::query_as::<_, CasbinRule>(
            r#"
            SELECT * FROM casbin_rule WHERE v1 = ? AND ptype = 'g3'
            "#,
        )
        .bind(policy_act)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to get policies for user: {}", e)))?;

        if rules.is_empty() {
            return Ok(vec![policy_act.parse()?]);
        }

        let mut actions = Vec::with_capacity(rules.len());
        for r in rules {
            actions.push(r.v0.parse()?);
        }

        Ok(actions)
    }

    async fn list_objects_for_user(
        &self,
        user_id: &str,
        active_only: bool,
    ) -> Result<Vec<AllowedObjects>, Error> {
        let mut res = self
            .list_targets_for_user(user_id, active_only)
            .await?
            .into_iter()
            .map(|v| AllowedObjects {
                pid: v.pid,
                id: v.id,
            })
            .collect::<Vec<AllowedObjects>>();

        let mut query = r#"
            WITH all_policy AS (SELECT id, v1 FROM casbin_rule WHERE v0 = ? AND ptype = 'p'
            UNION ALL SELECT id, v1 FROM casbin_rule WHERE ptype = 'p' AND v0 IN
            (SELECT v1 FROM casbin_rule WHERE v0 = ? AND ptype = 'g1'))
            SELECT l.* FROM 
            (SELECT p.id AS pid, c.v0 AS id FROM (SELECT * FROM casbin_rule WHERE ptype = 'g2') c INNER JOIN all_policy p ON p.v1 = c.v1
            UNION ALL SELECT p.id AS pid, p.v1 AS id FROM all_policy p LEFT JOIN (SELECT * FROM casbin_rule WHERE ptype = 'g2') c
            ON p.v1 = c.v1 WHERE c.v1 IS NULL) l INNER JOIN internal_objects io ON io.name = l.id
        "#.to_string();
        if active_only {
            query.push_str(" WHERE io.is_active = 1");
        }
        let row = sqlx::query_as::<_, AllowedObjects>(&query)
            .bind(user_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to get objects for user: {}", e)))?;

        res.extend_from_slice(&row);

        // query allowed internal actions for user
        Ok(res)
    }

    async fn get_policies_for_user(&self, user_id: &str) -> Result<Vec<CasbinRule>, Error> {
        let policies = sqlx::query_as::<_, CasbinRule>(
            r#"
            SELECT * FROM casbin_rule WHERE v0 = ? AND ptype = 'p'
            UNION ALL SELECT * FROM casbin_rule WHERE ptype = 'p' AND v0 IN
            (SELECT v1 FROM casbin_rule WHERE v0 = ? AND ptype = 'g1');
            "#,
        )
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to get policies for user: {}", e)))?;

        Ok(policies)
    }

    async fn list_casbin_rules(&self) -> Result<Vec<CasbinRule>, Error> {
        let query = r#"
        SELECT id, ptype, v0, v1, v2, v3, v4, v5, updated_by, updated_at
        FROM casbin_rule
    "#;

        sqlx::query_as::<_, CasbinRule>(query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list casbin rules: {}", e)))
    }

    async fn list_casbin_rules_by_ptype(&self, ptype: &str) -> Result<Vec<CasbinRule>, Error> {
        let query = r#"
        SELECT id, ptype, v0, v1, v2, v3, v4, v5, updated_by, updated_at
        FROM casbin_rule
        WHERE ptype = ?
    "#;

        sqlx::query_as::<_, CasbinRule>(query)
            .bind(ptype)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list casbin rules by ptype: {}", e)))
    }

    async fn create_casbin_rule(&self, rule: &CasbinRule) -> Result<CasbinRule, Error> {
        sqlx::query(
            r#"
            INSERT INTO casbin_rule
            (id, ptype, v0, v1, v2, v3, v4, v5, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.ptype)
        .bind(&rule.v0)
        .bind(&rule.v1)
        .bind(&rule.v2)
        .bind(&rule.v3)
        .bind(&rule.v4)
        .bind(&rule.v5)
        .bind(&rule.updated_by)
        .bind(rule.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create casbin rule: {}", e)))?;

        Ok(rule.clone())
    }

    async fn update_casbin_rule(&self, rule: &CasbinRule) -> Result<CasbinRule, Error> {
        let mut updated_rule = rule.clone();
        updated_rule.updated_at = Utc::now().timestamp_millis();

        sqlx::query(
            r#"
        UPDATE casbin_rule
        SET ptype = ?, v0 = ?, v1 = ?, v2 = ?, v3 = ?, v4 = ?, v5 = ?,
            updated_by = ?, updated_at = ?
        WHERE id = ?
        "#,
        )
        .bind(&updated_rule.ptype)
        .bind(&updated_rule.v0)
        .bind(&updated_rule.v1)
        .bind(&updated_rule.v2)
        .bind(&updated_rule.v3)
        .bind(&updated_rule.v4)
        .bind(&updated_rule.v5)
        .bind(&updated_rule.updated_by)
        .bind(updated_rule.updated_at)
        .bind(&updated_rule.id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to update casbin_rule: {}", e)))?;

        Ok(updated_rule)
    }

    async fn delete_casbin_rule(&self, id: &str) -> Result<bool, Error> {
        let result = sqlx::query("DELETE FROM casbin_rule WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete casbin_rule: {}", e)))?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_secrets(&self, active_only: bool) -> Result<Vec<Secret>, Error> {
        let mut query = String::from(
            r#"SELECT id, name, user, password, private_key, public_key,
            is_active, updated_by, updated_at
            FROM secrets"#,
        );

        if active_only {
            query.push_str(" WHERE is_active = 1");
        }

        sqlx::query_as::<_, Secret>(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list secrets: {}", e)))
    }

    async fn create_secret(&self, secret: &Secret) -> Result<Secret, Error> {
        sqlx::query(
            r#"
            INSERT INTO secrets
            (id, name, user, password, private_key, public_key, is_active, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&secret.id)
        .bind(&secret.name)
        .bind(&secret.user)
        .bind(&secret.password)
        .bind(&secret.private_key)
        .bind(&secret.public_key)
        .bind(secret.is_active)
        .bind(&secret.updated_by)
        .bind(secret.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create secret: {}", e)))?;

        Ok(secret.clone())
    }

    async fn get_secret_by_target_secret_id(
        &self,
        id: &str,
        active_only: bool,
    ) -> Result<Option<Secret>, Error> {
        let mut query = r#"SELECT s.id, s.name, s.user, s.password, s.private_key, s.public_key, s.is_active, s.updated_by,
            s.updated_at FROM target_secrets ts
            INNER JOIN secrets s ON ts.secret_id = s.id
            WHERE ts.id = ?"#
            .to_string();
        if active_only {
            query.push_str(" AND ts.is_active = 1 AND s.is_active = 1");
        }
        let row = sqlx::query_as::<_, Secret>(&query)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to get secret by id: {}", e)))?;

        Ok(row)
    }

    async fn get_secret_by_id(&self, id: &str) -> Result<Option<Secret>, Error> {
        let row = sqlx::query_as::<_, Secret>(
            r#"SELECT id, name, user, password, private_key, public_key, is_active, updated_by,
            updated_at FROM secrets WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to get secret by id: {}", e)))?;

        Ok(row)
    }

    async fn get_secrets_by_ids(&self, ids: &[&str]) -> Result<Vec<Secret>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            r#"SELECT id, name, user, password, private_key, public_key, is_active, updated_by,
            updated_at FROM secrets WHERE id IN ({placeholders})"#,
        );

        let mut query = sqlx::query_as::<_, Secret>(&sql);

        for id in ids {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to get secrets by ids: {}", e)))?;

        Ok(rows)
    }

    async fn update_secret(&self, secret: &Secret) -> Result<Secret, Error> {
        let mut updated_secret = secret.clone();
        updated_secret.updated_at = Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            UPDATE secrets 
            SET name = ?, user = ?, password = ?, private_key = ?, public_key = ?,
            is_active = ?, update_by = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&updated_secret.name)
        .bind(&updated_secret.user)
        .bind(&updated_secret.password)
        .bind(&updated_secret.private_key)
        .bind(&updated_secret.public_key)
        .bind(updated_secret.is_active)
        .bind(&updated_secret.updated_by)
        .bind(updated_secret.updated_at)
        .bind(&updated_secret.id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to update secret: {}", e)))?;

        Ok(updated_secret)
    }

    async fn delete_secret(&self, id: &str) -> Result<bool, Error> {
        let result = sqlx::query("DELETE FROM secrets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete secret: {}", e)))?;

        Ok(result.rows_affected() > 0)
    }

    async fn create_casbin_rules_batch(
        &self,
        rules: &[CasbinRule],
    ) -> Result<Vec<CasbinRule>, Error> {
        if rules.is_empty() {
            return Ok(vec![]);
        }

        // Build “VALUES (?,?,?,?,…), (?,?,?,?,…), …”
        let rows = rules
            .iter()
            .map(|_| "(?,?,?,?,?,?,?,?,?,?)")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r"INSERT INTO casbin_rule
              (id, ptype, v0, v1, v2, v3, v4, v5, updated_by, updated_at)
              VALUES {rows}"
        );

        let mut q = sqlx::query(&query);
        for r in rules {
            q = q
                .bind(&r.id)
                .bind(&r.ptype)
                .bind(&r.v0)
                .bind(&r.v1)
                .bind(&r.v2)
                .bind(&r.v3)
                .bind(&r.v4)
                .bind(&r.v5)
                .bind(&r.updated_by)
                .bind(r.updated_at);
        }

        q.execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to create casbin rules batch: {}", e)))?;

        Ok(rules.to_vec())
    }

    async fn create_users_batch(&self, users: &[User]) -> Result<Vec<User>, Error> {
        if users.is_empty() {
            return Ok(vec![]);
        }

        let rows = (0..users.len())
            .map(|_| "(?,?,?,?,?,?,?,?,?)")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r"INSERT INTO users
          (id, username, email, password_hash, authorized_keys,
           force_init_pass, is_active, updated_by, updated_at)
          VALUES {rows}"
        );
        let mut q = sqlx::query(&query);

        for u in users {
            q = q
                .bind(&u.id)
                .bind(&u.username)
                .bind(&u.email)
                .bind(&u.password_hash)
                .bind(&u.authorized_keys)
                .bind(u.force_init_pass)
                .bind(u.is_active)
                .bind(&u.updated_by)
                .bind(u.updated_at);
        }

        q.execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to create users batch: {}", e)))?;

        Ok(users.to_vec())
    }

    async fn create_targets_batch(&self, targets: &[Target]) -> Result<Vec<Target>, Error> {
        if targets.is_empty() {
            return Ok(vec![]);
        }

        let rows = (0..targets.len())
            .map(|_| "(?,?,?,?,?,?,?,?,?)")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!(
            r"INSERT INTO targets
          (id, name, hostname, port, server_public_key, description,
           is_active, updated_by, updated_at)
          VALUES {rows}"
        );
        let mut q = sqlx::query(&query);

        for t in targets {
            q = q
                .bind(&t.id)
                .bind(&t.name)
                .bind(&t.hostname)
                .bind(t.port as i64)
                .bind(&t.server_public_key)
                .bind(&t.description)
                .bind(t.is_active)
                .bind(&t.updated_by)
                .bind(t.updated_at);
        }

        q.execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to create targets batch: {}", e)))?;

        Ok(targets.to_vec())
    }

    async fn list_target_secrets(&self, active_only: bool) -> Result<Vec<TargetSecret>, Error> {
        let mut query = String::from(
            r#"SELECT id, target_id, secret_id, is_active, updated_by, updated_at
           FROM target_secrets"#,
        );

        if active_only {
            query.push_str(" WHERE is_active = 1");
        }

        sqlx::query_as::<_, TargetSecret>(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list target_secrets: {}", e)))
    }

    async fn create_target_secret(
        &self,
        target_secret: &TargetSecret,
    ) -> Result<TargetSecret, Error> {
        sqlx::query(
            r#"
            INSERT INTO target_secrets
            (id, target_id, secret_id, is_active, updated_by, updated_at)  
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&target_secret.id)
        .bind(&target_secret.target_id)
        .bind(&target_secret.secret_id)
        .bind(target_secret.is_active)
        .bind(&target_secret.updated_by)
        .bind(target_secret.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create target_secret: {}", e)))?;

        Ok(target_secret.clone())
    }

    async fn update_target_secret(
        &self,
        target_secret: &TargetSecret,
    ) -> Result<TargetSecret, Error> {
        let mut updated = target_secret.clone();
        updated.updated_at = Utc::now().timestamp_millis();

        sqlx::query(
            r#"
        UPDATE target_secrets
        SET target_id  = ?,
            secret_id  = ?,
            is_active  = ?,
            updated_by = ?,
            updated_at = ?
        WHERE id = ?
        "#,
        )
        .bind(&updated.target_id)
        .bind(&updated.secret_id)
        .bind(updated.is_active)
        .bind(&updated.updated_by)
        .bind(updated.updated_at)
        .bind(&updated.id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to update target_secret: {}", e)))?;

        Ok(updated)
    }

    async fn delete_target_secret(&self, id: &str) -> Result<bool, Error> {
        let result = sqlx::query("DELETE FROM target_secrets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete target_secret: {}", e)))?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_internal_objects(&self, active_only: bool) -> Result<Vec<InternalObject>, Error> {
        let mut query = String::from(
            r#"SELECT name, is_active, updated_by, updated_at
           FROM internal_objects"#,
        );

        if active_only {
            query.push_str(" WHERE is_active = 1");
        }

        sqlx::query_as::<_, InternalObject>(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to list internal_objects: {}", e)))
    }

    async fn update_internal_object(&self, obj: &InternalObject) -> Result<InternalObject, Error> {
        let mut updated_obj = obj.clone();
        updated_obj.updated_at = Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            UPDATE internal_objects 
            SET is_active = ?, updated_by = ?, updated_at = ?
            WHERE name = ?
            "#,
        )
        .bind(obj.is_active)
        .bind(&obj.updated_by)
        .bind(obj.updated_at)
        .bind(&obj.name)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to update internal_objects: {}", e)))?;

        Ok(updated_obj)
    }

    async fn create_internal_object(&self, obj: &InternalObject) -> Result<InternalObject, Error> {
        sqlx::query(
            r#"
            INSERT INTO internal_objects
            (name, is_active, updated_by, updated_at)  
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&obj.name)
        .bind(obj.is_active)
        .bind(&obj.updated_by)
        .bind(obj.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create internal_objects: {}", e)))?;

        Ok(obj.clone())
    }

    async fn check_object_active(&self, id: &str) -> Result<bool, Error> {
        let row = sqlx::query_as::<_, TargetSecret>(
            r#"SELECT ts.* FROM target_secrets ts INNER JOIN targets t ON ts.target_id = t.id
               INNER JOIN secrets s ON ts.secret_id = s.id WHERE ts.is_active = 1
               AND t.is_active = 1 AND s.is_active = 1 AND ts.id = ?
            "#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to query target_secrets: {}", e)))?;

        if row.len() == 1 {
            return Ok(true);
        }

        let row = sqlx::query_as::<_, InternalObject>(
            "SELECT * FROM internal_objects WHERE is_active = 1 AND name = ?",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to query internal_objects: {}", e)))?;

        if row.len() == 1 {
            return Ok(true);
        }

        Ok(false)
    }

    async fn create_secrets_batch(&self, secrets: &[Secret]) -> Result<Vec<Secret>, Error> {
        if secrets.is_empty() {
            return Ok(vec![]);
        }

        let rows = (0..secrets.len())
            .map(|_| "(?,?,?,?,?,?,?,?,?)")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r"INSERT INTO secrets
              (id, name, user, password, private_key, public_key, is_active, updated_by, updated_at)
              VALUES {rows}"
        );
        let mut q = sqlx::query(&query);

        for s in secrets {
            q = q
                .bind(&s.id)
                .bind(&s.name)
                .bind(&s.user)
                .bind(&s.password)
                .bind(&s.private_key)
                .bind(&s.public_key)
                .bind(s.is_active)
                .bind(&s.updated_by)
                .bind(s.updated_at);
        }

        q.execute(&self.pool).await?;
        Ok(secrets.to_vec())
    }

    async fn create_target_secrets_batch(
        &self,
        secrets: &[TargetSecret],
    ) -> Result<Vec<TargetSecret>, Error> {
        if secrets.is_empty() {
            return Ok(vec![]);
        }

        let rows = (0..secrets.len())
            .map(|_| "(?,?,?,?,?,?)")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r#"INSERT INTO target_secrets
            (id, target_id, secret_id, is_active, updated_by, updated_at)
            VALUES  {rows}"#,
        );

        let mut q = sqlx::query(&query);

        for s in secrets {
            q = q
                .bind(&s.id)
                .bind(&s.target_id)
                .bind(&s.secret_id)
                .bind(s.is_active)
                .bind(&s.updated_by)
                .bind(s.updated_at);
        }

        q.execute(&self.pool).await.map_err(|e| {
            Error::Database(format!("Failed to create target secrets batch: {}", e))
        })?;

        Ok(secrets.to_vec())
    }

    async fn create_internal_objects_batch(
        &self,
        objs: &[InternalObject],
    ) -> Result<Vec<InternalObject>, Error> {
        if objs.is_empty() {
            return Ok(vec![]);
        }

        let rows = (0..objs.len())
            .map(|_| "(?,?,?,?)")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r"INSERT INTO internal_objects
              (name, is_active, updated_by, updated_at)
              VALUES {rows}"
        );
        let mut q = sqlx::query(&query);

        for s in objs {
            q = q
                .bind(&s.name)
                .bind(s.is_active)
                .bind(&s.updated_by)
                .bind(s.updated_at);
        }

        q.execute(&self.pool).await?;
        Ok(objs.to_vec())
    }

    async fn search_users(&self, query: &str) -> Result<Vec<User>, Error> {
        let search_pattern = format!("%{}%", query);
        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT id, username, email, password_hash, force_init_pass, is_active, updated_by, updated_at
            FROM users 
            WHERE username LIKE ? OR email LIKE ?
            ORDER BY username
            "#,
        )
        .bind(&search_pattern)
        .bind(&search_pattern)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to search users: {}", e)))?;

        Ok(users)
    }

    async fn search_targets(&self, query: &str) -> Result<Vec<Target>, Error> {
        let search_pattern = format!("%{}%", query);
        let targets = sqlx::query_as::<_, Target>(
            r#"
            SELECT id, name, hostname, port, server_public_key, description,
            is_active, updated_by, updated_at
            FROM targets 
            WHERE name LIKE ? OR hostname LIKE ? OR description LIKE ?
            ORDER BY name
            "#,
        )
        .bind(&search_pattern)
        .bind(&search_pattern)
        .bind(&search_pattern)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to search targets: {}", e)))?;

        Ok(targets)
    }

    async fn count_users(&self) -> Result<i64, Error> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to count users: {}", e)))?;

        Ok(row.get("count"))
    }

    async fn count_targets(&self) -> Result<i64, Error> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM targets")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to count targets: {}", e)))?;

        Ok(row.get("count"))
    }

    async fn count_active_users(&self) -> Result<i64, Error> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to count active users: {}", e)))?;

        Ok(row.get("count"))
    }

    async fn count_active_targets(&self) -> Result<i64, Error> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM targets WHERE is_active = 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to count active targets: {}", e)))?;

        Ok(row.get("count"))
    }

    // log operations
    async fn insert_log(&self, log: &Log) -> Result<(), Error> {
        sqlx::query(
            r#"
            INSERT INTO logs
            (connection_id, log_type, user_id, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&log.connection_id)
        .bind(&log.log_type)
        .bind(&log.user_id)
        .bind(&log.detail)
        .bind(log.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to create target: {}", e)))?;

        Ok(())
    }

    async fn list_logs(&self) -> Result<Vec<Log>, Error> {
        let logs = sqlx::query_as::<_, Log>(
            r#"SELECT connection_id, log_type, user_id, detail, created_at
            FROM logs ORDER BY created_at desc"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(format!("Failed to list logs: {}", e)))?;

        Ok(logs)
    }
}
