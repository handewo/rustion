use super::extend_policy;
use crate::config::Config;
use crate::database::common::*;
use crate::database::entity;
use crate::database::{models::*, service::DatabaseService};
use ::log::info;
use sea_orm::ActiveValue::{Set, Unchanged};
use uuid::Uuid;

pub async fn init_service(config: Config) {
    let db = match DatabaseService::new(&config.database).await {
        Ok(d) => d,
        Err(e) => {
            panic!("Failed to initialize database service: {}", e);
        }
    };

    // Check if tables are empty
    match db.repository().list_users(false).await {
        Ok(users) if !users.is_empty() => {
            panic!("Table: users is not empty");
        }
        Err(e) => {
            panic!("Failed to list users: {}", e);
        }
        _ => {}
    }
    match db.repository().list_casbin_rules().await {
        Ok(rules) if !rules.is_empty() => {
            panic!("Table: casbin_rule is not empty");
        }
        Err(e) => {
            panic!("Failed to list casbin_rules: {}", e);
        }
        _ => {}
    }
    match db.repository().list_secrets(false).await {
        Ok(secrets) if !secrets.is_empty() => {
            panic!("Table: secrets is not empty");
        }
        Err(e) => {
            panic!("Failed to list secrets: {}", e);
        }
        _ => {}
    }
    match db.repository().list_targets(false).await {
        Ok(targets) if !targets.is_empty() => {
            panic!("Table: targets is not empty");
        }
        Err(e) => {
            panic!("Failed to list targets: {}", e);
        }
        _ => {}
    }
    match db.repository().list_casbin_names(false).await {
        Ok(names) if !names.is_empty() => {
            panic!("Table: casbin_names is not empty");
        }
        Err(e) => {
            panic!("Failed to list casbin_names: {}", e);
        }
        _ => {}
    }
    match db.repository().list_target_secrets(false).await {
        Ok(ts) if !ts.is_empty() => {
            panic!("Table: target_secrets doesn't empty");
        }
        Err(e) => {
            panic!("Failed to list target_secrets: {}", e);
        }
        _ => {}
    }

    info!("All tables verified empty, proceeding with initialization");

    // init admin user
    let admin_id = Uuid::now_v7();
    let u = entity::user::ActiveModel {
        id: Set(admin_id),
        username: Set("admin".to_string()),
        updated_by: Set(admin_id),
        force_init_pass: Set(true),
        is_active: Set(true),
        ..Default::default()
    };
    let u = match db.repository().create_user(u).await {
        Ok(user) => {
            info!("Admin user created with id={}", user.id);
            user
        }
        Err(e) => {
            panic!("Failed to create admin user: {}", e);
        }
    };

    // Create UUIDs for the built-in actions and objects, and store them in
    // casbin_names. Four of the ids are referenced by the policies below.
    let action_login_id =
        insert_name(&db, NamePtype::InternalActionType, ACT_LOGIN, admin_id).await;
    let action_shell_id =
        insert_name(&db, NamePtype::InternalActionType, ACT_SHELL, admin_id).await;
    insert_name(&db, NamePtype::InternalActionType, ACT_EXEC, admin_id).await;
    insert_name(&db, NamePtype::InternalActionType, ACT_PTY, admin_id).await;
    insert_name(&db, NamePtype::InternalActionType, ACT_SFTP, admin_id).await;
    insert_name(
        &db,
        NamePtype::InternalActionType,
        ACT_DIRECT_TCPIP,
        admin_id,
    )
    .await;
    let obj_login_id = insert_name(&db, NamePtype::InternalObjectType, OBJ_LOGIN, admin_id).await;
    let obj_admin_id = insert_name(&db, NamePtype::InternalObjectType, OBJ_ADMIN, admin_id).await;
    insert_name(&db, NamePtype::InternalObjectType, OBJ_PLAYER, admin_id).await;
    let login_group_id = insert_name(&db, NamePtype::G1, "login_group", admin_id).await;

    info!("Creating default permission policies");

    // All five default rules are `p` policies differing only in subject, object,
    // action and the serialized extend policy, and all are attributed to admin.
    let policy = |v0: Uuid, v1: Uuid, v2: Uuid, ext: &extend_policy::ExtendPolicy| {
        entity::casbin_rule::ActiveModel {
            id: Set(Uuid::now_v7()),
            ptype: Set(Ptype::Policy),
            v0: Set(v0),
            v1: Set(v1),
            v2: Set(v2),
            v3: Set(serde_json::to_string(ext).unwrap()),
            v4: Set(String::new()),
            v5: Set(String::new()),
            updated_by: Set(admin_id),
            ..Default::default()
        }
    };

    let ipv4_localhost = "127.0.0.1/32"
        .parse()
        .unwrap_or_else(|e| panic!("Failed to parse IPv4 localhost: {}", e));
    let ext = extend_policy::ExtendPolicy {
        ip_policy: Some(extend_policy::IpPolicy::Allow(ipv4_localhost)),
        start_time: None,
        end_time: None,
        expire_date: None,
        open_direct_tcpip_host: None,
        open_direct_tcpip_port: None,
    };

    // Policy: admin can login from localhost (IPv4)
    let p = policy(u.id, obj_login_id, action_login_id, &ext);
    match db.repository().create_casbin_rule(p).await {
        Ok(_) => info!("Created policy: admin can login from localhost (IPv4)"),
        Err(e) => {
            panic!("Failed to create admin login policy (IPv4): {}", e);
        }
    }

    // Policy: admin can access admin panel from localhost (IPv4)
    let p = policy(u.id, obj_admin_id, action_shell_id, &ext);
    match db.repository().create_casbin_rule(p).await {
        Ok(_) => info!("Created policy: admin can access admin panel from localhost (IPv4)"),
        Err(e) => {
            panic!("Failed to create admin panel policy (IPv4): {}", e);
        }
    }

    // for ipv6
    let ipv6_localhost = "::1/128"
        .parse()
        .unwrap_or_else(|e| panic!("Failed to parse IPv6 localhost: {}", e));
    let ext = extend_policy::ExtendPolicy {
        ip_policy: Some(extend_policy::IpPolicy::Allow(ipv6_localhost)),
        start_time: None,
        end_time: None,
        expire_date: None,
        open_direct_tcpip_host: None,
        open_direct_tcpip_port: None,
    };

    // Policy: admin can login from localhost (IPv6)
    let p = policy(u.id, obj_login_id, action_login_id, &ext);
    match db.repository().create_casbin_rule(p).await {
        Ok(_) => info!("Created policy: admin can login from localhost (IPv6)"),
        Err(e) => {
            panic!("Failed to create admin login policy (IPv6): {}", e);
        }
    }

    // Policy: admin can access admin panel from localhost (IPv6)
    let p = policy(u.id, obj_admin_id, action_shell_id, &ext);
    match db.repository().create_casbin_rule(p).await {
        Ok(_) => info!("Created policy: admin can access admin panel from localhost (IPv6)"),
        Err(e) => {
            panic!("Failed to create admin panel policy (IPv6): {}", e);
        }
    }

    // Policy: login_group can login (no IP restriction)
    let ext = extend_policy::ExtendPolicy {
        ip_policy: None,
        start_time: None,
        end_time: None,
        expire_date: None,
        open_direct_tcpip_host: None,
        open_direct_tcpip_port: None,
    };
    let p = policy(login_group_id, obj_login_id, action_login_id, &ext);
    match db.repository().create_casbin_rule(p).await {
        Ok(_) => info!("Created policy: login_group can login (no IP restriction)"),
        Err(e) => {
            panic!("Failed to create login_group policy: {}", e);
        }
    }

    let server = match crate::server::BastionServer::with_config(config).await {
        Ok(s) => s,
        Err(e) => {
            panic!("Failed to create BastionServer: {}", e);
        }
    };

    let active_model = entity::user::ActiveModel {
        id: Unchanged(admin_id),
        ..Default::default()
    };
    let pass = match server.generate_random_password(active_model).await {
        Ok(p) => p,
        Err(e) => {
            panic!("Failed to generate random password: {}", e);
        }
    };

    info!("Rustion initialization completed successfully");
    eprintln!("Rustion has been initialized successfully.");
    eprintln!("A temporary password is generated for admin: {}", pass);
    eprintln!("By default admin only allowed login on localhost.");
}

/// Inserts one `casbin_names` row and returns its id.
///
/// One insert per name rather than `create_casbin_names_batch`: the batch writes
/// whole rows verbatim, `updated_at` included, which is what importing a fixture
/// wants. These rows are new, so they go through the single-row path that stamps
/// the timestamp. Nine inserts, once, at init.
async fn insert_name(db: &DatabaseService, ptype: NamePtype, name: &str, updated_by: Uuid) -> Uuid {
    let n = entity::casbin_name::ActiveModel {
        id: Set(Uuid::now_v7()),
        ptype: Set(ptype),
        name: Set(name.to_string()),
        is_active: Set(true),
        updated_by: Set(updated_by),
        ..Default::default()
    };
    match db.repository().create_casbin_name(n).await {
        Ok(n) => {
            info!("Created casbin_name: {}", n.name);
            n.id
        }
        Err(e) => {
            panic!("Failed to create casbin_name {}: {}", name, e);
        }
    }
}
