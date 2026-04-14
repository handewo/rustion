use super::casbin;
use crate::config::Config;
use crate::database::common::*;
use crate::database::{models::*, service::DatabaseService};
use ::log::info;
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
    let admin_id = Uuid::new_v4();
    let mut u = User::new(admin_id);
    u.username = "admin".into();
    u.id = admin_id;
    let u = match db.repository().create_user(&u).await {
        Ok(user) => {
            info!("Admin user created with id={}", user.id);
            user
        }
        Err(e) => {
            panic!("Failed to create admin user: {}", e);
        }
    };

    // Create UUIDs for actions and store in casbin_names
    let action_login = CasbinName::new(
        INTERNAL_ACTION_TYPE.to_string(),
        ACT_LOGIN.to_string(),
        true,
        u.id,
    );
    let action_shell = CasbinName::new(
        INTERNAL_ACTION_TYPE.to_string(),
        ACT_SHELL.to_string(),
        true,
        u.id,
    );
    let action_exec = CasbinName::new(
        INTERNAL_ACTION_TYPE.to_string(),
        ACT_EXEC.to_string(),
        true,
        u.id,
    );
    let action_pty = CasbinName::new(
        INTERNAL_ACTION_TYPE.to_string(),
        ACT_PTY.to_string(),
        true,
        u.id,
    );
    let action_tcpip = CasbinName::new(
        INTERNAL_ACTION_TYPE.to_string(),
        ACT_DIRECT_TCPIP.to_string(),
        true,
        u.id,
    );
    let obj_login = CasbinName::new(
        INTERNAL_OBJECT_TYPE.to_string(),
        OBJ_LOGIN.to_string(),
        true,
        u.id,
    );
    let obj_admin = CasbinName::new(
        INTERNAL_OBJECT_TYPE.to_string(),
        OBJ_ADMIN.to_string(),
        true,
        u.id,
    );
    let obj_player = CasbinName::new(
        INTERNAL_OBJECT_TYPE.to_string(),
        OBJ_PLAYER.to_string(),
        true,
        u.id,
    );

    let casbin_names_rows = match db
        .repository()
        .create_casbin_names_batch(&[
            action_tcpip,
            action_pty,
            action_exec,
            action_shell,
            action_login,
            obj_login,
            obj_admin,
            obj_player,
        ])
        .await
    {
        Ok(rows) => {
            info!("Created {} casbin_names entries", rows.len());
            rows
        }
        Err(e) => {
            panic!("Failed to create casbin_names batch: {}", e);
        }
    };

    // Get UUIDs for internal objects (OBJ_LOGIN, OBJ_ADMIN)
    let obj_login_id = casbin_names_rows
        .iter()
        .find(|o| o.name == OBJ_LOGIN)
        .map(|o| o.id)
        .unwrap_or_else(|| panic!("Failed to find OBJ_LOGIN in casbin_names"));
    let obj_admin_id = casbin_names_rows
        .iter()
        .find(|o| o.name == OBJ_ADMIN)
        .map(|o| o.id)
        .unwrap_or_else(|| panic!("Failed to find OBJ_ADMIN in casbin_names"));
    let action_login = casbin_names_rows
        .iter()
        .find(|o| o.name == ACT_LOGIN)
        .unwrap_or_else(|| panic!("Failed to find ACT_LOGIN in casbin_names"));

    // Create login_group UUID and store in casbin_names
    let login_group = CasbinName::new("g1".to_string(), "login_group".to_string(), true, u.id);
    match db.repository().create_casbin_name(&login_group).await {
        Ok(_) => info!("Created login_group casbin_name"),
        Err(e) => {
            panic!("Failed to create login_group: {}", e);
        }
    }

    info!("Creating default permission policies");

    let ipv4_localhost = "127.0.0.1/32"
        .parse()
        .unwrap_or_else(|e| panic!("Failed to parse IPv4 localhost: {}", e));
    let ext = casbin::ExtendPolicy {
        ip_policy: Some(casbin::IpPolicy::Allow(ipv4_localhost)),
        start_time: None,
        end_time: None,
        expire_date: None,
    };

    // Policy: admin can login from localhost (IPv4)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_login_id,
        action_login.id,
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    match db.repository().create_casbin_rule(&p).await {
        Ok(_) => info!("Created policy: admin can login from localhost (IPv4)"),
        Err(e) => {
            panic!("Failed to create admin login policy (IPv4): {}", e);
        }
    }

    // Policy: admin can access admin panel from localhost (IPv4)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_admin_id,
        action_login.id,
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    match db.repository().create_casbin_rule(&p).await {
        Ok(_) => info!("Created policy: admin can access admin panel from localhost (IPv4)"),
        Err(e) => {
            panic!("Failed to create admin panel policy (IPv4): {}", e);
        }
    }

    // for ipv6
    let ipv6_localhost = "::1/128"
        .parse()
        .unwrap_or_else(|e| panic!("Failed to parse IPv6 localhost: {}", e));
    let ext = casbin::ExtendPolicy {
        ip_policy: Some(casbin::IpPolicy::Allow(ipv6_localhost)),
        start_time: None,
        end_time: None,
        expire_date: None,
    };

    // Policy: admin can login from localhost (IPv6)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_login_id,
        action_login.id,
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    match db.repository().create_casbin_rule(&p).await {
        Ok(_) => info!("Created policy: admin can login from localhost (IPv6)"),
        Err(e) => {
            panic!("Failed to create admin login policy (IPv6): {}", e);
        }
    }

    // Policy: admin can access admin panel from localhost (IPv6)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_admin_id,
        action_login.id,
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    match db.repository().create_casbin_rule(&p).await {
        Ok(_) => info!("Created policy: admin can access admin panel from localhost (IPv6)"),
        Err(e) => {
            panic!("Failed to create admin panel policy (IPv6): {}", e);
        }
    }

    // Policy: login_group can login (no IP restriction)
    let ext = casbin::ExtendPolicy {
        ip_policy: None,
        start_time: None,
        end_time: None,
        expire_date: None,
    };
    let p = CasbinRule::new(
        "p".to_string(),
        login_group.id,
        obj_login_id,
        action_login.id,
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    match db.repository().create_casbin_rule(&p).await {
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

    let pass = match server.generate_random_password(u).await {
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
