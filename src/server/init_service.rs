use super::casbin;
use crate::config::Config;
use crate::database::common::*;
use crate::database::{models::*, service::DatabaseService};
use uuid::Uuid;

pub async fn init_service(config: Config) {
    let db = DatabaseService::new(&config.database).await.unwrap();
    if !db.repository().list_users(false).await.unwrap().is_empty() {
        panic!("Table: users is not empty");
    }
    if !db
        .repository()
        .list_casbin_rules()
        .await
        .unwrap()
        .is_empty()
    {
        panic!("Table: casbin_rule is not empty");
    }
    if !db
        .repository()
        .list_secrets(false)
        .await
        .unwrap()
        .is_empty()
    {
        panic!("Table: secrets is not empty");
    }
    if !db
        .repository()
        .list_targets(false)
        .await
        .unwrap()
        .is_empty()
    {
        panic!("Table: targets is not empty");
    }
    if !db
        .repository()
        .list_casbin_names(false)
        .await
        .unwrap()
        .is_empty()
    {
        panic!("Table: casbin_names is not empty");
    }
    if !db
        .repository()
        .list_target_secrets(false)
        .await
        .unwrap()
        .is_empty()
    {
        panic!("Table: target_secrets doesn't empty");
    }

    // init admin user
    let admin_id = Uuid::new_v4();
    let mut u = User::new(admin_id);
    u.username = "admin".into();
    u.id = admin_id;
    let u = db.repository().create_user(&u).await.unwrap();

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

    let casbin_names_rows = db
        .repository()
        .create_casbin_names_batch(&[
            action_tcpip,
            action_pty,
            action_exec,
            action_shell,
            action_login,
            obj_login,
            obj_admin,
        ])
        .await
        .unwrap();

    // Get UUIDs for internal objects (OBJ_LOGIN, OBJ_ADMIN)
    let obj_login_id = casbin_names_rows
        .iter()
        .find(|o| o.name == OBJ_LOGIN)
        .unwrap()
        .id;
    let obj_admin_id = casbin_names_rows
        .iter()
        .find(|o| o.name == OBJ_ADMIN)
        .unwrap()
        .id;
    let action_login = casbin_names_rows
        .iter()
        .find(|o| o.name == ACT_LOGIN)
        .unwrap();

    // Create login_group UUID and store in casbin_names
    let login_group = CasbinName::new("g1".to_string(), "login_group".to_string(), true, u.id);
    db.repository()
        .create_casbin_name(&login_group)
        .await
        .unwrap();

    let ext = casbin::ExtendPolicy {
        ip_policy: Some(casbin::IpPolicy::Allow("127.0.0.1/32".parse().unwrap())),
        start_time: None,
        end_time: None,
        expire_date: None,
    };

    // Policy: admin can login from localhost (IPv4)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_login_id,
        Some(action_login.id),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

    // Policy: admin can access admin panel from localhost (IPv4)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_admin_id,
        Some(action_login.id),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

    // for ipv6
    let ext = casbin::ExtendPolicy {
        ip_policy: Some(casbin::IpPolicy::Allow("::1/128".parse().unwrap())),
        start_time: None,
        end_time: None,
        expire_date: None,
    };

    // Policy: admin can login from localhost (IPv6)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_login_id,
        Some(action_login.id),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

    // Policy: admin can access admin panel from localhost (IPv6)
    let p = CasbinRule::new(
        "p".to_string(),
        u.id,
        obj_admin_id,
        Some(action_login.id),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

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
        Some(action_login.id),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id,
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

    let server = crate::server::BastionServer::with_config(config)
        .await
        .unwrap();

    let pass = server.generate_random_password(u).await.unwrap();
    eprintln!("Rustion has been initialized successfully.");
    eprintln!("A temporary password is generated for admin: {}", pass);
    eprintln!("By default admin only allowed login on localhost.");
}
