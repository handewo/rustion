use super::casbin;
use super::common::*;
use crate::config::Config;
use crate::database::{models::*, service::DatabaseService};
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
        .list_internal_objects(false)
        .await
        .unwrap()
        .is_empty()
    {
        panic!("Table: internal_objects is not empty");
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
    let server = crate::server::BastionServer::with_config(config)
        .await
        .unwrap();

    // init admin user
    let admin_id = uuid::Uuid::new_v4().to_string();
    let mut u = User::new("admin".to_string(), admin_id.clone());
    u.id = admin_id;
    let u = db.repository().create_user(&u).await.unwrap();

    // init built-in policy
    let internal_objs = INTERNAL_OBJECTS
        .iter()
        .map(|o| InternalObject::new(o.to_string(), u.id.clone()))
        .collect::<Vec<_>>();
    db.repository()
        .create_internal_objects_batch(&internal_objs)
        .await
        .unwrap();
    let ext = casbin::ExtendPolicy {
        ip_policy: Some(casbin::IpPolicy::Allow("127.0.0.1/32".parse().unwrap())),
        start_time: None,
        end_time: None,
        expire_date: None,
    };
    let p = CasbinRule::new(
        "p".to_string(),
        u.id.clone(),
        OBJ_LOGIN.to_string(),
        Action::Login.to_string(),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id.clone(),
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

    let p = CasbinRule::new(
        "p".to_string(),
        u.id.clone(),
        OBJ_ADMIN.to_string(),
        Action::Login.to_string(),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id.clone(),
    );
    db.repository().create_casbin_rule(&p).await.unwrap();
    // for ipv6
    let ext = casbin::ExtendPolicy {
        ip_policy: Some(casbin::IpPolicy::Allow("::1/128".parse().unwrap())),
        start_time: None,
        end_time: None,
        expire_date: None,
    };
    let p = CasbinRule::new(
        "p".to_string(),
        u.id.clone(),
        OBJ_LOGIN.to_string(),
        Action::Login.to_string(),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id.clone(),
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

    let p = CasbinRule::new(
        "p".to_string(),
        u.id.clone(),
        OBJ_ADMIN.to_string(),
        Action::Login.to_string(),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id.clone(),
    );
    db.repository().create_casbin_rule(&p).await.unwrap();
    // add login_group
    let ext = casbin::ExtendPolicy {
        ip_policy: None,
        start_time: None,
        end_time: None,
        expire_date: None,
    };
    let p = CasbinRule::new(
        "p".to_string(),
        "login_group".to_string(),
        OBJ_LOGIN.to_string(),
        Action::Login.to_string(),
        ext.to_string(),
        String::new(),
        String::new(),
        u.id.clone(),
    );
    db.repository().create_casbin_rule(&p).await.unwrap();

    let pass = server.generate_random_password(u).await.unwrap();
    eprintln!("Rustion has been initialized successfully.");
    eprintln!("A temporary password is generated for admin: {}", pass);
    eprintln!("By default admin only allowed login on localhost.");
}
