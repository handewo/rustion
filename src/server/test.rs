#[cfg(test)]
mod tests {
    use crate::database::common::OBJ_LOGIN;
    use crate::database::entity::{casbin_name, casbin_rule, secret, target, target_secret, user};
    use crate::database::models::{
        CasbinRule, Ptype, Secret, Target, TargetSecretName, User, casbin_rule::CasbinName,
        target_secret::TargetSecret,
    };
    use crate::database::{DatabaseConfig, common, service::DatabaseService};
    use crate::server::extend_policy::{
        ExtendPolicy, ExtendPolicyReq, HostPolicy, IpPolicy, PortPolicy, TimeWithOffset,
    };
    use crate::server::{self, HandlerBackend};
    use chrono::{Datelike, FixedOffset, NaiveDate, NaiveTime, TimeZone, Utc};
    use ipnetwork::IpNetwork;
    use sea_orm::ActiveValue::{Set, Unchanged};
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use std::{fs::File, io::Read};
    use tempfile::tempdir;
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct RawData {
        users: Vec<User>,
        targets: Vec<Target>,
        secrets: Vec<Secret>,
        target_secrets: Vec<TargetSecret>,
        casbin_names: Vec<CasbinName>,
        casbin_rule: Vec<CasbinRule>,
    }

    // Whole-row conversions for the fixtures below. `models::*::into_active_model`
    // is `pub(in crate::database)` — this module is outside it, which is the same
    // position the server code is in — so these spell the rows out. Every column is
    // `Set`, including `updated_at`, though the repository overwrites that one.

    fn user_active_model(mut u: User) -> user::ActiveModel {
        user::ActiveModel {
            id: Set(u.id),
            username: Set(u.username.clone()),
            email: Set(u.email.clone()),
            authorized_keys: Set(u.take_authorized_keys().map(|v| v.into())),
            force_init_pass: Set(u.force_init_pass),
            is_active: Set(u.is_active),
            updated_by: Set(u.updated_by),
            updated_at: Set(u.updated_at),
            ..Default::default()
        }
    }

    fn target_active_model(t: Target) -> target::ActiveModel {
        target::ActiveModel {
            id: Set(t.id),
            name: Set(t.name),
            hostname: Set(t.hostname),
            port: Set(t.port.into()),
            server_public_key: Set(t.server_public_key),
            description: Set(t.description),
            proxy: Set(t.proxy),
            is_active: Set(t.is_active),
            updated_by: Set(t.updated_by),
            updated_at: Set(t.updated_at),
        }
    }

    fn secret_active_model(mut s: Secret) -> secret::ActiveModel {
        secret::ActiveModel {
            id: Set(s.id),
            name: Set(s.name.clone()),
            user: Set(s.user.clone()),
            password: Set(s.take_password()),
            private_key: Set(s.take_private_key()),
            public_key: Set(s.take_public_key()),
            is_active: Set(s.is_active),
            updated_by: Set(s.updated_by),
            updated_at: Set(s.updated_at),
        }
    }

    fn target_secret_active_model(ts: TargetSecret) -> target_secret::ActiveModel {
        target_secret::ActiveModel {
            id: Set(ts.id),
            target_id: Set(ts.target_id),
            secret_id: Set(ts.secret_id),
            is_active: Set(ts.is_active),
            updated_by: Set(ts.updated_by),
            updated_at: Set(ts.updated_at),
        }
    }

    fn casbin_name_active_model(n: CasbinName) -> casbin_name::ActiveModel {
        casbin_name::ActiveModel {
            id: Set(n.id),
            ptype: Set(n.ptype),
            name: Set(n.name),
            is_active: Set(n.is_active),
            updated_by: Set(n.updated_by),
            updated_at: Set(n.updated_at),
        }
    }

    #[tokio::test]
    async fn test_bastion_server() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let _ = File::create(&db_path).unwrap();
        let mut config = crate::config::Config::default().gen_secret_token();
        let db = DatabaseConfig::Sqlite {
            path: db_path.to_string_lossy().into(),
        };
        config.database = db;
        let db = DatabaseService::new(&config.database).await.unwrap();
        let mut test_data = File::open("mock_data.json").unwrap();
        let mut buffer = String::new();
        test_data.read_to_string(&mut buffer).unwrap();
        let mut raw_data: RawData = serde_json::from_str(&buffer).unwrap();

        // Create users first (needed as updated_by reference)
        let first_user = raw_data.users.pop().unwrap();
        db.repository()
            .create_user(user_active_model(first_user))
            .await
            .unwrap();
        db.repository()
            .create_users_batch(raw_data.users)
            .await
            .unwrap();

        db.repository()
            .create_target(target_active_model(raw_data.targets.pop().unwrap()))
            .await
            .unwrap();
        db.repository()
            .create_targets_batch(raw_data.targets)
            .await
            .unwrap();

        db.repository()
            .create_secret(secret_active_model(raw_data.secrets.pop().unwrap()))
            .await
            .unwrap();
        db.repository()
            .create_secrets_batch(raw_data.secrets)
            .await
            .unwrap();

        db.repository()
            .create_target_secret(target_secret_active_model(
                raw_data.target_secrets.pop().unwrap(),
            ))
            .await
            .unwrap();
        db.repository()
            .create_target_secrets_batch(raw_data.target_secrets)
            .await
            .unwrap();

        // Create internal objects first

        for cn in raw_data.casbin_names {
            db.repository()
                .create_casbin_name(casbin_name_active_model(cn))
                .await
                .unwrap();
        }

        db.repository()
            .create_casbin_rules_batch(raw_data.casbin_rule)
            .await
            .unwrap();

        let rules = db.repository().list_casbin_rules().await.unwrap();
        let secrets = db.repository().list_secrets(false).await.unwrap();
        let targets = db.repository().list_targets(false).await.unwrap();
        let target_secrets = db.repository().list_target_secrets(false).await.unwrap();
        let server = server::BastionServer::with_config(config).await.unwrap();

        // Get UUIDs from global cache (initialized by BastionServer::with_config)
        let uuids = common::InternalUuids::get();
        let shell_uuid = uuids.act_shell;
        let exec_uuid = uuids.act_exec;
        let login_uuid = uuids.act_login;
        let obj_login = uuids.obj_login;

        let mut alice = server
            .get_user_by_username("alice", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alice.id.to_string(), "66ed2d9e-a51c-4765-966d-b77763232717");
        let bob = server
            .get_user_by_username("bob", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bob.id.to_string(), "a422db6f-c50e-48d3-bcfb-ddbf8989a974");
        let paul = server
            .get_user_by_username("paul", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paul.id.to_string(), "aa0c69dc-4e7f-49ea-a225-65d89011a3f5");
        let jack = server
            .get_user_by_username("jack", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(jack.id.to_string(), "9f9eee07-b7bb-448f-a5b6-fb1e7a8830a1");
        let admin = server
            .get_user_by_username("admin", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin.id.to_string(), "ef3f2c71-14ca-49b2-93af-917618f1b09f");

        let active_model = user::ActiveModel {
            id: Unchanged(alice.id),
            ..Default::default()
        };
        alice = server
            .update_user_password("12345678".into(), active_model)
            .await
            .unwrap();
        assert!(alice.verify_password("12345678"));

        let alice_lt = server.list_targets_for_user(&alice.id, true).await.unwrap();
        assert_eq!(
            alice_lt
                .iter()
                .filter(|v| v.target_name.starts_with("venus"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            27
        );

        assert_eq!(
            alice_lt
                .iter()
                .filter(|v| v.target_name.starts_with("mars"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            32
        );
        assert!(
            alice_lt
                .iter()
                .any(|v| v.id == Uuid::from_str("65f4527b-2fa1-4e19-8324-204b68c7f1c6").unwrap())
        );
        assert!(
            alice_lt
                .iter()
                .any(|v| v.id.to_string() == "ee267744-b110-469e-917d-8754d8aafa3c")
        );

        assert_eq!(alice_lt.len(), 85);

        let paul_lt = server.list_targets_for_user(&paul.id, true).await.unwrap();
        assert_eq!(paul_lt.len(), 1);

        let jack_lt = server.list_targets_for_user(&jack.id, true).await.unwrap();
        assert!(
            !jack_lt
                .iter()
                .any(|v| v.id.to_string() == "ee267744-b110-469e-917d-8754d8aafa3c")
        );
        assert_eq!(jack_lt.len(), 26);

        let bob_lt = server.list_targets_for_user(&bob.id, true).await.unwrap();
        assert_eq!(
            bob_lt
                .iter()
                .filter(|v| v.target_name.starts_with("venus"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            26
        );
        assert_eq!(
            bob_lt
                .iter()
                .filter(|v| v.target_name.starts_with("saturn"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            25
        );
        assert!(
            bob_lt
                .iter()
                .any(|v| v.id == Uuid::from_str("7f003584-21ed-4963-a7a1-892810f74e66").unwrap())
        );
        assert!(
            !bob_lt
                .iter()
                .any(|v| v.id.to_string() == "ee267744-b110-469e-917d-8754d8aafa3c")
        );

        assert_eq!(bob_lt.len(), 52);

        assert_eq!(
            alice_lt
                .iter()
                .filter(|v| v.target_name.starts_with("venus"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            27
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    bob.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("a0a30d81-d0b0-4736-82cf-1f63140cf1dc").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    bob.id,
                    Uuid::from_str("65f4527b-2fa1-4e19-8324-204b68c7f1c6").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    bob.id,
                    Uuid::from_str("65f4527b-2fa1-4e19-8324-204b68c7f1c6").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("65f4527b-2fa1-4e19-8324-204b68c7f1c6").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("a0a30d81-d0b0-4736-82cf-1f63140cf1dc").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    bob.id,
                    Uuid::from_str("a0a30d81-d0b0-4736-82cf-1f63140cf1dc").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("62b5d32d-4518-4d8f-8e7a-3fe858e67486").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    bob.id,
                    Uuid::from_str("62b5d32d-4518-4d8f-8e7a-3fe858e67486").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );

        let mut r = rules
            .iter()
            .find(|v| v.id.to_string() == "749bed7e-67a5-4749-9371-ec7df959438e")
            .unwrap()
            .clone();
        // Only the column under test is `Set`; the update returns the whole row,
        // so `r` stays current for the next case.
        r = db
            .repository()
            .update_casbin_rule(casbin_rule::ActiveModel {
                id: Unchanged(r.id),
                v2: Set(exec_uuid),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );

        // tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        assert!(
            server
                .enforce(bob.id, obj_login, login_uuid, ExtendPolicyReq::default(),)
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(alice.id, obj_login, login_uuid, ExtendPolicyReq::default(),)
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(admin.id, obj_login, login_uuid, ExtendPolicyReq::default(),)
                .await
                .unwrap()
        );
        let io = db
            .repository()
            .list_casbin_names(true)
            .await
            .unwrap()
            .iter()
            .rfind(|v| v.name == OBJ_LOGIN)
            .unwrap()
            .clone();
        db.repository()
            .update_casbin_name(casbin_name::ActiveModel {
                id: Unchanged(io.id),
                is_active: Set(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(alice.id, obj_login, login_uuid, ExtendPolicyReq::default(),)
                .await
                .unwrap()
        );

        let offset = FixedOffset::east_opt(3 * 3600).unwrap();
        let ep = ExtendPolicy {
            ip_policy: None,
            start_time: None,
            end_time: None,
            expire_date: Some(
                offset
                    .from_local_datetime(
                        &NaiveDate::from_ymd_opt(2000, 1, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap(),
                    )
                    .unwrap(),
            ),
            open_direct_tcpip_host: Some(HostPolicy::Deny("192.168.1.0/24".into())),
            open_direct_tcpip_port: Some(PortPolicy::Allow(vec![2222, 22])),
        };
        r = db
            .repository()
            .update_casbin_rule(casbin_rule::ActiveModel {
                id: Unchanged(r.id),
                v3: Set(serde_json::to_string(&ep).unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: NaiveDate::from_ymd_opt(1999, 12, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                            .and_utc(),
                        open_direct_tcpip: Some(("example.com".to_string(), 22)),
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: NaiveDate::from_ymd_opt(1999, 12, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                            .and_utc(),
                        open_direct_tcpip: Some(("192.168.1.1".to_string(), 22)),
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: NaiveDate::from_ymd_opt(1999, 12, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                            .and_utc(),
                        open_direct_tcpip: Some(("example.com".to_string(), 223)),
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: NaiveDate::from_ymd_opt(1999, 12, 31)
                            .unwrap()
                            .and_hms_opt(21, 0, 1)
                            .unwrap()
                            .and_utc(),
                        open_direct_tcpip: None,
                    },
                )
                .await
                .unwrap()
        );

        let ep = ExtendPolicy {
            ip_policy: None,
            start_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(8, 35, 0).unwrap(),
                offset,
            }),
            end_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(17, 35, 0).unwrap(),
                offset,
            }),
            expire_date: Some(Utc::now().with_timezone(&offset).with_year(3000).unwrap()),
            open_direct_tcpip_host: Some(HostPolicy::Allow("10.10.10.0/24".to_string())),
            open_direct_tcpip_port: None,
        };
        r = db
            .repository()
            .update_casbin_rule(casbin_rule::ActiveModel {
                id: Unchanged(r.id),
                v3: Set(serde_json::to_string(&ep).unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: Utc::now()
                            .with_time(NaiveTime::from_hms_opt(5, 34, 59).unwrap())
                            .unwrap(),
                        open_direct_tcpip: Some(("10.10.10.10".to_string(), 22)),
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: Utc::now()
                            .with_time(NaiveTime::from_hms_opt(14, 35, 0).unwrap())
                            .unwrap(),
                        open_direct_tcpip: Some(("10.10.10.10".to_string(), 22)),
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: Utc::now()
                            .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                            .unwrap(),
                        open_direct_tcpip: Some(("example.com".to_string(), 22)),
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: Utc::now()
                            .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                            .unwrap(),
                        open_direct_tcpip: Some(("10.20.10.10".to_string(), 22)),
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: Utc::now()
                            .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                            .unwrap(),
                        open_direct_tcpip: Some(("10.10.10.10".to_string(), 22)),
                    },
                )
                .await
                .unwrap()
        );

        let ep = ExtendPolicy {
            ip_policy: Some(IpPolicy::Deny(IpNetwork::from_str("10.0.0.0/8").unwrap())),
            start_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(8, 35, 0).unwrap(),
                offset,
            }),
            end_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(17, 35, 0).unwrap(),
                offset,
            }),
            expire_date: Some(Utc::now().with_timezone(&offset).with_year(3000).unwrap()),
            open_direct_tcpip_host: None,
            open_direct_tcpip_port: None,
        };
        db.repository()
            .update_casbin_rule(casbin_rule::ActiveModel {
                id: Unchanged(r.id),
                v3: Set(serde_json::to_string(&ep).unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: None,
                        now: Utc::now()
                            .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                            .unwrap(),
                        open_direct_tcpip: None,
                    },
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq {
                        ip: Some("192.168.1.1".parse().unwrap()),
                        now: Utc::now()
                            .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                            .unwrap(),
                        open_direct_tcpip: None,
                    },
                )
                .await
                .unwrap()
        );

        assert!(
            server
                .enforce(
                    bob.id,
                    Uuid::from_str("7f003584-21ed-4963-a7a1-892810f74e66").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        let ts = target_secrets
            .iter()
            .find(|v| v.id == Uuid::from_str("7f003584-21ed-4963-a7a1-892810f74e66").unwrap())
            .unwrap()
            .clone();
        db.repository()
            .update_target_secret(target_secret::ActiveModel {
                id: Unchanged(ts.id),
                is_active: Set(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    bob.id,
                    Uuid::from_str("7f003584-21ed-4963-a7a1-892810f74e66").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );

        assert!(
            server
                .enforce(
                    bob.id,
                    Uuid::from_str("bc957df2-9712-4f5d-8588-c546664e520a").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        let t = targets
            .iter()
            .find(|v| v.id.to_string() == "328ed0d0-8f40-4711-be0e-86a5cea44046")
            .unwrap()
            .clone();
        db.repository()
            .update_target(target::ActiveModel {
                id: Unchanged(t.id),
                is_active: Set(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    bob.id,
                    Uuid::from_str("bc957df2-9712-4f5d-8588-c546664e520a").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );

        db.repository()
            .delete_casbin_rule(Uuid::parse_str("f45acaa9-c0e4-4e6a-a95a-a35efc6e528f").unwrap())
            .await
            .unwrap();
        server.load_role_manager().await.unwrap();
        assert!(
            server
                .enforce(
                    alice.id,
                    Uuid::from_str("a0a30d81-d0b0-4736-82cf-1f63140cf1dc").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            !server
                .enforce(
                    alice.id,
                    Uuid::from_str("a0a30d81-d0b0-4736-82cf-1f63140cf1dc").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );

        assert!(
            server
                .enforce(
                    bob.id,
                    Uuid::from_str("84bfa21c-c1ed-4858-b19d-f520c3458c7f").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        let s = secrets
            .iter()
            .find(|v| v.id.to_string() == "986aed01-172c-4fcd-9686-bb812e86cf0e")
            .unwrap()
            .clone();
        db.repository()
            .update_secret(secret::ActiveModel {
                id: Unchanged(s.id),
                is_active: Set(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    bob.id,
                    Uuid::from_str("84bfa21c-c1ed-4858-b19d-f520c3458c7f").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );

        assert!(
            server
                .enforce(
                    bob.id,
                    Uuid::from_str("f0f2bc11-cb7e-4626-9dd0-712d94bdfba8").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        db.repository()
            .delete_casbin_rule(Uuid::parse_str("6e62e16d-052e-4992-be35-4d1482449d90").unwrap())
            .await
            .unwrap();
        server.load_role_manager().await.unwrap();
        assert!(
            !server
                .enforce(
                    bob.id,
                    Uuid::from_str("f0f2bc11-cb7e-4626-9dd0-712d94bdfba8").unwrap(),
                    exec_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_full_role() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let _ = File::create(&db_path).unwrap();
        let mut config = crate::config::Config::default().gen_secret_token();
        let db = DatabaseConfig::Sqlite {
            path: db_path.to_string_lossy().into(),
        };
        config.database = db;
        let db = DatabaseService::new(&config.database).await.unwrap();
        let mut test_data = File::open("mock_data.json").unwrap();
        let mut buffer = String::new();
        test_data.read_to_string(&mut buffer).unwrap();
        let mut raw_data: RawData = serde_json::from_str(&buffer).unwrap();

        // Create users first
        let first_user = raw_data.users.pop().unwrap();
        db.repository()
            .create_user(user_active_model(first_user))
            .await
            .unwrap();
        db.repository()
            .create_users_batch(raw_data.users)
            .await
            .unwrap();

        db.repository()
            .create_target(target_active_model(raw_data.targets.pop().unwrap()))
            .await
            .unwrap();
        db.repository()
            .create_targets_batch(raw_data.targets)
            .await
            .unwrap();

        db.repository()
            .create_secret(secret_active_model(raw_data.secrets.pop().unwrap()))
            .await
            .unwrap();
        db.repository()
            .create_secrets_batch(raw_data.secrets)
            .await
            .unwrap();

        db.repository()
            .create_target_secret(target_secret_active_model(
                raw_data.target_secrets.pop().unwrap(),
            ))
            .await
            .unwrap();
        db.repository()
            .create_target_secrets_batch(raw_data.target_secrets)
            .await
            .unwrap();

        for cn in raw_data.casbin_names {
            db.repository()
                .create_casbin_name(casbin_name_active_model(cn))
                .await
                .unwrap();
        }

        db.repository()
            .create_casbin_rules_batch(raw_data.casbin_rule)
            .await
            .unwrap();

        let server = server::BastionServer::with_config(config).await.unwrap();

        // Get UUIDs from global cache (initialized by BastionServer::with_config)
        let uuids = common::InternalUuids::get();
        let shell_uuid = uuids.act_shell;
        let login_uuid = uuids.act_login;
        let obj_login = uuids.obj_login;

        let jack = server
            .get_user_by_username("jack", true)
            .await
            .unwrap()
            .unwrap();
        let admin = server
            .get_user_by_username("admin", true)
            .await
            .unwrap()
            .unwrap();

        assert!(
            !server
                .enforce(
                    jack.id,
                    Uuid::from_str("980f07aa-866c-481f-92a0-727587576a05").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    admin.id,
                    // mars
                    Uuid::from_str("5846631d-62c2-4de8-83c0-b1f25667ca5c").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    admin.id,
                    // saturn
                    Uuid::from_str("3d5c1f2b-2e7c-4f29-b7bd-cb826966f2e0").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        assert!(
            server
                .enforce(
                    admin.id,
                    // venus
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        let admin_lt = server.list_targets_for_user(&admin.id, true).await.unwrap();
        assert_eq!(
            admin_lt
                .iter()
                .filter(|v| v.target_name.starts_with("venus"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            26
        );
        assert_eq!(
            admin_lt
                .iter()
                .filter(|v| v.target_name.starts_with("mars"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            31
        );
        assert_eq!(
            admin_lt
                .iter()
                .filter(|v| v.target_name.starts_with("saturn"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            25
        );
        let t = db
            .repository()
            .get_target_by_id(
                Uuid::parse_str("a3123268-b942-44b5-98cf-8df8ef6b26e7").unwrap(),
                true,
            )
            .await
            .unwrap()
            .unwrap();
        db.repository()
            .update_target(target::ActiveModel {
                id: Unchanged(t.id),
                is_active: Set(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !server
                .enforce(
                    admin.id,
                    // venus
                    Uuid::from_str("9888ece7-a675-41d9-97e3-81c6d4964b0c").unwrap(),
                    shell_uuid,
                    ExtendPolicyReq::default(),
                )
                .await
                .unwrap()
        );
        let admin_lt = server.list_targets_for_user(&admin.id, true).await.unwrap();
        assert_eq!(
            admin_lt
                .iter()
                .filter(|v| v.target_name.starts_with("venus"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            24
        );
        // Look up all_req action group UUID
        let all_req_uuid = db
            .repository()
            .get_casbin_name_by_name("all_req")
            .await
            .unwrap()
            .unwrap()
            .id;

        let r = casbin_rule::ActiveModel {
            id: Set(Uuid::now_v7()),
            ptype: Set(Ptype::Policy),
            v0: Set(admin.id),
            v1: Set(obj_login),
            v2: Set(all_req_uuid),
            v3: Set(String::from("{}")),
            v4: Set(String::new()),
            v5: Set(String::new()),
            updated_by: Set(admin.id),
            ..Default::default()
        };
        db.repository().create_casbin_rule(r).await.unwrap();
        server.load_role_manager().await.unwrap();
        assert!(
            server
                .enforce(admin.id, obj_login, login_uuid, ExtendPolicyReq::default(),)
                .await
                .unwrap()
        );
    }
}
