#[cfg(test)]
mod tests {
    use crate::database::models::{
        target_secret::TargetSecret, Action, CasbinRule, InternalObject, Secret, Target,
        TargetSecretName, User,
    };
    use crate::database::{service::DatabaseService, DatabaseConfig};
    use crate::server::casbin::{ExtendPolicy, ExtendPolicyReq, IpPolicy};
    use crate::server::{self, common, HandlerBackend};
    use chrono::{Datelike, FixedOffset, NaiveDate, NaiveTime, TimeZone, Utc};
    use ipnetwork::IpNetwork;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use std::{fs::File, io::Read};
    use tempfile::tempdir;
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct RawData {
        users: Vec<User>,
        targets: Vec<Target>,
        secrets: Vec<Secret>,
        target_secrets: Vec<TargetSecret>,
        casbin_rule: Vec<CasbinRule>,
        internal_objects: Vec<InternalObject>,
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
        db.repository()
            .create_user(&raw_data.users.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_users_batch(&raw_data.users)
            .await
            .unwrap();

        db.repository()
            .create_target(&raw_data.targets.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_targets_batch(&raw_data.targets)
            .await
            .unwrap();

        db.repository()
            .create_casbin_rule(&raw_data.casbin_rule.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_casbin_rules_batch(&raw_data.casbin_rule)
            .await
            .unwrap();
        db.repository()
            .create_secret(&raw_data.secrets.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_secrets_batch(&raw_data.secrets)
            .await
            .unwrap();

        db.repository()
            .create_target_secret(&raw_data.target_secrets.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_target_secrets_batch(&raw_data.target_secrets)
            .await
            .unwrap();

        db.repository()
            .create_internal_object(&raw_data.internal_objects.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_internal_objects_batch(&raw_data.internal_objects)
            .await
            .unwrap();

        let rules = db.repository().list_casbin_rules().await.unwrap();
        let secrets = db.repository().list_secrets(false).await.unwrap();
        let targets = db.repository().list_targets(false).await.unwrap();
        let target_secrets = db.repository().list_target_secrets(false).await.unwrap();
        let server = server::BastionServer::with_config(config).await.unwrap();

        let mut alice = server
            .get_user_by_username("alice", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alice.id, "66ed2d9e-a51c-4765-966d-b77763232717");
        let bob = server
            .get_user_by_username("bob", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bob.id, "a422db6f-c50e-48d3-bcfb-ddbf8989a974");
        let paul = server
            .get_user_by_username("paul", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paul.id, "aa0c69dc-4e7f-49ea-a225-65d89011a3f5");
        let jack = server
            .get_user_by_username("jack", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(jack.id, "9f9eee07-b7bb-448f-a5b6-fb1e7a8830a1");
        let admin = server
            .get_user_by_username("admin", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin.id, "ef3f2c71-14ca-49b2-93af-917618f1b09f");

        alice = server
            .update_user_password("12345678".into(), alice)
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
        assert!(alice_lt
            .iter()
            .any(|v| v.id == "65f4527b-2fa1-4e19-8324-204b68c7f1c6"));
        assert!(alice_lt
            .iter()
            .any(|v| v.id == "ee267744-b110-469e-917d-8754d8aafa3c"));

        assert_eq!(alice_lt.len(), 85);

        let paul_lt = server.list_targets_for_user(&paul.id, true).await.unwrap();
        assert_eq!(paul_lt.len(), 1);

        let jack_lt = server.list_targets_for_user(&jack.id, true).await.unwrap();
        assert!(!jack_lt
            .iter()
            .any(|v| v.id == "ee267744-b110-469e-917d-8754d8aafa3c"));
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
        assert!(bob_lt
            .iter()
            .any(|v| v.id == "7f003584-21ed-4963-a7a1-892810f74e66"));
        assert!(!bob_lt
            .iter()
            .any(|v| v.id == "ee267744-b110-469e-917d-8754d8aafa3c"));

        assert_eq!(bob_lt.len(), 52);

        assert_eq!(
            alice_lt
                .iter()
                .filter(|v| v.target_name.starts_with("venus"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            27
        );
        assert!(server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &bob.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "a0a30d81-d0b0-4736-82cf-1f63140cf1dc",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &bob.id,
                "65f4527b-2fa1-4e19-8324-204b68c7f1c6",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(!server
            .enforce(
                &bob.id,
                "65f4527b-2fa1-4e19-8324-204b68c7f1c6",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "65f4527b-2fa1-4e19-8324-204b68c7f1c6",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "a0a30d81-d0b0-4736-82cf-1f63140cf1dc",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(!server
            .enforce(
                &bob.id,
                "a0a30d81-d0b0-4736-82cf-1f63140cf1dc",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "62b5d32d-4518-4d8f-8e7a-3fe858e67486",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &bob.id,
                "62b5d32d-4518-4d8f-8e7a-3fe858e67486",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());

        let mut r = rules
            .iter()
            .find(|v| v.id == "749bed7e-67a5-4749-9371-ec7df959438e")
            .unwrap()
            .clone();
        r.v2 = "exec".to_string();
        r = db.repository().update_casbin_rule(&r).await.unwrap();
        assert!(!server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());

        // tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        assert!(server
            .enforce(
                &bob.id,
                common::OBJ_LOGIN,
                Action::Login,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                common::OBJ_LOGIN,
                Action::Login,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(!server
            .enforce(
                &admin.id,
                common::OBJ_LOGIN,
                Action::Login,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        let mut io = db
            .repository()
            .list_internal_objects(true)
            .await
            .unwrap()
            .pop()
            .unwrap();
        io.is_active = false;
        db.repository().update_internal_object(&io).await.unwrap();
        assert!(!server
            .enforce(
                &alice.id,
                common::OBJ_LOGIN,
                Action::Login,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());

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
        };
        r.v3 = ep.to_string();
        r = db.repository().update_casbin_rule(&r).await.unwrap();
        assert!(!server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq {
                    ip: None,
                    now: NaiveDate::from_ymd_opt(1999, 12, 1)
                        .unwrap()
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc(),
                },
            )
            .await
            .unwrap());

        assert!(!server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq {
                    ip: None,
                    now: NaiveDate::from_ymd_opt(1999, 12, 31)
                        .unwrap()
                        .and_hms_opt(21, 0, 1)
                        .unwrap()
                        .and_utc(),
                },
            )
            .await
            .unwrap());

        let ep = ExtendPolicy {
            ip_policy: None,
            start_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(8, 35, 0).unwrap())
                    .unwrap(),
            ),
            end_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(17, 35, 0).unwrap())
                    .unwrap(),
            ),
            expire_date: Some(Utc::now().with_timezone(&offset).with_year(3000).unwrap()),
        };
        r.v3 = ep.to_string();
        r = db.repository().update_casbin_rule(&r).await.unwrap();
        assert!(!server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq {
                    ip: None,
                    now: Utc::now()
                        .with_time(NaiveTime::from_hms_opt(5, 34, 59).unwrap())
                        .unwrap()
                },
            )
            .await
            .unwrap());
        assert!(!server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq {
                    ip: None,
                    now: Utc::now()
                        .with_time(NaiveTime::from_hms_opt(14, 35, 0).unwrap())
                        .unwrap()
                },
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq {
                    ip: None,
                    now: Utc::now()
                        .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                        .unwrap()
                },
            )
            .await
            .unwrap());

        let ep = ExtendPolicy {
            ip_policy: Some(IpPolicy::Deny(IpNetwork::from_str("10.0.0.0/8").unwrap())),
            start_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(8, 35, 0).unwrap())
                    .unwrap(),
            ),
            end_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(17, 35, 0).unwrap())
                    .unwrap(),
            ),
            expire_date: Some(Utc::now().with_timezone(&offset).with_year(3000).unwrap()),
        };
        r.v3 = ep.to_string();
        db.repository().update_casbin_rule(&r).await.unwrap();
        assert!(!server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq {
                    ip: None,
                    now: Utc::now()
                        .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                        .unwrap()
                },
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &alice.id,
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Exec,
                ExtendPolicyReq {
                    ip: Some("192.168.1.1".parse().unwrap()),
                    now: Utc::now()
                        .with_time(NaiveTime::from_hms_opt(10, 0, 0).unwrap())
                        .unwrap()
                },
            )
            .await
            .unwrap());

        assert!(server
            .enforce(
                &bob.id,
                "7f003584-21ed-4963-a7a1-892810f74e66",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        let mut ts = target_secrets
            .iter()
            .find(|v| v.id == "7f003584-21ed-4963-a7a1-892810f74e66")
            .unwrap()
            .clone();
        ts.is_active = false;
        db.repository().update_target_secret(&ts).await.unwrap();
        assert!(!server
            .enforce(
                &bob.id,
                "7f003584-21ed-4963-a7a1-892810f74e66",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());

        assert!(server
            .enforce(
                &bob.id,
                "bc957df2-9712-4f5d-8588-c546664e520a",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        let mut t = targets
            .iter()
            .find(|v| v.id == "328ed0d0-8f40-4711-be0e-86a5cea44046")
            .unwrap()
            .clone();
        t.is_active = false;
        db.repository().update_target(&t).await.unwrap();
        assert!(!server
            .enforce(
                &bob.id,
                "bc957df2-9712-4f5d-8588-c546664e520a",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());

        db.repository()
            .delete_casbin_rule("f45acaa9-c0e4-4e6a-a95a-a35efc6e528f")
            .await
            .unwrap();
        #[cfg(feature = "full-role")]
        server.load_role_manager().await.unwrap();
        assert!(server
            .enforce(
                &alice.id,
                "a0a30d81-d0b0-4736-82cf-1f63140cf1dc",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(!server
            .enforce(
                &alice.id,
                "a0a30d81-d0b0-4736-82cf-1f63140cf1dc",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());

        assert!(server
            .enforce(
                &bob.id,
                "84bfa21c-c1ed-4858-b19d-f520c3458c7f",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        let mut s = secrets
            .iter()
            .find(|v| v.id == "986aed01-172c-4fcd-9686-bb812e86cf0e")
            .unwrap()
            .clone();
        s.is_active = false;
        db.repository().update_secret(&s).await.unwrap();
        assert!(!server
            .enforce(
                &bob.id,
                "84bfa21c-c1ed-4858-b19d-f520c3458c7f",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());

        assert!(server
            .enforce(
                &bob.id,
                "f0f2bc11-cb7e-4626-9dd0-712d94bdfba8",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        db.repository()
            .delete_casbin_rule("6e62e16d-052e-4992-be35-4d1482449d90")
            .await
            .unwrap();
        #[cfg(feature = "full-role")]
        server.load_role_manager().await.unwrap();
        assert!(!server
            .enforce(
                &bob.id,
                "f0f2bc11-cb7e-4626-9dd0-712d94bdfba8",
                Action::Exec,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        #[cfg(feature = "light-role")]
        assert!(!server
            .enforce(
                &jack.id,
                "980f07aa-866c-481f-92a0-727587576a05",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        #[cfg(feature = "light-role")]
        assert!(!server
            .enforce(
                &admin.id,
                // mars
                "5846631d-62c2-4de8-83c0-b1f25667ca5c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        #[cfg(feature = "light-role")]
        assert!(!server
            .enforce(
                &admin.id,
                // saturn
                "3d5c1f2b-2e7c-4f29-b7bd-cb826966f2e0",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        #[cfg(feature = "light-role")]
        assert!(!server
            .enforce(
                &admin.id,
                // venus
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    #[cfg(feature = "full-role")]
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
        db.repository()
            .create_user(&raw_data.users.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_users_batch(&raw_data.users)
            .await
            .unwrap();

        db.repository()
            .create_target(&raw_data.targets.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_targets_batch(&raw_data.targets)
            .await
            .unwrap();

        db.repository()
            .create_casbin_rule(&raw_data.casbin_rule.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_casbin_rules_batch(&raw_data.casbin_rule)
            .await
            .unwrap();
        db.repository()
            .create_secret(&raw_data.secrets.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_secrets_batch(&raw_data.secrets)
            .await
            .unwrap();

        db.repository()
            .create_target_secret(&raw_data.target_secrets.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_target_secrets_batch(&raw_data.target_secrets)
            .await
            .unwrap();

        db.repository()
            .create_internal_object(&raw_data.internal_objects.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_internal_objects_batch(&raw_data.internal_objects)
            .await
            .unwrap();

        let server = server::BastionServer::with_config(config).await.unwrap();

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

        assert!(!server
            .enforce(
                &jack.id,
                "980f07aa-866c-481f-92a0-727587576a05",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &admin.id,
                // mars
                "5846631d-62c2-4de8-83c0-b1f25667ca5c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &admin.id,
                // saturn
                "3d5c1f2b-2e7c-4f29-b7bd-cb826966f2e0",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        assert!(server
            .enforce(
                &admin.id,
                // venus
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
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
            .get_target_by_id("a3123268-b942-44b5-98cf-8df8ef6b26e7", true)
            .await
            .unwrap()
            .unwrap();
        let t = t.set_active(false);
        db.repository().update_target(&t).await.unwrap();
        assert!(!server
            .enforce(
                &admin.id,
                // venus
                "9888ece7-a675-41d9-97e3-81c6d4964b0c",
                Action::Shell,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
        let admin_lt = server.list_targets_for_user(&admin.id, true).await.unwrap();
        assert_eq!(
            admin_lt
                .iter()
                .filter(|v| v.target_name.starts_with("venus"))
                .collect::<Vec<&TargetSecretName>>()
                .len(),
            24
        );
        let r = CasbinRule::new(
            "p".to_string(),
            "ef3f2c71-14ca-49b2-93af-917618f1b09f".to_string(),
            common::OBJ_LOGIN.to_string(),
            "all_req".to_string(),
            String::new(),
            String::new(),
            String::new(),
            admin.id.clone(),
        );
        db.repository().create_casbin_rule(&r).await.unwrap();
        server.load_role_manager().await.unwrap();
        assert!(server
            .enforce(
                &admin.id,
                // venus
                common::OBJ_LOGIN,
                Action::Login,
                ExtendPolicyReq::default(),
            )
            .await
            .unwrap());
    }
}
