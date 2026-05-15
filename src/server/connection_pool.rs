use crate::database::models::Target;
use moka::future::Cache;
use russh::client as ru_client;
use std::sync::Arc;
use uuid::Uuid;

pub(super) type ConnectionPool = Cache<Uuid, Arc<ru_client::Handle<Target>>>;
