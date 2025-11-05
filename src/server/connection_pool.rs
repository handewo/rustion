use crate::database::models::Target;
use moka::future::Cache;
use russh::client as ru_client;
use std::sync::Arc;

pub(super) type ConnectionPool = Cache<String, Arc<ru_client::Handle<Target>>>;
