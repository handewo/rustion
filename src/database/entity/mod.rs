//! sea-orm entity definitions.
//!
//! One module per table. These describe the *storage* shape and are kept
//! separate from the domain types in [`crate::database::models`], which keep
//! their own public API and behaviour. Conversions live alongside each model.
//!
//! `DeriveEntityModel` requires the struct be named `Model`, which is why these
//! can't be the domain types themselves. That separation is also where
//! backend-specific quirks get absorbed — most notably `port`, which is stored
//! as `i32` because sea-orm has no `u16` support on PostgreSQL.

pub(crate) mod casbin_name;
pub(crate) mod casbin_rule;
pub(crate) mod event_log;
pub(crate) mod secret;
pub(crate) mod session_recording;
pub(crate) mod target;
pub(crate) mod target_secret;
pub(crate) mod user;
