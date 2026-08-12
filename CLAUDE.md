# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
cargo build                          # Build the project
cargo run -- --init                  # Initialize database with admin user
cargo run                            # Start server (default: 127.0.0.1:2222)
cargo run -- -c path/to/config.toml  # Use custom config file
cargo run -- --generate-config       # Generate default rustion.toml
cargo test                           # Run all tests
cargo test <test_name>               # Run a single test by name
```

## Architecture Overview

**Rustion** is a Rust SSH bastion/jump host server with RBAC, session recording, and a TUI admin interface. It is **not** a web application — it uses the `russh` crate to implement SSH protocol directly.

### Core Flow

```
main.rs → cli.rs (clap) → Config (TOML) → BastionServer::with_config()
  → russh TCP listener → BastionHandler per connection
    → Auth (password/pubkey) → Application enum dispatch:
       - Admin TUI (ratatui)
       - Target selector (interactive)
       - Direct target connection
       - Password change (forced reset)
```

### Key Modules

- **`server/casbin.rs`** — Custom lightweight Casbin RBAC engine (~550 LOC) using `petgraph` for role hierarchy. Supports time-of-day, IP CIDR, and expiry constraints via `ExtendPolicy`. Rule types: `p` (policy), `g1` (user→role), `g2` (secret→group), `g3` (action→group).
- **`database/`** — sea-orm 2.0 on SQLite, PostgreSQL, and MySQL. Repository pattern with `DatabaseRepository` trait (50+ async methods), backed by a single backend-agnostic `SeaOrmRepository` (`repository.rs`) — sea-orm picks the driver from the connection URL, so there is no per-backend impl. Factory: `create_repository()`.
  - `entity/` — sea-orm entities (one module per table, struct must be named `Model`). Storage shape only.
  - `models/` — domain types with validation and behaviour, plus `From<entity::Model>`/`into_active_model()` conversions. Deliberately separate from entities: `DeriveEntityModel` requires the name `Model`, and the boundary is where backend quirks are absorbed (e.g. `port` is `i32` in storage because sea-orm cannot read `u16` on PostgreSQL, but `u16` on `Target`).
  - `query.rs` — joins, aggregation, and composed display labels. Built through the query builder for dialect portability; string concatenation and `GROUP_CONCAT` are done in Rust because they have no portable SQL spelling.
  - Schema is created by `SchemaBuilder::sync()` (feature `schema-sync`), skipped when all tables already exist.
- **`server/bastion_server.rs`** — Implements `russh::server::Server`. Holds config, database service, connection/rate-limit caches (moka), and the Casbin role manager.
- **`server/bastion_handler.rs`** — Implements `russh::server::Handler`. Per-connection state machine routing I/O to the active `Application`.
- **`server/app/admin/`** — TUI admin interface using ratatui + reedline. CRUD for users, targets, secrets, roles, permissions, and bindings.
- **`asciinema/`** — Session recording in Asciinema v3 format.

### Key Traits

- **`DatabaseRepository`** (`database/mod.rs`) — Async trait for all DB operations, and the seam `HandlerBackend` hands to the rest of the app. Adding a database sea-orm already supports means adding a `DatabaseConfig` variant with a connection URL, not a new impl.
- **`HandlerBackend`** (`server/mod.rs`) — Abstraction over server operations (auth, target connections, RBAC enforcement, encryption). Implemented by `BastionServer`.

### Error Handling

Nested enum pattern with `thiserror`. Top-level `Error` in `src/error.rs` wraps module-level errors: `ConfigError`, `DatabaseError`, `ServerError`, `AppError`, `AsciinemaError`. Each module has its own `error.rs`.

### Security

- Passwords: Argon2 hashing
- Stored secrets: AES-256-GCM encryption (key from `secret_key` in config)
- Rate limiting: moka caches for per-IP and per-user attempt tracking

### Dependencies with Custom Forks

Several dependencies use git forks (not crates.io): `russh`, `crossterm`, `reedline`, `inquire`, `ratatui`, `tui-textarea`, `tui-tree-widget`. Check `Cargo.toml` for exact sources.

## Configuration

Runtime config is in `rustion.toml` (TOML format). Key settings: listen address, server key path, auth rate limits, connection pooling, database config, session recording. See `src/config/mod.rs` for the `Config` struct.

The `[database]` table is tagged by `type`:

```toml
[database]
type = "sqlite"
path = "rustion.db"

# type = "postgres"        # port defaults to 5432
# host = "localhost"
# database = "rustion"
# username = "rustion"
# password = "..."

# type = "mysql"           # port defaults to 3306
```

## Testing

Tests are inline (`#[cfg(test)]` modules) in:
- `config/mod.rs` — Config parsing/validation
- `server/casbin.rs` — Casbin policy matching
- `server/test.rs` — Integration tests (uses `mock_data.json`)
- `database/service.rs` — Database service integration tests
- `server/app/change_password.rs` — Password change logic
