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
  - Deletes take what cannot outlive the row in one transaction: a target's or secret's bindings, and every `casbin_rule` naming the row or those bindings (`v0`–`v2` are polymorphic, so no foreign key can). `dependents(id)` counts the same set without deleting, for the confirm dialog; the delete returns what it took, which goes into the audit row. The role graphs skip rules left dangling by older versions.
  - Schema is created by `SchemaBuilder::sync()` (feature `schema-sync`), skipped when all tables already exist.
- **`server/bastion_server.rs`** — Implements `russh::server::Server`. Holds config, database service, connection/rate-limit caches (moka), and the Casbin role manager.
- **`server/bastion_handler.rs`** — Implements `russh::server::Handler`. Per-connection state machine routing I/O to the active `Application`.
- **`server/app/sftp/`** — SFTP proxy: per-operation actions (`SftpActions`), regex `sftp_path` rules in `ExtendPolicy`, lexical path resolution against the target's home, handle table, audit rows under `EventKind::Sftp`.
- **`server/app/admin/`** — TUI admin interface using ratatui + reedline. CRUD for users, targets, secrets, roles, permissions, and bindings.
- **`server/widgets/`** — Widgets shared by the admin panels and the replay player. `theme.rs` holds the colour themes; widgets take a `&Theme` at render time instead of keeping colours, and `TabBar`, `render_footer`, `popup_block` and the dialogs keep the panels looking the same. `t` cycles the theme in any panel; the admin shell carries the choice from one panel to the next. Help text is written `(key) what it does | (key) …` and drawn as key caps in aligned columns (size the footer with `footer_height`, which grows it on narrow terminals); message and confirm dialogs size themselves to their text and word-wrap it.
- **`i18n/`** — Interface languages: `en`, `zh-CN`, `zh-TW`, `ja`, `ru`, `fr`, `es`, `pt-BR`. One `Strings` constant per language, so a missing translation is a compile error; templates use `{name}` placeholders filled by `fill!`. Widgets take the session's `&Strings` at render time like the `Theme`; text a widget keeps (form labels, help) is a `Label`/`Help` fn of `&Strings`, so `L` (cycle the language in any panel) rewords it. Help keys stay as on the keyboard; only what they do is translated. The tests hold every language to the English placeholders and keys.
- **`server/event_log.rs`** — Audit events. `detail` stores an `Audit` as JSON, in no language, and `event_log::render` words it in the reader's language when the log is shown; rows from before are English text and shown as they are. The JSON tags and field names are the stored format: never rename them.
- **`asciinema/`** — Session recording in Asciinema v3 format.

### Key Traits

- **`DatabaseRepository`** (`database/mod.rs`) — Async trait for all DB operations, and the seam `HandlerBackend` hands to the rest of the app. Using a database sea-orm already supports means pointing the `database` URL at it, not a new impl.
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

`theme` picks the TUI theme sessions start with: `default`, `oled-black`,
`oled-white`, `nord` or `gruvbox` (omitted means `default`). `default` keeps the
terminal's own background and text colour; the others paint every cell.

`language` picks the interface language of a session whose client sends no
locale: `en` (the default), `zh-CN`, `zh-TW`, `ja`, `ru`, `fr`, `es` or `pt-BR`.
A client that sends `LC_ALL`, `LC_MESSAGES` or `LANG` (OpenSSH's `SendEnv`)
naming one of these gets it instead; other environment variables are refused.

`database` is a sea-orm connection URL, passed to sea-orm verbatim. The scheme
selects the driver, so it is the whole of the backend choice
(`database::SUPPORTED_SCHEMES` is validated at config load; everything past the
scheme is sea-orm's to parse):

```toml
database = "sqlite://rustion.db?mode=rwc"   # mode=rwc creates the file if missing
# database = "sqlite::memory:"
# database = "postgres://rustion:password@localhost:5432/rustion"
# database = "mysql://rustion:password@localhost:3306/rustion"
```

Reserved characters in a password must be percent-encoded (`@` → `%40`). The URL
is never logged raw — `database::redact_url()` masks the password for the startup
banner, the connect log, and config errors.

## Testing

Tests are inline (`#[cfg(test)]` modules) in:
- `config/mod.rs` — Config parsing/validation
- `server/casbin.rs` — Casbin policy matching
- `database/fixture.rs` — The shared test dataset, built in Rust from the types in
  `database/models/`. `fixture::seed()` gives a temp-file SQLite database with the
  whole set written to it, plus name → id lookups (`user()`, `target()`,
  `secret()`, `name()`, `binding()`, `policy()`). Replaces the former
  `mock_data.json`.
- `database/test.rs` — Every `DatabaseRepository` method, against the fixture
- `database/service.rs` — `DatabaseService` construction and `Clone` sharing
- `server/test.rs` — `HandlerBackend` integration tests against the fixture:
  `enforce` and `list_targets_for_user`, built on a real `BastionServer` opened on
  the fixture's SQLite file (`TestDb::url`).
- `server/bastion_handler.rs` — A real russh client against a real
  `BastionServer` over `tokio::io::duplex`: the connection keeps answering past
  russh's per-channel queue (`channel_buffer_size`), which a retained, unread
  `Channel` would fill.
- `server/app/sftp/test.rs` — The SFTP proxy end to end: a `RawSftpSession`
  client, the proxy, and an in-memory fake target joined by `tokio::io::duplex`,
  with policies enforced by a real `BastionServer` on the fixture. Pure helpers
  are tested inline in `sftp/{path,audit,handles,client}.rs`.
- `server/widgets/{mod,theme}.rs` — Themes, and the shared widgets rendered into a
  `Buffer`: outside `default`, no cell is left at the terminal's default colours.
- `i18n/mod.rs` — Locale parsing, and every language against English: the same
  placeholders, the same help keys.
- `server/event_log.rs` — The stored form of audit events, rendering in each
  language, and the 512-character bound.
- `server/extend_policy.rs` — Extended-policy parsing and matching, including
  the regex `sftp_path` rules.
- `server/app/change_password.rs` — Password change logic
