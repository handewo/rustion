# Rustion

**Rustion** is a lightweight, high-performance SSH bastion/jump host server with a TUI management interface, written in Rust 🦀.

## 🤔 What is a Bastion Server?

A bastion server (also known as a jump host) is a secure gateway that acts as the single entry point for accessing internal servers. Instead of connecting directly to target machines, users first connect to the bastion, which then forwards their connection to the intended destination. This architecture:

- 🔒 Centralizes access control and auditing
- 🎯 Reduces the attack surface of your infrastructure
- 📋 Provides a single point for monitoring and logging all SSH activity
- 🛡️ Enables fine-grained authorization policies

Rustion implements this concept with modern Rust technologies, offering security, performance, and flexibility.

⚠️ **Warning:** Rustion is under active development and should **not** be used in production environments without thorough testing. The API and DB structure may change.

---

## ✨ Features

### 🚀 Core Capabilities

- **Fine-grained Authorization** - Control exactly who can access which targets, when, and from where
- **SSH Protocol Implementation** - Built on `russh` crate for native SSH protocol support (no OpenSSH dependency)
- **Session Recording** - Record SSH sessions in Asciinema v3 format for auditing and replay
- **Brute-force Protection** - Rate limiting and slow rejection responses to deter attacks
- **Connection Pooling** - Reuse target connections for improved performance
- **SQLite, PostgreSQL and MySQL** - Pick the database with a connection URL; the schema is created on first start
- **Audit Trail** - Logins, admin changes, target requests and SFTP operations are recorded in `event_log`, and shown in the reader's language

### 👥 Role-Based Access Control (RBAC)

Rustion implements a custom lightweight Casbin-style RBAC engine using `petgraph` for role hierarchy management:

- **Policy Rules (p)** - Define who can do what to which objects
- **Role Inheritance (g1)** - User-to-role mappings with hierarchical support
- **Object Groups (g2)** - Organize targets into groups for easier management
- **Action Groups (g3)** - Group permissions (login, admin, etc.)


**Constraint Support:**
- Time-of-day restrictions (e.g., allow access only during business hours)
- IP CIDR restrictions (e.g., only from specific networks)
- Expiry dates for temporary access

### 🖥️ Admin TUI Interface

A full-featured terminal user interface for administration:

- User management (create, update, delete, password reset)
- Target server configuration
- Secret/credential management
- Role and permission assignment
- Policy binding management
- Session recording viewer
- Eight interface languages and five colour themes, switchable in any panel
- Deletes list what goes with the row (bindings, group memberships, permissions) before you confirm

![TUI](assets/vhs/manage.gif)

<details><summary>Screenshots</summary>

**Add User**
![Add User](assets/vhs/add_user.gif)

**Add Target**

![Add Target](assets/vhs/add_target.gif)

**Add Secret**

![Add Secret](assets/vhs/add_secret.gif)

**Add Group**

![Add Group](assets/vhs/add_group.gif)

**Add Permission**

![Add Permission](assets/vhs/add_permission.gif)

**Add Binding**

![Add Binding](assets/vhs/add_bind.gif)

**Role Hierarchy**
![Role Hierarchy](assets/vhs/role_hierarchy.gif)

</details>

### 🌐 Languages and Themes

The admin panels, the session player, the target selector and the password prompt are translated into English (`en`), Simplified Chinese (`zh-CN`), Traditional Chinese (`zh-TW`), Japanese (`ja`), Russian (`ru`), French (`fr`), Spanish (`es`) and Brazilian Portuguese (`pt-BR`).

A session picks its language from the client's locale, read from `LC_ALL`, then `LC_MESSAGES`, then `LANG`. OpenSSH sends these with `SendEnv`, which many distributions already enable for `LANG` and `LC_*`. To choose one explicitly:

```bash
ssh -o SetEnv=LANG=zh_CN.UTF-8 -p 2222 admin@admin@localhost
```

If the client sends no locale, or one without a translation, the `language` setting applies. Other environment variables are refused.

Themes are `default` (keeps the terminal's own colours), `oled-black`, `oled-white`, `nord` and `gruvbox`.

In any panel, `t` cycles the theme and `L` cycles the language; the admin shell keeps the choice from one panel to the next.

Audit rows are stored in no language and worded when they are shown, so each admin reads the log in their own language.

### 📁 SFTP

SFTP works on direct target connections:

```bash
sftp -P 2222 user@secretuser@target@localhost
```

**Actions** - `__internal_action_sftp` only opens the session. Every operation needs its own action:

| Action | Operations |
|---|---|
| `__internal_action_sftp` | Open the SFTP session, `realpath` |
| `__internal_action_sftp_list` | `opendir`/`readdir`, `stat`, `lstat`, `readlink` |
| `__internal_action_sftp_read` | Open a file for reading, read from it |
| `__internal_action_sftp_write` | Open a file with any write flag (write, append, create, truncate, exclusive), write to it |
| `__internal_action_sftp_mkdir` | `mkdir` |
| `__internal_action_sftp_setstat` | `setstat` (change attributes by path) |
| `__internal_action_sftp_fsetstat` | `fsetstat` (change attributes of an open file) |
| `__internal_action_sftp_symlink` | `symlink` (both the link and its target are checked) |
| `__internal_action_sftp_rename` | `rename` (both the source and the destination are checked) |
| `__internal_action_sftp_delete` | `remove`, `rmdir` |

- `setstat` and `fsetstat` change the same attributes, so grant both or neither. Changing a file's size also requires the write action.

**Path rules** - Add `sftp_path` to a policy's extended policy to restrict it to some paths:

```json
{"sftp_path":{"Allow":["/srv/upload(/.*)?"]}}
```

- Patterns are regexes matched against the whole resolved absolute path (relative paths resolve against the target user's home)
- To cover a directory and its contents, write `/dir(/.*)?`
- `Allow` passes if any pattern matches; `Deny` passes if none does
- `Allow: []` denies everything; `Deny: []` restricts nothing

A path rule only constrains requests that name a path. The session gate and `realpath` name none, so they are not blocked by it, and one policy can both open the session and narrow what happens inside it:

```text
ag_sftp_rw  {"sftp_path":{"Allow":["/srv/upload(/.*)?"]}}
```

By the same rule, a path rule says nothing about other kinds of request. On a policy whose action group also holds `shell` or `exec`, those are granted unconstrained — what a policy grants is its action list, and the extended policy only narrows the kind it names. Split the group if that is not what you want. The client address, the time window and the expiry are not per-kind: they are checked for every request.

**Audit** - `event_log` records session start and end (with file and byte totals), one row per file with the bytes read or written, every mutation (setstat, mkdir, remove, rename, symlink, ...), and every denial. Listings are not recorded.

**Known limitations:**
- Path checks are lexical. Existing symlinks on the target can lead outside a pattern.
- `realpath` reveals whether a path exists.
- Symlinks created through the bastion store an absolute target.
- SFTP extensions (`posix-rename`, `hardlink`, ...) are not supported.
- Requests are processed one at a time.

---

## 🔨 Build from source

### Clone & Run service

```bash
# Clone source code
git clone https://github.com/handewo/rustion.git
cd rustion

# Generate an SSH server key
ssh-keygen -t ed25519 -f server_key.pem -N ''

# Initialize Rustion (creates admin user with temporary password)
cargo run -- --init

# Start the server
cargo run
# [2025-11-05T06:54:16Z INFO  rustion] Starting Rustion application
# [2025-11-05T06:54:16Z INFO  rustion::server::bastion_server] Rustion server started on 127.0.0.1:2222
```

![Initialize Rustion](assets/vhs/init.gif)

### Configuration

`cargo run -- --generate-config` writes a default `rustion.toml`. The database, theme and language settings:

```toml
# sea-orm connection URL; the scheme picks the driver
database = "sqlite://rustion.db?mode=rwc"   # mode=rwc creates the file if missing
# database = "postgres://rustion:password@localhost:5432/rustion"
# database = "mysql://rustion:password@localhost:3306/rustion"

theme = "default"   # default, oled-black, oled-white, nord, gruvbox
language = "en"     # used when the client sends no locale
```

Percent-encode reserved characters in a database password (`@` becomes `%40`). The password is masked wherever the URL is logged.

### Connecting as Admin

```bash
# Connect to the bastion as admin
ssh -p 2222 admin@admin@localhost

# Enter the temporary password from --init
# Reset password when first login
```

![First Login](assets/vhs/first_login.gif)

### Change password

```bash

ssh -p 2222 user@password@localhost
? New Password:
[Please change your password]
```
### Connecting to a Target

```bash
# Interactive target selection
ssh -p 2222 user@localhost

# Direct target connection
ssh -p 2222 user@root@target@localhost
```

![Login to Server](assets/vhs/login_server.gif)

---

## 🗺️ Roadmap / Goals

- Integration with external authentication systems (SSO, LDAP, OIDC)
- Support for more target types:
  - Kubernetes pods
  - MySQL/PostgreSQL/Redis databases
  - Custom protocol targets
- Real-time session monitoring
- AI-assisted anomaly detection

---

## 🚫 Non-Goals

- Web-based administration UI (not planned)
- Acting as a general-purpose SSH server (bastion-focused only)
- Windows server support (Linux/Unix only)

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Open an issue to discuss significant changes
2. Follow the existing code style
3. Add tests for new functionality
4. Update documentation as needed
