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
- **In-memory policy enforcement** - Every check answers from a snapshot held in memory; the admin TUI reloads it after each change, and `policy_reload_interval` covers changes made outside the process
- **SSH Protocol Implementation** - Built on `russh` crate for native SSH protocol support (no OpenSSH dependency)
- **Session Recording** - Record SSH sessions in Asciinema v3 format for auditing and replay
- **Brute-force Protection** - Rate limiting and slow rejection responses to deter attacks
- **Connection Pooling** - Reuse target connections for improved performance
- **SQLite, PostgreSQL and MySQL** - Pick the database with a connection URL; the schema is created on first start
- **Limited Shell** - Let a user run only the commands an admin listed, with the arguments the admin allowed
- **Audit Trail** - Logins, admin changes, target requests, SFTP operations and limited-shell commands are recorded in `event_log`, and shown in the reader's language

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
- Command set editing for the limited shell (the `Commands` tab)
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

**Actions** - access is granted per operation: opening the session, listing, reading, writing, creating, renaming and deleting each need their own action, so a policy can let a user list and read while refusing every write.

**Path rules** - a policy's extended policy can narrow a grant to paths: `sftp_path` holds regex `Allow`/`Deny` lists matched against the whole resolved absolute path (`/dir(/.*)?` covers a directory and its contents). Checks are lexical — existing symlinks on the target can lead outside a pattern.

Every operation and every denial is recorded in `event_log`.

### 🔒 Limited Shell

A user who should run only some commands on a target gets a **command set** instead of `shell` or `exec`:

```bash
ssh -p 2222 user@cmd@localhost
> help                      # the targets you hold a command set on
> web1                      # or root@web1 when web1 has more than one user
root@web1> help             # the commands you may run here
root@web1> systemctl status nginx
root@web1> cd /var/log
root@web1> exit
>
```

The prompt runs on the bastion: a line is checked against the user's command sets before anything is sent, and an allowed line runs as one `exec` on the target, holding exactly the string that was checked. No shell on the target reads what the user types, so `;`, `|`, `$(...)`, globs and aliases are only text — `df ; sh` is refused, not run.

- **Command sets** are JSON, edited in the `Commands` tab of `manage`: each command is an alias, the program it runs and the argument shapes it accepts (`help ALIAS` prints one usage line per shape). Unknown fields are refused; a config is saved only when it loads.
- A set is granted like an action — as a permission's action or in an action group — and the permission's extended policy (IP, time window, expiry) applies to it.
- Built-ins: `help`, `cd` (an allowlist of directories, checked against the path the target resolves it to), `pwd`, `exit`. The prompt shows the last command's exit code.
- `pty` and `stdin` run interactive tools (`htop`); `command_timeout` in `rustion.toml` bounds how long one command may run.
- Every command run and every line refused is audited; with `enable_record`, each target visit is a session recording.

A set checks the line, not what a program does with its arguments: commands that can start a shell from their arguments (`find -exec`, `awk`, editors' shell-escape keys) need tight templates, and `exec` paths should be absolute.

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
# policy_reload_interval = "1m"  # re-read casbin_rule on a timer ("0s", off, default)
# command_timeout = "10m"        # bound one limited-shell command ("0s", off, default)
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
