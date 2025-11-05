# Rustion

**Rustion** is a lightweight, Rust-based bastion server designed for secure and fine-grained SSH access control.

---

### 🚀 Quick Start

```bash
# Generate an SSH server key
$ ssh-keygen -t ed25519 -f server_key.pem -N ''

# Initialize Rustion
$ cargo run -- --init
Rustion has been initialized successfully.
A temporary password has been generated for admin: Px<WA32*asHp
By default, the admin can only log in from localhost.

# Start the server
$ cargo run
[2025-11-05T06:54:16Z INFO  rustion] Starting Rustion application
[2025-11-05T06:54:16Z INFO  rustion::database::service] Initializing database service
[2025-11-05T06:54:16Z INFO  rustion::database::sqlite] Connecting to SQLite database: rustion.db
[2025-11-05T06:54:16Z INFO  rustion::database::sqlite] Database tables and indexes created successfully
[2025-11-05T06:54:16Z INFO  rustion::server::bastion_server] Rustion server started on 127.0.0.1:2222
```

---

### ✨ Features

* Fine-grained authorization and access control at the SSH level
* Built-in TUI (terminal UI) admin management system *(in development)*
* Protection against brute-force login attempts
* Full Role-Based Access Control (RBAC) support

---

### 🎯 Roadmap / Goals

* Support for additional databases (MySQL, PostgreSQL)
* Integration with authentication systems such as SSO and LDAP
* Support for more target types (e.g., Kubernetes, MySQL, etc.)
* SFTP transfer capabilities between targets
* Integration with AI-driven features

---

### 🚫 Non-Goals

* Developing a web-based UI (not planned)

---

### ⚠️ Disclaimer

Rustion is under active development and should not yet be used in production environments. Use it at your own risk.

---

### 📄 License

This project is licensed under the **MIT License**.
See the [LICENSE](LICENSE) file for details.
