//! Lexical path resolution for SFTP requests.
//!
//! Every path a client sends is resolved here before it is checked against a
//! policy, and the resolved path — not the client's string — is what the target
//! receives, so the target acts on exactly the path that was authorized.
//!
//! Lexical, not canonical: a symlink that already exists on the target can lead
//! outside an allowed pattern. Following links would cost a target round trip
//! per request and depend on the target's sftp-server.

/// Resolve `path` against `home`: join if relative, then drop `.` and empty
/// components and apply `..` (never above `/`). The empty path is `home`.
pub(super) fn resolve(home: &str, path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{home}/{path}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn relative_joins_home() {
        assert_eq!(resolve("/home/u", "a/b"), "/home/u/a/b");
        assert_eq!(resolve("/home/u", "."), "/home/u");
        assert_eq!(resolve("/home/u", ""), "/home/u");
    }

    #[test]
    fn absolute_ignores_home() {
        assert_eq!(resolve("/home/u", "/etc/passwd"), "/etc/passwd");
        assert_eq!(resolve("/home/u", "/"), "/");
    }

    #[test]
    fn dot_dot_and_slashes_collapse() {
        assert_eq!(resolve("/home/u", "../v/./x"), "/home/v/x");
        assert_eq!(resolve("/home/u", "//srv///a/"), "/srv/a");
        assert_eq!(resolve("/", "a/../../../etc"), "/etc");
    }

    /// The case path rules exist for: `..` must not climb out of an allowed
    /// prefix while still looking like it is inside it.
    #[test]
    fn dot_dot_cannot_hide_inside_an_allowed_prefix() {
        assert_eq!(resolve("/", "/srv/upload/../../etc/shadow"), "/etc/shadow");
    }
}
