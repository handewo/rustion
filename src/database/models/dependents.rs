use serde::{Deserialize, Serialize};

/// What goes with a deleted row: the rows that name it and cannot outlive it.
///
/// Deleting a target or a secret takes its bindings, and every delete takes the
/// `casbin_rule` rows that name the row or those bindings. Counted before a
/// delete to warn the admin, and returned by it to report what went. Part of
/// the stored audit format (`Audit::Saved`): fields must not be renamed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependents {
    /// `target_secret` rows.
    #[serde(default)]
    pub bindings: u64,
    /// `g1`/`g2`/`g3` rules: a user in a role, a binding in a target group, an
    /// action in an action group, a group in another.
    #[serde(default)]
    pub memberships: u64,
    /// `p` rules.
    #[serde(default)]
    pub permissions: u64,
}

impl Dependents {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_default_is_empty() {
        assert!(Dependents::default().is_empty());
        for d in [
            Dependents {
                bindings: 1,
                ..Default::default()
            },
            Dependents {
                memberships: 1,
                ..Default::default()
            },
            Dependents {
                permissions: 1,
                ..Default::default()
            },
        ] {
            assert!(!d.is_empty(), "{d:?}");
        }
    }
}
