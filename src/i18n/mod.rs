//! Interface languages of the TUIs and prompts: the admin panels, the replay
//! player, the target selector and the password change.
//!
//! Every language is one [`Strings`] constant, so a missing translation is a
//! compile error rather than an English fallback at run time. Widgets take the
//! session's `&Strings` when they render, as they take its `Theme`.
//!
//! Text with values in it is a template with `{name}` placeholders, filled by
//! [`fill!`](crate::fill). Help text keeps the `(key) what it does | …` shape
//! the footer parses, and the keys themselves stay as they are on the keyboard;
//! only what they do is translated. The tests below hold every language to the
//! English placeholders and keys.
//!
//! The audit trail is stored language-neutral (`server::event_log::Audit`) and
//! worded here only when it is shown, in the viewer's language.

mod en;
mod es;
mod fr;
mod ja;
mod pt_br;
mod ru;
mod zh_hans;
mod zh_hant;

use serde::{Deserialize, Serialize};

/// A language of the interface. `language` in `rustion.toml` picks the one a
/// session starts in; a client that sends its locale (`LC_ALL`, `LC_MESSAGES`
/// or `LANG`, as OpenSSH does with `SendEnv`) gets its own instead, and `L`
/// cycles through them in the panels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Lang {
    #[default]
    En,
    ZhHans,
    ZhHant,
    Ja,
    Ru,
    Fr,
    Es,
    PtBr,
}

impl Lang {
    pub const ALL: [Lang; 8] = [
        Lang::En,
        Lang::ZhHans,
        Lang::ZhHant,
        Lang::Ja,
        Lang::Ru,
        Lang::Fr,
        Lang::Es,
        Lang::PtBr,
    ];

    /// The name as written in `rustion.toml`.
    pub const fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhHans => "zh-CN",
            Lang::ZhHant => "zh-TW",
            Lang::Ja => "ja",
            Lang::Ru => "ru",
            Lang::Fr => "fr",
            Lang::Es => "es",
            Lang::PtBr => "pt-BR",
        }
    }

    pub const fn strings(self) -> &'static Strings {
        match self {
            Lang::En => &en::EN,
            Lang::ZhHans => &zh_hans::ZH_HANS,
            Lang::ZhHant => &zh_hant::ZH_HANT,
            Lang::Ja => &ja::JA,
            Lang::Ru => &ru::RU,
            Lang::Fr => &fr::FR,
            Lang::Es => &es::ES,
            Lang::PtBr => &pt_br::PT_BR,
        }
    }

    /// The language after this one, wrapping around.
    pub fn next(self) -> Lang {
        let i = Self::ALL.iter().position(|l| *l == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    /// The language a locale name asks for: `ja_JP.UTF-8`, `zh-Hant`, `pt-BR`,
    /// `fr`. `None` for `C`, `POSIX` and languages there is no translation for.
    ///
    /// Chinese goes by script, then region: `zh_TW`, `zh_HK` and `zh_MO` are
    /// Traditional, the rest Simplified. Any Portuguese gets Brazilian.
    pub fn from_locale(locale: &str) -> Option<Lang> {
        let name = locale
            .split(['.', '@'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let mut parts = name.split(['_', '-']);
        let lang = match parts.next()? {
            "en" => Lang::En,
            "ja" => Lang::Ja,
            "ru" => Lang::Ru,
            "fr" => Lang::Fr,
            "es" => Lang::Es,
            "pt" => Lang::PtBr,
            "zh" => {
                let traditional = parts.any(|p| matches!(p, "hant" | "tw" | "hk" | "mo"));
                if traditional {
                    Lang::ZhHant
                } else {
                    Lang::ZhHans
                }
            }
            _ => return None,
        };
        Some(lang)
    }

    /// The language of a client's environment: the first of `LC_ALL`,
    /// `LC_MESSAGES` and `LANG` that names one, in the order the C library
    /// gives them precedence. A variable set to `C` or to an untranslated
    /// language is passed over rather than meaning English.
    pub fn from_env<'a>(var: impl Fn(&str) -> Option<&'a str>) -> Option<Lang> {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .filter_map(var)
            .find_map(Lang::from_locale)
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl TryFrom<String> for Lang {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Lang::from_locale(&s).ok_or_else(|| {
            let known: Vec<&str> = Lang::ALL.iter().map(|l| l.code()).collect();
            format!(
                "unknown language '{s}', expected one of: {}",
                known.join(", ")
            )
        })
    }
}

impl From<Lang> for String {
    fn from(lang: Lang) -> Self {
        lang.code().to_string()
    }
}

/// Fill a template's `{name}` placeholders. A placeholder with no value is
/// left as it is, so a slip shows up in the text rather than vanishing.
pub fn fill(template: &str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let key = &after[..close];
                match args.iter().find(|(k, _)| *k == key) {
                    Some((_, v)) => out.push_str(&v.to_string()),
                    None => {
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            None => {
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// `fill!(tr.user_added, name = u.username, id = u.id)`: [`fill`] with the
/// placeholders named as arguments.
#[macro_export]
macro_rules! fill {
    ($template:expr $(, $key:ident = $value:expr)* $(,)?) => {{
        // A statement of its own, so the borrowed values are dropped here: a
        // `&dyn Display` is not `Send`, and the result often crosses an await.
        let text = $crate::i18n::fill(
            $template,
            &[$((stringify!($key), &$value as &dyn ::std::fmt::Display)),*],
        );
        text
    }};
}

/// Declares [`Strings`], and `entries()` listing every field by name for the
/// tests.
macro_rules! strings {
    ($($(#[$doc:meta])* $name:ident,)*) => {
        /// Everything the interface says, in one language.
        #[derive(Debug)]
        pub struct Strings {
            $($(#[$doc])* pub $name: &'static str,)*
        }

        impl Strings {
            #[cfg(test)]
            fn entries(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($name), self.$name)),*]
            }
        }
    };
}

strings! {
    /// The language's own name for itself.
    lang_name,

    // Shared widgets.
    footer_theme,
    footer_language,
    /// `{count}`
    footer_more,
    dialog_info,
    dialog_warning,
    dialog_error,
    dialog_success,
    ok,
    yes,
    no,
    confirm_delete,
    confirm_cancel,
    cancel_sure,
    cancel_lost,
    /// A help notice and a field label suffix, so written `(…)`.
    read_only,
    no_records,
    empty_group,
    window_too_small,
    internal_error,
    unknown,

    // Form help.
    help_form_edit,
    help_form_nav,
    help_radio,
    help_radio_edit,
    help_checkbox,
    help_multiline,
    help_multiline_edit,
    help_multiline_edit_nav,
    help_multiline_input,
    help_multiline_input_nav,

    // Manage panel.
    help_manage,
    help_manage_user,
    help_manage_nav,
    tab_users,
    tab_targets,
    tab_secrets,
    tab_bind,
    tab_permissions,
    tab_groups,
    tab_role_hierarchy,
    tab_target_group,
    tab_action_group,
    title_add_user,
    title_add_target,
    title_add_secret,
    title_add_permission,
    title_add_group,
    title_edit_user,
    title_edit_target,
    title_edit_secret,
    title_edit_permission,
    title_edit_group,
    title_grant_role,
    delete_user_q,
    delete_target_q,
    delete_secret_q,
    delete_permission_q,
    delete_group_q,
    user_exists,
    target_exists,
    secret_exists,
    permission_exists,
    group_exists,
    /// `{password}`
    new_password,
    invalid_authorized_keys,
    /// `{lines}`
    line_numbers,

    // Table headers.
    col_username,
    col_email,
    col_password_hash,
    col_authorized_keys,
    col_force_init_pass,
    col_is_active,
    col_role,
    col_name,
    col_hostname,
    col_port,
    col_server_public_key,
    col_description,
    col_proxy,
    col_user,
    col_password,
    col_private_key,
    col_public_key,
    col_type,
    col_user_role,
    col_target_group,
    col_action_group,
    col_extend_policy,
    col_object,
    col_is_group,
    col_target_label,
    col_started_at,
    col_ended_at,
    col_status,
    status_active,
    status_completed,

    // What a group holds.
    kind_role,
    kind_user,
    kind_target,
    kind_action,
    kind_group,

    // Form fields. A `*` either side marks a required one.
    field_username,
    field_email,
    field_generate_password,
    field_force_init_password,
    field_is_active,
    field_authorized_keys,
    field_name,
    field_hostname,
    field_port,
    field_server_public_key,
    field_description,
    field_proxy,
    field_secret_user,
    field_password,
    field_private_key,
    field_type,
    field_user_role,
    field_target_group,
    field_action_group,
    field_extend_policy,

    // Field validation.
    v_username_empty,
    /// `{max}`
    v_username_too_long,
    v_email_invalid,
    /// `{lines}`
    v_authorized_keys,
    v_name_empty,
    /// `{max}`
    v_name_too_long,
    v_name_underscore,
    v_hostname_empty,
    /// `{max}`
    v_hostname_too_long,
    v_port_not_number,
    v_port_range,
    v_server_public_key,
    v_proxy,
    v_secret_user_empty,
    /// `{max}`
    v_secret_user_too_long,
    /// `{error}`
    v_ssh_key,
    v_ptype,
    v_user_role_empty,
    v_target_group_empty,
    v_action_group_empty,
    v_missing_rule_id,
    /// `{error}`
    v_extend_policy,
    /// `{target}`, `{user}`
    duplicate_target_user,

    // Bind, grant role, permission and group editors.
    help_bind,
    help_grant,
    help_grant_nav,
    help_pick,
    help_pick_nav,
    help_permission,
    help_group,
    help_group_nav,
    help_group_pick,
    select_one_group,
    /// `{group}`
    select_item_in_group,
    deleted,
    group_self,
    /// `{name}`
    group_cycle,
    /// `{kind}`, `{name}`, `{group}`
    member_added,
    /// `{kind}`, `{name}`, `{group}`
    member_exists,
    /// `{name}`, `{group}`
    delete_member_q,
    /// `{group}`
    title_add_to_group,

    // Database panel.
    /// Its second line is `help_manage_nav`.
    help_database,

    // Player.
    title_player,
    title_setting,
    help_player,
    help_player_nav,
    state_ended,
    state_paused,
    state_playing,
    help_ended,
    help_paused,
    help_playing,
    /// `{width}`, `{height}`
    window_size,
    field_speed,
    field_idle_time_limit,
    field_pause_on_markers,
    field_auto_exit,
    v_not_a_number,

    // Admin shell.
    /// `{error}`
    flush_failed,
    flushed,
    /// `{command}`
    unknown_command,
    command_not_found,

    // Target selector.
    select_target,
    select_target_user,
    /// `{name}`
    no_such_target,
    /// `{name}`
    no_such_target_user,

    // Password change.
    /// `{min}`
    pw_min_length,
    pw_digit,
    pw_uppercase,
    pw_lowercase,
    pw_special,
    pw_same,
    pw_prompt,
    pw_confirm,
    pw_help,
    pw_mismatch,
    pw_failed,
    pw_updated,

    // The audit trail, as shown in the log table.
    a_login_password,
    a_login_public_key,
    a_logout,
    a_admin,
    a_player,
    a_password_changed,
    /// `{request}`, `{target}`
    a_target_request,
    /// `{request}`, `{target}`
    a_target_request_closed,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_user_added,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_user_updated,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_user_deleted,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_target_added,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_target_updated,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_target_deleted,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_secret_added,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_secret_updated,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_secret_deleted,
    /// `{id}`
    a_permission_added,
    /// `{id}`
    a_permission_updated,
    /// `{id}`
    a_permission_deleted,
    // A permission has no name, so its dialog says nothing about which.
    permission_added,
    permission_updated,
    permission_deleted,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_group_added,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_group_updated,
    /// `{name}`: `name(id)` in the log, the name alone in a dialog.
    a_group_deleted,
    /// `{role}`, `{user}`
    a_role_granted,
    /// `{role}`, `{user}`
    a_role_revoked,
    /// `{secret}`, `{target}`
    a_secret_bound,
    /// `{secret}`, `{target}`
    a_secret_unbound,
    /// `{kind}`, `{member}`, `{group}`
    a_member_added,
    /// `{kind}`, `{member}`, `{group}`
    a_member_removed,
    /// `{target}`
    a_sftp_started,
    /// `{target}`
    a_sftp_refused,
    /// `{files_read}`, `{bytes_read}`, `{files_written}`, `{bytes_written}`, `{not_closed}`
    a_sftp_ended,
    /// `{op}`, `{paths}`
    a_sftp_denied,
    /// `{path}`, `{bytes}`
    a_sftp_read,
    /// `{path}`, `{bytes}`
    a_sftp_read_open,
    /// `{path}`, `{bytes}`
    a_sftp_wrote,
    /// `{path}`, `{bytes}`
    a_sftp_wrote_open,
    /// `{path}`, `{read}`, `{written}`
    a_sftp_read_wrote,
    /// `{path}`, `{read}`, `{written}`
    a_sftp_read_wrote_open,
    /// `{path}`, `{attrs}`
    a_sftp_setstat,
    /// `{path}`, `{attrs}`
    a_sftp_fsetstat,
    a_sftp_no_attrs,
    /// `{path}`
    a_sftp_mkdir,
    /// `{path}`
    a_sftp_remove,
    /// `{path}`
    a_sftp_rmdir,
    /// `{from}`, `{to}`
    a_sftp_rename,
    /// `{link}`, `{target}`
    a_sftp_symlink,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn placeholders(s: &str) -> BTreeSet<&str> {
        let mut out = BTreeSet::new();
        let mut rest = s;
        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else { break };
            out.insert(&after[..close]);
            rest = &after[close + 1..];
        }
        out
    }

    /// The `(key)` of every hint, in order.
    fn keys(help: &str) -> Vec<&str> {
        help.split(" | ")
            .filter_map(|h| h.trim().strip_prefix('(')?.split_once(')'))
            .map(|(k, _)| k)
            .collect()
    }

    #[test]
    fn every_language_fills_the_same_placeholders() {
        let en = Lang::En.strings().entries();
        for lang in Lang::ALL {
            for ((name, want), (_, got)) in en.iter().zip(lang.strings().entries()) {
                assert_eq!(
                    placeholders(want),
                    placeholders(got),
                    "{lang}: `{name}` = {got:?}"
                );
                assert!(!got.trim().is_empty(), "{lang}: `{name}` is empty");
            }
        }
    }

    /// Keys are what is on the keyboard; only what they do is translated. And
    /// the footer parses `(key) what | (key) what`, so the separators have to
    /// survive translation too. `read_only` is a notice, a `(…)` with nothing
    /// after it, so all of it is translated but the brackets.
    #[test]
    fn help_keeps_the_english_keys() {
        let en = Lang::En.strings().entries();
        for lang in Lang::ALL {
            for ((name, want), (_, got)) in en.iter().zip(lang.strings().entries()) {
                if name.starts_with("help_") {
                    assert_eq!(keys(want), keys(got), "{lang}: `{name}` = {got:?}");
                }
            }
            let notice = lang.strings().read_only;
            assert!(
                notice.starts_with('(') && notice.ends_with(')'),
                "{lang}: {notice}"
            );
        }
    }

    #[test]
    fn locales_name_their_language() {
        for (locale, want) in [
            ("en_US.UTF-8", Some(Lang::En)),
            ("ja_JP.UTF-8", Some(Lang::Ja)),
            ("ru_RU.KOI8-R", Some(Lang::Ru)),
            ("fr_CA", Some(Lang::Fr)),
            ("fr", Some(Lang::Fr)),
            ("es_MX.UTF-8", Some(Lang::Es)),
            ("pt_BR.UTF-8", Some(Lang::PtBr)),
            ("pt-PT", Some(Lang::PtBr)),
            ("zh_CN.UTF-8", Some(Lang::ZhHans)),
            ("zh_SG", Some(Lang::ZhHans)),
            ("zh-Hans", Some(Lang::ZhHans)),
            ("zh_TW.UTF-8", Some(Lang::ZhHant)),
            ("zh_HK.Big5", Some(Lang::ZhHant)),
            ("zh-Hant-CN", Some(Lang::ZhHant)),
            ("de_DE@euro", None),
            ("C", None),
            ("C.UTF-8", None),
            ("POSIX", None),
            ("", None),
        ] {
            assert_eq!(Lang::from_locale(locale), want, "{locale:?}");
        }
    }

    #[test]
    fn every_code_reads_back_as_its_language() {
        for lang in Lang::ALL {
            assert_eq!(Lang::from_locale(lang.code()), Some(lang));
            assert_eq!(Lang::try_from(lang.to_string()), Ok(lang));
        }
        assert!(Lang::try_from("klingon".to_string()).is_err());
    }

    #[test]
    fn the_environment_follows_c_precedence() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| *v)
        };
        assert_eq!(
            Lang::from_env(env(&[("LANG", "fr_FR.UTF-8"), ("LC_ALL", "ja_JP.UTF-8")])),
            Some(Lang::Ja)
        );
        assert_eq!(
            Lang::from_env(env(&[("LANG", "fr_FR.UTF-8"), ("LC_MESSAGES", "es_ES")])),
            Some(Lang::Es)
        );
        // `C` says nothing about a language, so the next one is asked.
        assert_eq!(
            Lang::from_env(env(&[("LC_ALL", "C.UTF-8"), ("LANG", "ru_RU.UTF-8")])),
            Some(Lang::Ru)
        );
        assert_eq!(Lang::from_env(env(&[("LANG", "C")])), None);
        assert_eq!(Lang::from_env(env(&[])), None);
    }

    #[test]
    fn next_visits_every_language_and_wraps() {
        let mut lang = Lang::En;
        let mut seen = Vec::new();
        for _ in Lang::ALL {
            seen.push(lang);
            lang = lang.next();
        }
        assert_eq!(seen, Lang::ALL);
        assert_eq!(lang, Lang::En);
    }

    #[test]
    fn fill_replaces_named_placeholders() {
        assert_eq!(fill!("{a} and {b}, {a}", a = 1, b = "two"), "1 and two, 1");
        assert_eq!(fill!("{missing} {", a = 1), "{missing} {");
        assert_eq!(fill!("no placeholders"), "no placeholders");
    }
}
