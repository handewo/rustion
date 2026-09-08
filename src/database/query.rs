//! Queries involving joins, aggregation, or composed display labels.
//!
//! These were raw SQLite SQL before. They're rebuilt here through sea-orm's
//! query builder so the emitted SQL is valid on SQLite, PostgreSQL and MySQL —
//! identifiers get quoted per dialect (`secrets.user` is a reserved word
//! outside SQLite), booleans bind as real booleans rather than `1`/`0`, and
//! placeholders match each driver.
//!
//! Two SQL constructs have no portable spelling and are therefore done in Rust
//! instead of in the database:
//!
//! * **String concatenation** — SQLite and PostgreSQL use `||`, MySQL needs
//!   `CONCAT()`. The component columns are selected and the display label is
//!   built with `format!`, which also keeps the label definition in one place.
//! * **`GROUP_CONCAT`** — PostgreSQL spells it `STRING_AGG` with different
//!   argument order. The rows are folded into a map instead.

use std::collections::HashMap;

use sea_orm::sea_query::{Condition, Expr, ExprTrait, IntoCondition, JoinType};
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbBackend, DeriveIden, EntityTrait, FromQueryResult,
    QueryFilter, QueryOrder, QuerySelect, RelationTrait,
};
use uuid::Uuid;

use crate::database::entity::casbin_name::NamePtype;
use crate::database::entity::casbin_rule::Ptype;
use crate::database::entity::{
    casbin_name, casbin_rule, secret, session_recording, target, target_secret, user,
};
use crate::database::models::{
    CasbinName, CasbinRule, CasbinRuleGroup, ObjectGroup, PermissionPolicy, RecordingStatus,
    RecordingView, Role, Secret, SecretInfo, Target, TargetSecretName, UserWithRole,
};
use crate::error::Error;

// ---------------------------------------------------------------- label parts

/// The pieces that make up a `user(name)@target:port` style label.
///
/// Selected as columns so the label can be composed in Rust rather than with a
/// backend-specific concat operator.
#[derive(Debug, FromQueryResult)]
struct TargetSecretParts {
    id: Uuid,
    secret_user: String,
    secret_name: String,
    target_name: String,
    port: i32,
}

impl TargetSecretParts {
    /// `user@target:port` — matches the former
    /// `s.user || '@' || t.name || ':' || t.port`.
    fn short_label(&self) -> String {
        format!("{}@{}:{}", self.secret_user, self.target_name, self.port)
    }

    /// `user(name)@target:port` — matches the former
    /// `s.user || '(' || s.name || ')' || '@' || t.name || ':' || t.port`.
    fn full_label(&self) -> String {
        format!(
            "{}({})@{}:{}",
            self.secret_user, self.secret_name, self.target_name, self.port
        )
    }
}

/// Every `target_secret` with the columns needed to build its label.
///
/// Ordered, not a map: this feeds the admin pickers, which render the rows
/// directly without sorting, so a `HashMap` would reshuffle the list on every
/// refresh. Sorted explicitly rather than relying on scan order, which differs
/// between backends. Use [`parts_by_id`] when a lookup is what's wanted.
async fn target_secret_parts(db: &DatabaseConnection) -> Result<Vec<TargetSecretParts>, Error> {
    Ok(target_secret::Entity::find()
        .select_only()
        .column_as(target_secret::Column::Id, "id")
        .column_as(secret::Column::User, "secret_user")
        .column_as(secret::Column::Name, "secret_name")
        .column_as(target::Column::Name, "target_name")
        .column_as(target::Column::Port, "port")
        .join(JoinType::LeftJoin, target_secret::Relation::Target.def())
        .join(JoinType::LeftJoin, target_secret::Relation::Secret.def())
        .order_by_asc(target::Column::Name)
        .order_by_asc(secret::Column::User)
        .into_model::<TargetSecretParts>()
        .all(db)
        .await?)
}

/// [`target_secret_parts`] keyed by `target_secret` id, for label lookups.
async fn parts_by_id(db: &DatabaseConnection) -> Result<HashMap<Uuid, TargetSecretParts>, Error> {
    Ok(target_secret_parts(db)
        .await?
        .into_iter()
        .map(|r| (r.id, r))
        .collect())
}

/// `casbin_names` keyed by id, for resolving group/action labels.
async fn casbin_name_map(
    db: &DatabaseConnection,
    ptype: Option<NamePtype>,
) -> Result<HashMap<Uuid, CasbinName>, Error> {
    let mut q = casbin_name::Entity::find();
    if let Some(ptype) = ptype {
        q = q.filter(casbin_name::Column::Ptype.eq(ptype));
    }
    Ok(q.all(db)
        .await?
        .into_iter()
        .map(|m| (m.id, CasbinName::from(m)))
        .collect())
}

// ----------------------------------------------------------------- users

/// Users with their roles as a comma-separated string.
///
/// TODO: Replace `Expr::cust` with sea_orm API in future
pub(super) async fn list_users_with_role(
    db: &DatabaseConnection,
    active_only: bool,
) -> Result<Vec<UserWithRole>, Error> {
    let group_concat = match db.get_database_backend() {
        DbBackend::MySql | DbBackend::Sqlite => "GROUP_CONCAT(casbin_name.name, ', ')",
        DbBackend::Postgres => "STRING_AGG(casbin_name.name, ', ' ORDER BY casbin_name.name)",
        _ => unreachable!(),
    };
    let mut q = user::Entity::find()
        .select_only()
        .column(user::Column::Id)
        .column(user::Column::Username)
        .column(user::Column::Email)
        .column(user::Column::PasswordHash)
        .column(user::Column::AuthorizedKeys)
        .column(user::Column::ForceInitPass)
        .column(user::Column::IsActive)
        .column(user::Column::UpdatedBy)
        .column(user::Column::UpdatedAt)
        .column_as(Expr::cust(group_concat), "role")
        .left_join(casbin_rule::Entity)
        .join(
            JoinType::LeftJoin,
            casbin_rule::Relation::RoleGroupV0
                .def()
                .on_condition(|left, _right| {
                    Expr::col((left, casbin_rule::Column::Ptype))
                        .eq(Ptype::G1)
                        .into_condition()
                }),
        )
        .group_by(user::Column::Id)
        .group_by(user::Column::Username)
        .group_by(user::Column::Email)
        .group_by(user::Column::PasswordHash)
        .group_by(user::Column::AuthorizedKeys)
        .group_by(user::Column::ForceInitPass)
        .group_by(user::Column::IsActive)
        .group_by(user::Column::UpdatedBy)
        .group_by(user::Column::UpdatedAt);

    if active_only {
        q = q.having(user::Column::IsActive.eq(true));
    }

    let res: Vec<user::UserWithRole> = q.into_model().all(db).await?;

    Ok(res
        .into_iter()
        .map(|v| UserWithRole {
            user: v.user.into(),
            role: v.role.unwrap_or_default(),
        })
        .collect())
}

// --------------------------------------------------------- target ⟷ secret

pub(super) async fn get_target_by_target_secret_id(
    db: &DatabaseConnection,
    id: Uuid,
    active_only: bool,
) -> Result<Option<Target>, Error> {
    let mut ts_cond = Condition::all().add(target_secret::Column::Id.eq(id));

    if active_only {
        ts_cond = ts_cond.add(target_secret::Column::IsActive.eq(true));
    }

    let mut q = target::Entity::find().has_related(target_secret::Entity, ts_cond);

    if active_only {
        q = q.filter(target::Column::IsActive.eq(true));
    }

    Ok(q.one(db).await?.map(Target::from))
}

pub(super) async fn get_targets_by_target_secret_ids(
    db: &DatabaseConnection,
    ids: Vec<Uuid>,
    active_only: bool,
) -> Result<Vec<Target>, Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut ts_cond = Condition::all().add(target_secret::Column::Id.is_in(ids));

    if active_only {
        ts_cond = ts_cond.add(target_secret::Column::IsActive.eq(true));
    }

    let mut q = target::Entity::find().has_related(target_secret::Entity, ts_cond);

    if active_only {
        q = q.filter(target::Column::IsActive.eq(true));
    }

    Ok(q.all(db).await?.into_iter().map(Target::from).collect())
}

pub(super) async fn get_secret_by_target_secret_id(
    db: &DatabaseConnection,
    id: Uuid,
    active_only: bool,
) -> Result<Option<Secret>, Error> {
    let mut ts_cond = Condition::all().add(target_secret::Column::Id.eq(id));

    if active_only {
        ts_cond = ts_cond.add(target_secret::Column::IsActive.eq(true));
    }

    let mut q = secret::Entity::find().has_related(target_secret::Entity, ts_cond);

    if active_only {
        q = q.filter(secret::Column::IsActive.eq(true));
    }

    Ok(q.one(db).await?.map(Secret::from))
}

/// All secrets, flagged with whether they're bound to `target_id`.
///
/// `is_bound` was `CASE WHEN ts.is_active IS NULL THEN 0 ELSE ts.is_active END`
/// over a `LEFT JOIN`: false when unbound, otherwise the binding's active flag.
pub(super) async fn list_secrets_for_target(
    db: &DatabaseConnection,
    target_id: Uuid,
) -> Result<Vec<SecretInfo>, Error> {
    Ok(secret::Entity::find()
        .select_only()
        .column(secret::Column::Id)
        .column(secret::Column::Name)
        .column(secret::Column::User)
        .column_as(
            Expr::col((target_secret::Entity, target_secret::Column::Id)).is_not_null(),
            "is_bound",
        )
        .join(
            JoinType::LeftJoin,
            target_secret::Relation::Secret
                .def()
                .rev()
                .on_condition(move |_left, right| {
                    Condition::all()
                        .add(Expr::col((right.clone(), target_secret::Column::IsActive)).eq(true))
                        .add(Expr::col((right, target_secret::Column::TargetId)).eq(target_id))
                }),
        )
        .order_by_asc(secret::Column::Name)
        .into_model()
        .all(db)
        .await?)
}

/// True when `id` is an active `target_secret` (with active target and secret)
/// or an active internal object.
pub(super) async fn check_object_active(db: &DatabaseConnection, id: Uuid) -> Result<bool, Error> {
    let ts_active = target_secret::Entity::find()
        .join(JoinType::InnerJoin, target_secret::Relation::Target.def())
        .join(JoinType::InnerJoin, target_secret::Relation::Secret.def())
        .filter(target_secret::Column::Id.eq(id))
        .filter(target_secret::Column::IsActive.eq(true))
        .filter(target::Column::IsActive.eq(true))
        .filter(secret::Column::IsActive.eq(true))
        .one(db)
        .await?
        .is_some();

    if ts_active {
        return Ok(true);
    }

    Ok(casbin_name::Entity::find()
        .filter(casbin_name::Column::Id.eq(id))
        .filter(casbin_name::Column::Ptype.eq(NamePtype::InternalObjectType))
        .filter(casbin_name::Column::IsActive.eq(true))
        .one(db)
        .await?
        .is_some())
}

// ------------------------------------------------------------------- roles

/// Every `g1` role, flagged with whether `user_id` is bound to it.
///
/// Was a `LEFT JOIN` of `casbin_names` (ptype `g1`) against the `g1` rules for
/// this user; `rule_id` is `None` and `is_bound` false when there's no binding.
pub(super) async fn list_roles_by_user_id(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<Role>, Error> {
    let q = casbin_name::Entity::find()
        .select_only()
        .column_as(casbin_name::Column::Id, "casbin_name_id")
        .column_as(casbin_rule::Column::Id, "casbin_rule_id")
        .column_as(casbin_name::Column::Name, "role")
        .join(
            JoinType::LeftJoin,
            casbin_rule::Relation::RoleGroupV0
                .def()
                .rev()
                .on_condition(move |_left, right| {
                    Condition::all()
                        .add(Expr::col((right.clone(), casbin_rule::Column::Ptype)).eq(Ptype::G1))
                        .add(Expr::col((right, casbin_rule::Column::V1)).eq(user_id))
                }),
        )
        .filter(casbin_name::Column::Ptype.eq(NamePtype::G1))
        .order_by_asc(casbin_name::Column::Name);

    Ok(q.into_model().all(db).await?)
}

/// Group-membership rules of one `ptype`, with human-readable labels on both
/// sides.
///
/// `casbin.rs` requires exactly one of the two labels per side to be `Some`
/// (`Label::from_v0`/`from_v1` error otherwise), which is why each arm sets one
/// and leaves the other `None`:
///
/// * `g1` — `v0` is always a group; `v1` is a user (object label) or a nested
///   group (group label).
/// * `g2` — `v0` is a `target_secret` (composed label) or an internal object;
///   `v1` is always a group.
/// * `g3` — `v0` is an internal action (object label) or a group; `v1` is a group.
pub(super) async fn list_casbin_rule_group_by_ptype(
    db: &DatabaseConnection,
    ptype: Ptype,
) -> Result<Vec<CasbinRuleGroup>, Error> {
    #[derive(DeriveIden, Clone, Copy)]
    pub enum Alias {
        V0,
        V1,
    }

    match ptype {
        Ptype::G1 => {
            let q =
                casbin_rule::Entity::find()
                    .select_only()
                    .column(casbin_rule::Column::Id)
                    .column(casbin_rule::Column::V0)
                    .column_as(Expr::null(), "v0_object_label")
                    .tbl_col_as((Alias::V0, casbin_name::Column::Name), "v0_group_label")
                    .column(casbin_rule::Column::V1)
                    .column_as(user::Column::Username, "v1_object_label")
                    .tbl_col_as((Alias::V1, casbin_name::Column::Name), "v1_group_label")
                    .join(JoinType::LeftJoin, casbin_rule::Relation::User.def())
                    .join_as(
                        JoinType::LeftJoin,
                        casbin_name::Relation::RoleGroupV0.def().rev().on_condition(
                            |_left, right| {
                                Expr::col((right, casbin_name::Column::Ptype))
                                    .eq(NamePtype::G1)
                                    .into_condition()
                            },
                        ),
                        Alias::V0,
                    )
                    .join_as(
                        JoinType::LeftJoin,
                        casbin_name::Relation::RoleGroupV1.def().rev().on_condition(
                            |_left, right| {
                                Expr::col((right, casbin_name::Column::Ptype))
                                    .eq(NamePtype::G1)
                                    .into_condition()
                            },
                        ),
                        Alias::V1,
                    )
                    .filter(casbin_rule::Column::Ptype.eq(Ptype::G1));

            Ok(q.into_model().all(db).await?)
        }
        Ptype::G2 => {
            // TODO: replace with one query
            let parts = parts_by_id(db).await?;
            let rules = casbin_rule::Entity::find()
                .filter(casbin_rule::Column::Ptype.eq(Ptype::G2))
                .all(db)
                .await?;
            let internal_object_names =
                casbin_name_map(db, Some(NamePtype::InternalObjectType)).await?;
            let target_group_names = casbin_name_map(db, Some(NamePtype::G2)).await?;

            Ok(rules
                .into_iter()
                .map(|r| {
                    // The original unioned target_secret labels with internal
                    // object names into a single id->name mapping.
                    let v0_object_label = parts
                        .get(&r.v0)
                        .map(|p| p.short_label())
                        .or_else(|| internal_object_names.get(&r.v0).map(|n| n.name.clone()));
                    CasbinRuleGroup {
                        id: r.id,
                        v0: r.v0,
                        v0_object_label,
                        v0_group_label: target_group_names.get(&r.v0).map(|n| n.name.clone()),
                        v1: r.v1,
                        v1_object_label: None,
                        v1_group_label: target_group_names.get(&r.v1).map(|n| n.name.clone()),
                    }
                })
                .collect())
        }
        Ptype::G3 => {
            let q =
                casbin_rule::Entity::find()
                    .select_only()
                    .column(casbin_rule::Column::Id)
                    .column(casbin_rule::Column::V0)
                    .column_as(casbin_name::Column::Name, "v0_object_label")
                    .tbl_col_as((Alias::V0, casbin_name::Column::Name), "v0_group_label")
                    .column(casbin_rule::Column::V1)
                    .column_as(Expr::null(), "v1_object_label")
                    .tbl_col_as((Alias::V1, casbin_name::Column::Name), "v1_group_label")
                    .join(
                        JoinType::LeftJoin,
                        casbin_name::Relation::RoleGroupV0.def().rev().on_condition(
                            |_left, right| {
                                Expr::col((right, casbin_name::Column::Ptype))
                                    .eq(NamePtype::InternalActionType)
                                    .into_condition()
                            },
                        ),
                    )
                    .join_as(
                        JoinType::LeftJoin,
                        casbin_name::Relation::RoleGroupV0.def().rev().on_condition(
                            |_left, right| {
                                Expr::col((right, casbin_name::Column::Ptype))
                                    .eq(NamePtype::G3)
                                    .into_condition()
                            },
                        ),
                        Alias::V0,
                    )
                    .join_as(
                        JoinType::LeftJoin,
                        casbin_name::Relation::RoleGroupV1.def().rev().on_condition(
                            |_left, right| {
                                Expr::col((right, casbin_name::Column::Ptype))
                                    .eq(NamePtype::G3)
                                    .into_condition()
                            },
                        ),
                        Alias::V1,
                    )
                    .filter(casbin_rule::Column::Ptype.eq(Ptype::G3));

            Ok(q.into_model().all(db).await?)
        }
        // Now exhaustive: `p` is the only other variant, and a permission policy
        // is not a group membership.
        Ptype::Policy => unreachable!("list_casbin_rule_group_by_ptype called with `p`"),
    }
}

pub(super) async fn list_targets_by_ids(
    db: &DatabaseConnection,
    ids: Vec<Uuid>,
    pid: Uuid,
    active_only: bool,
) -> Result<Vec<TargetSecretName>, Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let rows = target_secret_rows(db, &ids, active_only).await?;

    // Preserve the requested id order rather than the database's.
    Ok(ids
        .iter()
        .filter_map(|id| {
            rows.get(id).map(|r| TargetSecretName {
                pid,
                id: r.id,
                target_id: r.target_id,
                target_name: r.target_name.clone(),
                secret_id: r.secret_id,
                secret_user: r.secret_user.clone(),
            })
        })
        .collect())
}

#[derive(Debug, FromQueryResult)]
struct TargetSecretRow {
    id: Uuid,
    target_id: Uuid,
    target_name: String,
    secret_id: Uuid,
    secret_user: String,
}

/// Resolve `target_secret` ids to their target/secret details in one query.
async fn target_secret_rows(
    db: &DatabaseConnection,
    ids: &[Uuid],
    active_only: bool,
) -> Result<HashMap<Uuid, TargetSecretRow>, Error> {
    let mut q = target_secret::Entity::find()
        .select_only()
        .column_as(target_secret::Column::Id, "id")
        .column_as(target::Column::Id, "target_id")
        .column_as(target::Column::Name, "target_name")
        .column_as(secret::Column::Id, "secret_id")
        .column_as(secret::Column::User, "secret_user")
        .join(JoinType::InnerJoin, target_secret::Relation::Target.def())
        .join(JoinType::InnerJoin, target_secret::Relation::Secret.def())
        .filter(target_secret::Column::Id.is_in(ids.iter().copied()));

    if active_only {
        q = q
            .filter(target_secret::Column::IsActive.eq(true))
            .filter(target::Column::IsActive.eq(true))
            .filter(secret::Column::IsActive.eq(true));
    }

    Ok(q.into_model::<TargetSecretRow>()
        .all(db)
        .await?
        .into_iter()
        .map(|r| (r.id, r))
        .collect())
}

// ------------------------------------------------------------- group pickers
// Each was a `UNION ALL` of concrete objects and their groups, feeding the
// admin pickers. Built as two reads and concatenated, preserving row order.

/// Users, then `g1` groups.
///
/// Ordered within each section. The original queries had no `ORDER BY` and
/// relied on SQLite's scan order being stable in practice; PostgreSQL and MySQL
/// make no such promise (PostgreSQL in particular reorders rows after updates),
/// and these lists are rendered unsorted, so the order needs to be explicit to
/// stop the picker reshuffling between refreshes.
pub(super) async fn list_user_group(db: &DatabaseConnection) -> Result<Vec<ObjectGroup>, Error> {
    let mut out: Vec<ObjectGroup> = user::Entity::find()
        .order_by_asc(user::Column::Username)
        .all(db)
        .await?
        .into_iter()
        .map(|u| ObjectGroup {
            id: u.id,
            name: u.username,
            is_group: false,
        })
        .collect();

    out.extend(
        casbin_name::Entity::find()
            .filter(casbin_name::Column::Ptype.eq(NamePtype::G1))
            .order_by_asc(casbin_name::Column::Name)
            .all(db)
            .await?
            .into_iter()
            .map(|n| ObjectGroup {
                id: n.id,
                name: n.name,
                is_group: true,
            }),
    );

    Ok(out)
}

/// `target_secret`s (labelled `user(name)@target:port`), then `g2` groups and
/// internal objects. Internal objects report `is_group: false`, as before.
pub(super) async fn list_target_group(db: &DatabaseConnection) -> Result<Vec<ObjectGroup>, Error> {
    let mut out: Vec<ObjectGroup> = target_secret_parts(db)
        .await?
        .into_iter()
        .map(|p| ObjectGroup {
            id: p.id,
            name: p.full_label(),
            is_group: false,
        })
        .collect();

    out.extend(
        casbin_name::Entity::find()
            .filter(
                casbin_name::Column::Ptype
                    .eq(NamePtype::G2)
                    .or(casbin_name::Column::Ptype.eq(NamePtype::InternalObjectType)),
            )
            .order_by_asc(casbin_name::Column::Name)
            .all(db)
            .await?
            .into_iter()
            .map(|n| ObjectGroup {
                is_group: n.ptype == NamePtype::G2,
                id: n.id,
                name: n.name,
            }),
    );

    Ok(out)
}

/// `g3` groups and internal actions.
pub(super) async fn list_action_group(db: &DatabaseConnection) -> Result<Vec<ObjectGroup>, Error> {
    Ok(casbin_name::Entity::find()
        .filter(
            casbin_name::Column::Ptype
                .eq(NamePtype::G3)
                .or(casbin_name::Column::Ptype.eq(NamePtype::InternalActionType)),
        )
        .order_by_asc(casbin_name::Column::Name)
        .all(db)
        .await?
        .into_iter()
        .map(|n| ObjectGroup {
            is_group: n.ptype == NamePtype::G3,
            id: n.id,
            name: n.name,
        })
        .collect())
}

// ---------------------------------------------------------------- recordings

/// A user's recordings, labelled `user@target:port`.
pub(super) async fn list_recording_view_for_user(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<RecordingView>, Error> {
    #[derive(FromQueryResult)]
    struct Row {
        id: Uuid,
        started_at: i64,
        ended_at: Option<i64>,
        status: RecordingStatus,
        secret_user: Option<String>,
        target_name: Option<String>,
        port: Option<i32>,
    }

    // LEFT JOINs: a recording whose target or secret has since been deleted
    // still lists, with an empty label — same as the original.
    let rows = session_recording::Entity::find()
        .select_only()
        .column(session_recording::Column::Id)
        .column(session_recording::Column::StartedAt)
        .column(session_recording::Column::EndedAt)
        .column(session_recording::Column::Status)
        .column_as(secret::Column::User, "secret_user")
        .column_as(target::Column::Name, "target_name")
        .column_as(target::Column::Port, "port")
        .join(
            JoinType::LeftJoin,
            session_recording::Relation::Secret.def(),
        )
        .join(
            JoinType::LeftJoin,
            session_recording::Relation::Target.def(),
        )
        .filter(session_recording::Column::UserId.eq(user_id))
        .order_by_desc(session_recording::Column::StartedAt)
        .into_model::<Row>()
        .all(db)
        .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let target_secret = match (r.secret_user, r.target_name, r.port) {
                (Some(u), Some(n), Some(p)) => format!("{}@{}:{}", u, n, p),
                _ => String::new(),
            };
            RecordingView {
                id: r.id,
                target_secret,
                started_at: r.started_at,
                ended_at: r.ended_at,
                status: r.status,
            }
        })
        .collect())
}

// ------------------------------------------------------- permission policies

/// The `p` rules with all three columns resolved to display names.
///
/// The original resolved each column through a `UNION ALL` of every possible
/// name source. Those sources are read once into maps here and applied in Rust:
///
/// * `v0` (subject) — a `casbin_name` or a username
/// * `v1` (object) — a `target_secret` label or a `casbin_name`
/// * `v2` (action) — a `casbin_name`
pub(super) async fn list_permission_polices(
    db: &DatabaseConnection,
) -> Result<Vec<PermissionPolicy>, Error> {
    // TODO: Replace with one query
    let rules = casbin_rule::Entity::find()
        .filter(casbin_rule::Column::Ptype.eq(Ptype::Policy))
        .all(db)
        .await?;

    let names = casbin_name_map(db, None).await?;
    let parts = parts_by_id(db).await?;
    let usernames: HashMap<Uuid, String> = user::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|u| (u.id, u.username))
        .collect();

    Ok(rules
        .into_iter()
        .map(|r| {
            // `casbin_names` first, then `users` — the union's order.
            let user_role = names
                .get(&r.v0)
                .map(|n| n.name.clone())
                .or_else(|| usernames.get(&r.v0).cloned())
                .unwrap();

            // target_secret labels first, then `casbin_names`.
            let target_group = parts
                .get(&r.v1)
                .map(|p| p.full_label())
                .or_else(|| names.get(&r.v1).map(|n| n.name.clone()))
                .unwrap();

            let action_group = names.get(&r.v2).map(|n| n.name.clone()).unwrap();

            PermissionPolicy {
                rule: CasbinRule::from(r),
                user_role,
                target_group,
                action_group,
            }
        })
        .collect())
}
