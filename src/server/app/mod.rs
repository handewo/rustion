pub(super) mod admin;
pub(super) mod change_password;
pub(super) mod connect_target;
pub(super) mod target_selector;

pub(super) use admin::Admin;
pub(super) use change_password::ChangePassword;
pub(super) use connect_target::ConnectTarget;
pub(super) use target_selector::TargetSelector;

pub enum Application {
    ConnectTarget(Box<ConnectTarget>),
    ChangePassword(Box<ChangePassword>),
    TargetSelector(Box<TargetSelector>),
    Admin(Box<Admin>),
    None,
}
