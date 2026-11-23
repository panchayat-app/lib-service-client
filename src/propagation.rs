use uuid::Uuid;

pub trait PropagationHandler {
    fn apply_principal_version(&self, principal_id: Uuid, authorization_version: i64);
}
