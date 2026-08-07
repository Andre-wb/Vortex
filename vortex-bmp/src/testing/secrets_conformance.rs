use std::sync::Arc;

use crate::ports::room_secrets::RoomSecrets;
use crate::secret::value::BmpSecret;

pub type SecretsFactory = dyn Fn() -> Arc<dyn RoomSecrets>;

pub fn secret(byte: &str) -> BmpSecret {
    BmpSecret::parse(&byte.repeat(32)).unwrap()
}

pub fn check_all(make: &SecretsFactory) {
    a_registered_secret_comes_back_for_its_room(make);
    an_unknown_room_has_no_secret(make);
    registering_again_replaces_the_previous_secret(make);
    a_removed_secret_is_gone(make);
    rooms_are_counted(make);
}

pub fn a_registered_secret_comes_back_for_its_room(make: &SecretsFactory) {
    let secrets = make();
    secrets.set(42, secret("ab"));
    assert_eq!(secrets.get(42), Some(secret("ab")));
}

pub fn an_unknown_room_has_no_secret(make: &SecretsFactory) {
    assert_eq!(make().get(4242), None);
}

pub fn registering_again_replaces_the_previous_secret(make: &SecretsFactory) {
    let secrets = make();
    secrets.set(1, secret("ab"));
    secrets.set(1, secret("cd"));
    assert_eq!(secrets.get(1), Some(secret("cd")));
    assert_eq!(secrets.len(), 1);
}

pub fn a_removed_secret_is_gone(make: &SecretsFactory) {
    let secrets = make();
    secrets.set(7, secret("ab"));
    secrets.remove(7);
    assert_eq!(secrets.get(7), None);
    assert!(secrets.is_empty());
}

pub fn rooms_are_counted(make: &SecretsFactory) {
    let secrets = make();
    secrets.set(1, secret("ab"));
    secrets.set(2, secret("cd"));
    assert_eq!(secrets.len(), 2);
}
