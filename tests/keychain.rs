#![cfg(all(target_os = "macos", feature = "tls"))]

use coqui_syshttp::tls::{IdentitySource, KeychainSource};

#[test]
fn the_users_keychains_list_without_failing_or_prompting() {
    // What they hold depends on the machine; listing must not fail or ask.
    let identities = KeychainSource::new().identities().unwrap();
    for identity in &identities {
        assert!(!identity.chain().is_empty());
    }
}
