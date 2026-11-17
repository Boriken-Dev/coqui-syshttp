//! A Windows certificate store for a test: a PKCS #12 file imported in memory, whose keys are
//! deleted again when the store is dropped.

#![allow(
    unsafe_code,
    reason = "the CNG calls that delete a key have no safe binding"
)]

use std::sync::Arc;

use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, PrivateKey,
    PrivateKeyChain,
};
use rustls_cng::store::{CertStore, Pkcs12Flags};
use windows_sys::Win32::Security::Cryptography::{
    CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO, CertGetCertificateContextProperty,
    NCryptDeleteKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
};

use super::pki::Leaf;

/// A PKCS #12 file of `leaf` and its chain, in the legacy scheme every Windows release imports.
pub fn pkcs12(leaf: &Leaf, password: &str) -> Vec<u8> {
    let key = PrivateKey::from_der(&leaf.key_pkcs8).unwrap();
    let certificates = leaf
        .chain
        .iter()
        .map(|der| Certificate::from_der(der.as_ref()).unwrap());
    let mut store = KeyStore::new();
    store.add_entry(
        "client",
        KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(vec![1, 2, 3, 4], key, certificates)),
    );
    store
        .writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc)
        .mac_algorithm(MacAlgorithm::HmacSha1)
        .write()
        .unwrap()
}

/// A store holding `leaf`, in memory. The import creates a key in the current user's key
/// storage; the [`KeyGuard`] made from the same store deletes it.
pub fn import(leaf: &Leaf) -> Arc<CertStore> {
    Arc::new(
        CertStore::from_pkcs12(
            &pkcs12(leaf, "test-password"),
            "test-password",
            Pkcs12Flags::PREFER_CNG_KSP | Pkcs12Flags::INCLUDE_EXTENDED_PROPERTIES,
        )
        .expect("the store imports"),
    )
}

/// Deletes the key behind every certificate of the store when dropped, so a failing test leaves
/// nothing behind in the user's key storage.
pub struct KeyGuard(pub Arc<CertStore>);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        delete_keys(&self.0);
    }
}

fn delete_keys(store: &CertStore) {
    for context in store.find_all().unwrap_or_default() {
        // SAFETY: the property is read into a buffer of the size the call reports.
        unsafe {
            let mut size = 0u32;
            if CertGetCertificateContextProperty(
                context.inner(),
                CERT_KEY_PROV_INFO_PROP_ID,
                std::ptr::null_mut(),
                &mut size,
            ) == 0
            {
                continue;
            }
            let mut buffer = vec![0u8; size as usize];
            if CertGetCertificateContextProperty(
                context.inner(),
                CERT_KEY_PROV_INFO_PROP_ID,
                buffer.as_mut_ptr().cast(),
                &mut size,
            ) == 0
            {
                continue;
            }
            let info = &*buffer.as_ptr().cast::<CRYPT_KEY_PROV_INFO>();
            let mut provider = 0usize;
            if NCryptOpenStorageProvider(&mut provider, info.pwszProvName, 0) != 0 {
                continue;
            }
            let mut key = 0usize;
            if NCryptOpenKey(
                provider,
                &mut key,
                info.pwszContainerName,
                info.dwKeySpec,
                0,
            ) == 0
            {
                // Deleting a key also frees its handle.
                NCryptDeleteKey(key, 0);
            }
            NCryptFreeObject(provider);
        }
    }
}
