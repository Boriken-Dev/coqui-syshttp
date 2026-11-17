#![cfg(all(feature = "pkcs11", unix))]

//! A PKCS #11 token (SoftHSM) answers a server's certificate request. The token is created and
//! filled with the `softhsm2-util` and `pkcs11-tool` programs, then the handshake runs in a copy of
//! this test binary whose environment names the token's configuration, because a module reads its
//! configuration from the environment when it is loaded.
//!
//! Run with `COQUI_SYSHTTP_TEST_PKCS11=1 cargo test --features pkcs11 --test pkcs11 -- --ignored`.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use coqui_syshttp::Secret;
use coqui_syshttp::tls::{ClientCertificates, IdentitySource, Pkcs11Source, Selector, Tls, Trust};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256,
};
use support::pki::Ca;
use support::tls_server::{ClientAuth, TlsServer, https_get};

const PIN: &str = "1234";
const SO_PIN: &str = "5678";

fn module_path() -> PathBuf {
    [
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/pkcs11/libsofthsm2.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
    .expect("libsofthsm2.so is installed")
}

fn run(program: &str, args: &[&str], config: &Path) {
    let output = Command::new(program)
        .args(args)
        .env("SOFTHSM2_CONF", config)
        .output()
        .unwrap_or_else(|error| panic!("{program} runs: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A client certificate under `ca` for a key made by `openssl` (RSA) or by rcgen (EC).
fn client_certificate(ca: &Ca, directory: &Path, rsa: bool) -> (Vec<u8>, String) {
    let key = if rsa {
        let path = directory.join("rsa.pem");
        let output = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&path)
            .output()
            .expect("openssl runs");
        assert!(output.status.success(), "openssl genpkey");
        KeyPair::from_pem_and_sign_algo(&std::fs::read_to_string(&path).unwrap(), &PKCS_RSA_SHA256)
            .unwrap()
    } else {
        KeyPair::generate().unwrap()
    };
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "token-user");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let certificate = ca.sign_with(params, &key);
    (certificate, key.serialize_pem())
}

fn parent(rsa: bool) {
    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path();
    let tokens = dir.join("tokens");
    std::fs::create_dir(&tokens).unwrap();
    let config = dir.join("softhsm2.conf");
    std::fs::write(
        &config,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\n",
            tokens.display()
        ),
    )
    .unwrap();

    let server_ca = Ca::new("Server CA");
    let client_ca = Ca::new("Corp Client CA");
    let (certificate, key_pem) = client_certificate(&client_ca, dir, rsa);
    std::fs::write(dir.join("client.der"), &certificate).unwrap();
    std::fs::write(dir.join("client.key.pem"), &key_pem).unwrap();
    std::fs::write(dir.join("server-ca.der"), server_ca.der()).unwrap();
    std::fs::write(dir.join("client-ca.der"), client_ca.der()).unwrap();

    let module = module_path();
    let module = module.to_str().unwrap();
    run(
        "softhsm2-util",
        &[
            "--init-token",
            "--free",
            "--label",
            "coqui-test",
            "--pin",
            PIN,
            "--so-pin",
            SO_PIN,
        ],
        &config,
    );
    run(
        "softhsm2-util",
        &[
            "--import",
            dir.join("client.key.pem").to_str().unwrap(),
            "--token",
            "coqui-test",
            "--label",
            "client",
            "--id",
            "01",
            "--pin",
            PIN,
        ],
        &config,
    );
    run(
        "pkcs11-tool",
        &[
            "--module",
            module,
            "--login",
            "--pin",
            PIN,
            "--write-object",
            dir.join("client.der").to_str().unwrap(),
            "--type",
            "cert",
            "--label",
            "client",
            "--id",
            "01",
        ],
        &config,
    );

    let exe = std::env::current_exe().unwrap();
    let output = Command::new(exe)
        .args([
            "--exact",
            if rsa {
                "an_rsa_key_on_a_token_signs_the_handshake"
            } else {
                "an_ec_key_on_a_token_signs_the_handshake"
            },
            "--ignored",
            "--nocapture",
        ])
        .env("SOFTHSM2_CONF", &config)
        .env("COQUI_SYSHTTP_TEST_PKCS11_DIR", dir)
        .env("COQUI_SYSHTTP_TEST_PKCS11_MODULE", module)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the handshake in the child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The handshake, in the process whose environment names the token.
fn child() {
    let dir = PathBuf::from(std::env::var("COQUI_SYSHTTP_TEST_PKCS11_DIR").unwrap());
    let module = std::env::var("COQUI_SYSHTTP_TEST_PKCS11_MODULE").unwrap();
    let der = |name: &str| {
        rustls::pki_types::CertificateDer::from(std::fs::read(dir.join(name)).unwrap())
    };
    let client_der = std::fs::read(dir.join("client.der")).unwrap();
    let server_ca = Ca::new("Handshake Server CA");

    let server = TlsServer::start(
        &server_ca.issue_server("localhost"),
        &[der("client-ca.der")],
        ClientAuth::Required,
    );
    let source = Pkcs11Source::builder(module)
        .pin(Secret::new(PIN))
        .token_label("coqui-test")
        .build();
    let identities = source.identities().unwrap();
    assert_eq!(
        identities.len(),
        1,
        "one certificate with a key on the token"
    );
    assert_eq!(identities[0].chain()[0].as_ref(), client_der.as_slice());

    let tls = Tls::builder()
        .trust(Trust::Roots(vec![server_ca.der()]))
        .client_certificates(ClientCertificates::Selector(Arc::new(
            Selector::builder().source(source).build(),
        )))
        .build()
        .unwrap();
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("client certificate seen"), "{reply}");
    assert_eq!(server.presented(), [Some(client_der)]);
}

fn requested() -> bool {
    std::env::var_os("COQUI_SYSHTTP_TEST_PKCS11_DIR").is_none()
}

#[test]
#[ignore = "needs softhsm2-util, pkcs11-tool and SoftHSM; run with COQUI_SYSHTTP_TEST_PKCS11=1 and --ignored"]
fn an_ec_key_on_a_token_signs_the_handshake() {
    if requested() {
        assert!(
            std::env::var_os("COQUI_SYSHTTP_TEST_PKCS11").is_some(),
            "set COQUI_SYSHTTP_TEST_PKCS11=1 to run this test"
        );
        parent(false);
    } else {
        child();
    }
}

#[test]
#[ignore = "needs softhsm2-util, pkcs11-tool, openssl and SoftHSM; run with COQUI_SYSHTTP_TEST_PKCS11=1 and --ignored"]
fn an_rsa_key_on_a_token_signs_the_handshake() {
    if requested() {
        assert!(
            std::env::var_os("COQUI_SYSHTTP_TEST_PKCS11").is_some(),
            "set COQUI_SYSHTTP_TEST_PKCS11=1 to run this test"
        );
        parent(true);
    } else {
        child();
    }
}
