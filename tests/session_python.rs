//! A Netscape file written by the Rust jar loads in Python syshttp, and the reverse. Runs only
//! with `COQUI_SYSHTTP_TEST_PYTHON` naming a Python (run as `python -I`) that has `syshttp`.
#![cfg(feature = "session")]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use coqui_syshttp::Secret;
use coqui_syshttp::session::cookies::{Cookie, load_netscape, save_netscape};

const SCRIPT: &str = r#"
import sys
from pathlib import Path
from syshttp.cookies import load_netscape, save_netscape, CookieSpec

mode, path = sys.argv[1], Path(sys.argv[2])
if mode == "load":
    for c in load_netscape(path):
        print("\t".join([c.domain, c.path, str(c.secure), str(c.expires or 0), c.name, c.value,
                         str(c.http_only), str(c.subdomains)]))
else:
    save_netscape([
        CookieSpec("example.test", "/p", True, 2000000000, "py", "val ue", True, True),
        CookieSpec(".dot.test", "/", False, None, "s", "x"),
    ], path)
"#;

fn python() -> Option<String> {
    std::env::var("COQUI_SYSHTTP_TEST_PYTHON")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn run(python: &str, script: &Path, mode: &str, file: &Path) -> String {
    let output = Command::new(python)
        .arg("-I")
        .arg(script)
        .arg(mode)
        .arg(file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .replace("\r\n", "\n")
}

fn cookie(
    domain: &str,
    subdomains: bool,
    secure: bool,
    http_only: bool,
    expires: Option<u64>,
    name: &str,
    value: &str,
) -> Cookie {
    Cookie {
        domain: domain.into(),
        path: "/p".into(),
        secure,
        expires: expires.map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds)),
        name: name.into(),
        value: Secret::new(value),
        http_only,
        subdomains,
    }
}

#[test]
fn the_rust_file_loads_in_python_and_the_python_file_loads_in_rust() {
    let Some(python) = python() else {
        eprintln!("COQUI_SYSHTTP_TEST_PYTHON is not set: skipped");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("interop.py");
    std::fs::write(&script, SCRIPT).unwrap();

    let rust_file = directory.path().join("rust.txt");
    save_netscape(
        [
            cookie(
                "example.test",
                true,
                true,
                true,
                Some(2_000_000_000),
                "rs",
                "a b",
            ),
            cookie("host.test", false, false, false, None, "plain", ""),
        ],
        &rust_file,
    )
    .unwrap();
    let seen = run(&python, &script, "load", &rust_file);
    assert_eq!(
        seen,
        "example.test\t/p\tTrue\t2000000000\trs\ta b\tTrue\tTrue\nhost.test\t/p\tFalse\t0\tplain\t\tFalse\tFalse\n"
    );

    let python_file = directory.path().join("python.txt");
    run(&python, &script, "save", &python_file);
    let loaded = load_netscape(&python_file);
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].domain, "example.test");
    assert!(loaded[0].http_only && loaded[0].secure && loaded[0].subdomains);
    assert_eq!(
        loaded[0].expires,
        Some(UNIX_EPOCH + Duration::from_secs(2_000_000_000))
    );
    assert_eq!(loaded[0].value.expose(), "val ue");
    assert_eq!(loaded[1].domain, ".dot.test");
    assert_eq!(loaded[1].expires, None);
}
