//! Cookie and token jars: memory, files, the root and the names.
#![cfg(feature = "session")]

use coqui_syshttp::Secret;
use coqui_syshttp::session::HttpEnv;
use coqui_syshttp::session::cookies::Cookie;
use coqui_syshttp::session::jar::{
    CookieJar, FileCookieJar, FileTokenJar, MemoryCookieJar, MemoryTokenJar, TokenJar,
    default_root, safe_name, store_root,
};

fn env(pairs: &[(&str, &str)]) -> HttpEnv {
    HttpEnv::builder()
        .environment(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .build()
        .unwrap()
}

fn cookie(name: &str) -> Cookie {
    Cookie {
        domain: "example.test".into(),
        path: "/".into(),
        secure: false,
        expires: None,
        name: name.into(),
        value: Secret::new("v"),
        http_only: false,
        subdomains: false,
    }
}

#[test]
fn safe_names_replace_what_no_filesystem_takes() {
    assert_eq!(safe_name("example.test"), "example.test");
    assert_eq!(safe_name("[::1]:80"), "[__1]_80");
    assert_eq!(safe_name(r#"a/b\c<d>e"f|g?h*i"#), "a_b_c_d_e_f_g_h_i");
}

#[test]
fn the_root_is_syshttp_home_else_the_platform_state_directory() {
    let home = store_root(&env(&[("SYSHTTP_HOME", "/data/jars")]));
    assert_eq!(home, std::path::PathBuf::from("/data/jars"));
    let prefixed = store_root(&env(&[
        ("SYSHTTP_PREFIX", "T_"),
        ("T_SYSHTTP_HOME", "/t/jars"),
    ]));
    assert_eq!(prefixed, std::path::PathBuf::from("/t/jars"));
    let none = env(&[]);
    assert_eq!(store_root(&none), default_root(&none));
    assert!(default_root(&none).ends_with("syshttp"));
}

#[cfg(unix)]
#[test]
fn the_default_root_follows_xdg_state_home() {
    let xdg = default_root(&env(&[("XDG_STATE_HOME", "/state")]));
    assert_eq!(xdg, std::path::PathBuf::from("/state/syshttp"));
}

#[cfg(windows)]
#[test]
fn the_default_root_follows_local_app_data() {
    let local = default_root(&env(&[("LOCALAPPDATA", "C:\\Local")]));
    assert_eq!(local, std::path::PathBuf::from("C:\\Local").join("syshttp"));
}

#[test]
fn a_home_that_starts_with_a_tilde_is_under_the_home_directory() {
    let expanded = store_root(&env(&[("SYSHTTP_HOME", "~/jars")]));
    assert!(!expanded.starts_with("~"), "{expanded:?}");
    assert!(expanded.ends_with("jars"));
}

#[test]
fn memory_jars_keep_and_replace_by_key() {
    let jar = MemoryCookieJar::new();
    assert!(jar.get("a.test").is_none());
    jar.set("a.test", &[cookie("one")]).unwrap();
    jar.set("a.test", &[cookie("two"), cookie("three")])
        .unwrap();
    assert_eq!(jar.get("a.test").unwrap().len(), 2);
    let tokens = MemoryTokenJar::new();
    assert!(tokens.get("a.test").is_none());
    tokens.set("a.test", &Secret::new("t")).unwrap();
    assert_eq!(tokens.get("a.test").unwrap().expose(), "t");
}

#[test]
fn a_file_cookie_jar_keeps_netscape_files_by_host_under_the_root() {
    let directory = tempfile::tempdir().unwrap();
    let jar = FileCookieJar::new(directory.path());
    assert!(
        !directory.path().join("cookies").exists(),
        "nothing is made until a write"
    );
    assert!(jar.get("example.test").is_none());
    jar.set("example.test", &[cookie("a")]).unwrap();
    let file = directory.path().join("cookies").join("example.test.txt");
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("example.test\tFALSE\t/\tFALSE\t0\ta\tv")
    );
    assert_eq!(jar.get("example.test").unwrap()[0].name, "a");
    jar.set("[::1]", &[cookie("b")]).unwrap();
    assert!(directory.path().join("cookies").join("[__1].txt").exists());
}

#[test]
fn a_file_token_jar_trims_and_ends_the_line() {
    let directory = tempfile::tempdir().unwrap();
    let jar = FileTokenJar::builder()
        .root(directory.path())
        .build_tokens();
    assert!(jar.get("example.test").is_none());
    jar.set("example.test", &Secret::new("  abc  ")).unwrap();
    let file = directory.path().join("tokens").join("example.test.token");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "abc\n");
    assert_eq!(jar.get("example.test").unwrap().expose(), "abc");
    std::fs::write(&file, "  \n").unwrap();
    assert!(jar.get("example.test").is_none(), "a blank token is none");
    assert!(format!("{jar:?}").contains("tokens"));
}

#[cfg(unix)]
#[test]
fn token_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let jar = FileTokenJar::new(directory.path());
    jar.set("example.test", &Secret::new("abc")).unwrap();
    let file = directory.path().join("tokens").join("example.test.token");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn the_builder_reads_the_root_from_the_env_it_is_given() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().to_string_lossy().to_string();
    let jar = FileCookieJar::builder()
        .env(env(&[("SYSHTTP_HOME", &home)]))
        .build_cookies();
    jar.set("a.test", &[cookie("x")]).unwrap();
    assert!(directory.path().join("cookies").join("a.test.txt").exists());
}

#[test]
fn an_unreadable_or_missing_file_is_no_entry() {
    let directory = tempfile::tempdir().unwrap();
    let jar = FileTokenJar::new(directory.path());
    assert!(jar.get("nobody.test").is_none());
}

/// A path `fs::read` refuses with `PermissionDenied` however often it is tried.
fn unreadable(directory: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    #[cfg(windows)]
    std::fs::create_dir_all(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, "token\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0)).unwrap();
    }
    path
}

#[test]
#[cfg(any(windows, unix))]
fn the_file_retries_are_settings_of_the_jar_builder() {
    use std::time::{Duration, Instant};
    let directory = tempfile::tempdir().unwrap();
    let tokens = directory.path().join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    let path = unreadable(&tokens, "retry.example.token");
    #[cfg(unix)]
    if std::fs::read(&path).is_ok() {
        return; // the superuser reads a file whatever its mode
    }
    let _ = &path;
    let timed = |tries: u32| {
        let jar = FileTokenJar::builder()
            .root(directory.path())
            .file_retries(tries, Duration::from_millis(60))
            .build_tokens();
        let started = Instant::now();
        assert!(jar.get("retry.example").is_none());
        started.elapsed()
    };
    assert!(timed(1) < Duration::from_millis(150));
    assert!(
        timed(6) >= Duration::from_millis(250),
        "five waits of 60 ms between six tries"
    );
}
