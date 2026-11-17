//! Rules of the house that a test keeps true: where `unsafe` may appear, what process-wide state
//! the library may hold, and that it never prints or exits.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn files_under(directory: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    rust_files(&root.join(directory), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (relative, fs::read_to_string(&path).unwrap())
        })
        .collect()
}

/// The lines of `source` that are code: no blank lines, no comments.
fn code_lines(source: &str) -> impl Iterator<Item = &str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
}

fn holding(directory: &str, needle: impl Fn(&str) -> bool) -> Vec<String> {
    files_under(directory)
        .into_iter()
        .filter(|(path, source)| path != "tests/guards.rs" && code_lines(source).any(&needle))
        .map(|(path, _)| path)
        .collect()
}

#[test]
fn unsafe_code_is_only_in_the_files_that_meet_a_system_boundary() {
    let uses_unsafe = |line: &str| {
        line.contains("unsafe {")
            || line.contains("unsafe fn")
            || line.contains("unsafe impl")
            || line.contains("unsafe extern")
    };
    assert_eq!(
        holding("src", uses_unsafe),
        ["src/auth/sspi.rs", "src/system/winhttp.rs"]
    );
    assert_eq!(
        holding("tests", |line| uses_unsafe(line)
            && !line.contains("allow(unsafe_code")),
        ["tests/support/cng_store.rs", "tests/support/sspi_server.rs"]
    );
}

#[test]
fn every_module_without_unsafe_is_covered_by_the_crate_wide_denial() {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(lib.contains("#![deny(unsafe_code)]"));
    // The two modules that allow it say so with a reason where they are declared.
    let all = files_under("src");
    let allowing: Vec<&str> = all
        .iter()
        .filter(|(_, source)| source.lines().any(|line| line.trim() == "unsafe_code,"))
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(allowing, ["src/auth/mod.rs", "src/system/mod.rs"]);
}

#[test]
fn the_library_keeps_no_process_wide_state_beyond_the_pac_engines_dns_cache() {
    let state = |line: &str| {
        line.starts_with("static ")
            || line.starts_with("pub static ")
            || line.contains("thread_local!")
            || line.contains("OnceLock")
            || line.contains("LazyLock")
            || line.contains("LazyCell")
            || line.contains("lazy_static")
    };
    // `GSS_MECH_NTLM` is an immutable object identifier; the DNS cache belongs to the thread that
    // runs one script.
    assert_eq!(
        holding("src", state),
        ["src/auth/gssapi.rs", "src/pac/mod.rs"]
    );
}

#[test]
fn the_library_never_prints_exits_or_changes_the_environment() {
    let forbidden = |line: &str| {
        line.contains("println!")
            || line.contains("eprintln!")
            || line.contains("process::exit")
            || line.contains("set_var")
            || line.contains("remove_var")
            || line.contains("set_current_dir")
    };
    assert_eq!(holding("src", forbidden), Vec::<String>::new());
}
