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
fn the_facade_has_no_unsafe_code() {
    let uses_unsafe = |line: &str| {
        line.contains("unsafe {")
            || line.contains("unsafe fn")
            || line.contains("unsafe impl")
            || line.contains("unsafe extern")
    };
    assert_eq!(holding("src", uses_unsafe), Vec::<String>::new());
    assert_eq!(holding("tests", uses_unsafe), Vec::<String>::new());
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(lib.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn the_facade_keeps_no_process_wide_state() {
    let state = |line: &str| {
        line.starts_with("static ")
            || line.starts_with("pub static ")
            || line.contains("thread_local!")
            || line.contains("OnceLock")
            || line.contains("LazyLock")
            || line.contains("LazyCell")
            || line.contains("lazy_static")
    };
    assert_eq!(holding("src", state), Vec::<String>::new());
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
