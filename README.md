# deps

Everything a build of the main branch needs from the network, as text: `crates/` is a cargo vendor
directory with one `NAME-VERSION/` directory for each package Cargo.lock names, and `manifest.json`
says which commit and lock it was made from. Nothing here is edited by hand: `tools/build.py deps
refresh` on main rewrites it, and `tools/build.py deps check` holds it to Cargo.lock.

No archive, executable, key or opaque binary is kept: a file a build reads that is one is written
as text.
