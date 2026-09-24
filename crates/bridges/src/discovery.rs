//! Best-effort local discovery of pluggable-transport binaries, so common
//! transports (currently `obfs4`) work out of the box without requiring
//! `--pt` on every invocation — the exact friction that made a first-time
//! user's bridge line fail with a deep, unhelpful Arti error instead of a
//! clear "install this package" message. `--pt` still exists as an
//! explicit override for non-standard install locations or transports this
//! module doesn't know about.

use std::path::{Path, PathBuf};

/// Binary names to search for, in preference order, for a given PT
/// protocol. `obfs4proxy` was renamed `lyrebird` upstream; both names are
/// still shipped by different distros.
fn candidate_binary_names(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "obfs4" => &["obfs4proxy", "lyrebird"],
        "snowflake" => &["snowflake-client"],
        "webtunnel" => &["webtunnel-client"],
        _ => &[],
    }
}

/// Install locations that aren't always on `$PATH` (e.g. a login shell's
/// `PATH` differs from a systemd unit's).
const EXTRA_SEARCH_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/lib/obfs4proxy",
    "/opt/homebrew/bin",
    "/snap/bin",
];

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn path_dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default()
}

/// Searches `$PATH` plus a handful of common install locations for a
/// binary matching `protocol`. Returns the first match.
pub fn locate_transport_binary(protocol: &str) -> Option<PathBuf> {
    let names = candidate_binary_names(protocol);
    if names.is_empty() {
        return None;
    }
    let dirs: Vec<PathBuf> = path_dirs()
        .into_iter()
        .chain(EXTRA_SEARCH_DIRS.iter().map(PathBuf::from))
        .collect();
    for name in names {
        for dir in &dirs {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// The package believed to provide `protocol`'s binary on most distros, if
/// known.
fn package_name(protocol: &str) -> Option<&'static str> {
    match protocol {
        "obfs4" => Some("obfs4proxy"),
        "snowflake" => Some("snowflake-client"),
        _ => None,
    }
}

/// Picks an install command to suggest, based on whichever package
/// manager's own binary is present on `$PATH` — best-effort, just for the
/// error message; anonet never runs this itself.
fn suggest_install_command(pkg: &str) -> Option<String> {
    const MANAGERS: &[(&str, &str)] = &[
        ("apt-get", "sudo apt-get install -y"),
        ("dnf", "sudo dnf install -y"),
        ("pacman", "sudo pacman -S --noconfirm"),
        ("zypper", "sudo zypper install -y"),
        ("apk", "sudo apk add"),
    ];
    let dirs = path_dirs();
    MANAGERS
        .iter()
        .find(|(bin, _)| dirs.iter().any(|dir| dir.join(bin).exists()))
        .map(|(_, cmd)| format!("{cmd} {pkg}"))
}

/// A one-line, actionable error message for when `protocol`'s binary
/// couldn't be found anywhere, naming a concrete fix instead of leaving the
/// caller to decode an Arti pluggable-transport-manager error.
pub fn missing_transport_message(protocol: &str) -> String {
    match package_name(protocol) {
        Some(pkg) => match suggest_install_command(pkg) {
            Some(cmd) => format!(
                "no '{protocol}' pluggable-transport binary found; install it with: {cmd}"
            ),
            None => format!(
                "no '{protocol}' pluggable-transport binary found; install the '{pkg}' package for your distro, or pass --pt {protocol}=<path>"
            ),
        },
        None => format!(
            "no '{protocol}' pluggable-transport binary found, and anonet doesn't know which package provides it; pass --pt {protocol}=<path> to point at it manually"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_file(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn is_executable_true_only_for_executable_files() {
        let dir = tempfile::tempdir().unwrap();
        let exe = write_file(dir.path(), "obfs4proxy", 0o755);
        let non_exe = write_file(dir.path(), "readme", 0o644);
        assert!(is_executable(&exe));
        assert!(!is_executable(&non_exe));
        assert!(!is_executable(&dir.path().join("does-not-exist")));
    }

    #[test]
    fn locate_transport_binary_returns_none_for_unknown_protocol() {
        // Never touches the filesystem for a protocol we don't recognize —
        // there's nothing to search for.
        assert!(locate_transport_binary("not-a-real-transport").is_none());
    }

    #[test]
    fn missing_transport_message_names_known_package_and_protocol() {
        let msg = missing_transport_message("obfs4");
        assert!(msg.contains("obfs4"));
        assert!(msg.contains("obfs4proxy"));
    }

    #[test]
    fn missing_transport_message_falls_back_to_pt_flag_for_unknown_protocol() {
        let msg = missing_transport_message("mystery-transport");
        assert!(msg.contains("--pt mystery-transport="));
    }
}
