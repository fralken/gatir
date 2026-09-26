//! Where the configuration file is looked for when none is named.
//!
//! The user's own file comes first, then the one for the whole machine, so that
//! a service run by a user and a service run by the system both find theirs
//! without being told.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

const USER_FILE: &str = "gatir/gatir.toml";

#[cfg(unix)]
const SYSTEM_FILE: &str = "/etc/gatir/gatir.toml";

/// The places to look, in order.
fn candidates(config_home: Option<OsString>, home: Option<OsString>) -> Vec<PathBuf> {
    let mut places = Vec::new();
    // A relative `XDG_CONFIG_HOME` is not to be honored (the XDG specification).
    let config_home = config_home
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| {
            home.filter(|home| !home.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        });
    if let Some(dir) = config_home {
        places.push(dir.join(USER_FILE));
    }
    #[cfg(windows)]
    if let Some(dir) = std::env::var_os("APPDATA").filter(|dir| !dir.is_empty()) {
        places.push(PathBuf::from(dir).join(USER_FILE));
    }
    #[cfg(unix)]
    places.push(PathBuf::from(SYSTEM_FILE));
    places
}

/// The first of `places` for which `is_file` says yes.
fn first_that_exists(places: Vec<PathBuf>, is_file: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    places.into_iter().find(|place| is_file(place))
}

/// The configuration file to read when the command line names none, if there is one.
pub fn default_path() -> Option<PathBuf> {
    let places = candidates(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    );
    first_that_exists(places, Path::is_file)
}

/// How other users could get at the file, if they could: a file that holds a
/// secret must not be read by them, and none may be changed by them, since
/// what it says is where the traffic goes.
#[cfg(unix)]
pub fn exposure(path: &Path, holds_secrets: bool) -> Option<&'static str> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    if mode & 0o022 != 0 {
        Some("can be changed by other users")
    } else if holds_secrets && mode & 0o044 != 0 {
        Some("holds secrets and can be read by other users")
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn exposure(_path: &Path, _holds_secrets: bool) -> Option<&'static str> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn os(text: &str) -> Option<OsString> {
        Some(OsString::from(text))
    }

    #[cfg(unix)]
    #[test]
    fn the_users_file_comes_before_the_systems() {
        assert_eq!(
            candidates(os("/cfg"), os("/home/bob")),
            [
                PathBuf::from("/cfg/gatir/gatir.toml"),
                PathBuf::from("/etc/gatir/gatir.toml")
            ]
        );
        assert_eq!(
            candidates(None, os("/home/bob")),
            [
                PathBuf::from("/home/bob/.config/gatir/gatir.toml"),
                PathBuf::from("/etc/gatir/gatir.toml")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_relative_or_empty_xdg_directory_is_ignored() {
        for xdg in ["", "relative/dir", "."] {
            assert_eq!(
                candidates(os(xdg), os("/home/bob"))[0],
                PathBuf::from("/home/bob/.config/gatir/gatir.toml"),
                "{xdg:?}"
            );
        }
        // Without a home there is only the system's file.
        assert_eq!(
            candidates(None, None),
            [PathBuf::from("/etc/gatir/gatir.toml")]
        );
        assert_eq!(
            candidates(None, os("")),
            [PathBuf::from("/etc/gatir/gatir.toml")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_file_others_can_change_or_read_is_reported() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gatir.toml");
        std::fs::write(&file, "").unwrap();
        let with_mode = |mode: u32| {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        for (mode, secrets, expected) in [
            (0o600, true, None),
            (0o400, true, None),
            (0o644, false, None),
            (
                0o644,
                true,
                Some("holds secrets and can be read by other users"),
            ),
            (
                0o640,
                true,
                Some("holds secrets and can be read by other users"),
            ),
            (
                0o604,
                true,
                Some("holds secrets and can be read by other users"),
            ),
            (0o660, false, Some("can be changed by other users")),
            (0o602, false, Some("can be changed by other users")),
            (0o666, true, Some("can be changed by other users")),
        ] {
            with_mode(mode);
            assert_eq!(exposure(&file, secrets), expected, "{mode:o} {secrets}");
        }
        assert_eq!(exposure(&dir.path().join("missing"), true), None);
    }

    #[test]
    fn the_first_file_that_is_there_is_the_one() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (dir.path().join("a.toml"), dir.path().join("b.toml"));
        std::fs::write(&second, "").unwrap();
        let places = vec![first.clone(), second.clone()];
        assert_eq!(
            first_that_exists(places.clone(), Path::is_file),
            Some(second)
        );
        std::fs::write(&first, "").unwrap();
        assert_eq!(first_that_exists(places, Path::is_file), Some(first));
        assert_eq!(first_that_exists(Vec::new(), Path::is_file), None);
        // A directory of that name is not a configuration file.
        let folder = dir.path().join("folder.toml");
        std::fs::create_dir(&folder).unwrap();
        assert_eq!(first_that_exists(vec![folder], Path::is_file), None);
    }
}
