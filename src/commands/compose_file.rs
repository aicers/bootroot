use std::path::{Path, PathBuf};

/// Returns the directory containing `compose_file`, normalising the
/// "no directory component" case to `"."`.
///
/// `Path::parent` returns `Some("")` (not `None`) for relative paths
/// without a directory component like `docker-compose.yml`, so a naive
/// `compose_file.parent().unwrap_or(Path::new("."))` produces an empty
/// path that breaks downstream `canonicalize` / `file_name` / `.join`
/// behaviour.  Funnel every `--compose-file` directory derivation
/// through this helper to avoid that footgun.
pub(crate) fn compose_file_dir(compose_file: &Path) -> PathBuf {
    match compose_file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_parent_becomes_dot() {
        assert_eq!(
            compose_file_dir(Path::new("docker-compose.yml")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn explicit_relative_directory_preserved() {
        assert_eq!(
            compose_file_dir(Path::new("deploy/docker-compose.yml")),
            PathBuf::from("deploy")
        );
    }

    #[test]
    fn absolute_directory_preserved() {
        assert_eq!(
            compose_file_dir(Path::new("/srv/bootroot/docker-compose.yml")),
            PathBuf::from("/srv/bootroot")
        );
    }

    #[test]
    fn dot_relative_directory_preserved() {
        assert_eq!(
            compose_file_dir(Path::new("./docker-compose.yml")),
            PathBuf::from(".")
        );
    }
}
