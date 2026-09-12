//! File-based API definition loading.
//!
//! The file-based source: the gateway scans a directory for
//! `*.json`, `*.yaml`, and `*.yml` files, each containing exactly one
//! [`ApiDefinition`]. Later milestones add a Redis-backed source managed via
//! the admin API; both feed the same router.

use std::collections::HashSet;
use std::path::Path;

use crate::{ApiDefinition, Error};

/// Loads, validates, and cross-checks every API definition in `dir`.
///
/// Files with unrecognized extensions are ignored. The returned definitions
/// are sorted by `api_id` so the load order is deterministic across pods.
///
/// # Errors
///
/// Returns the first error encountered: unreadable directory or file
/// ([`Error::Io`]), malformed file ([`Error::Parse`]), invalid definition
/// ([`Error::InvalidApiDefinition`]), or duplicate `api_id`/`listen_path`
/// across files ([`Error::ConflictingApiDefinitions`]).
pub fn load_dir(dir: &Path) -> Result<Vec<ApiDefinition>, Error> {
    let entries = std::fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.to_owned(),
        source,
    })?;

    let mut defs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| Error::Io {
            path: dir.to_owned(),
            source,
        })?;
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !matches!(ext, "json" | "yaml" | "yml") {
            continue;
        }

        let raw = std::fs::read_to_string(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        // YAML is a superset of JSON, so one parser covers all extensions.
        let def: ApiDefinition = serde_yaml::from_str(&raw).map_err(|e| Error::Parse {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        def.validate()?;
        tracing::debug!(api_id = %def.api_id, file = %path.display(), "loaded API definition");
        defs.push(def);
    }

    check_conflicts(&defs)?;
    defs.sort_by(|a, b| a.api_id.cmp(&b.api_id));
    Ok(defs)
}

/// Rejects definition sets with duplicate `api_id`s or `listen_path`s.
fn check_conflicts(defs: &[ApiDefinition]) -> Result<(), Error> {
    let mut ids = HashSet::new();
    let mut paths = HashSet::new();
    for def in defs {
        if !ids.insert(&def.api_id) {
            return Err(Error::ConflictingApiDefinitions {
                reason: format!("duplicate api_id `{}`", def.api_id),
            });
        }
        // Normalize the trailing slash so `/a` and `/a/` are seen as one path.
        let normalized = def.listen_path.trim_end_matches('/');
        if !paths.insert(normalized.to_owned()) {
            return Err(Error::ConflictingApiDefinitions {
                reason: format!("duplicate listen_path `{}`", def.listen_path),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_def(dir: &Path, file: &str, api_id: &str, listen_path: &str) {
        let body = format!(
            r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"http://up.internal"}}"#
        );
        fs::write(dir.join(file), body).expect("write def");
    }

    #[test]
    fn loads_json_and_yaml_sorted_by_api_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_def(dir.path(), "b.json", "beta", "/beta/");
        fs::write(
            dir.path().join("a.yaml"),
            "api_id: alpha\nname: Alpha\nlisten_path: /alpha/\ntarget_url: http://up.internal\n",
        )
        .expect("write yaml");
        fs::write(dir.path().join("notes.txt"), "ignored").expect("write txt");

        let defs = load_dir(dir.path()).expect("load");
        let ids: Vec<_> = defs.iter().map(|d| d.api_id.as_str()).collect();
        assert_eq!(ids, ["alpha", "beta"]);
    }

    #[test]
    fn empty_dir_loads_zero_definitions() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load_dir(dir.path()).expect("load").is_empty());
    }

    #[test]
    fn missing_dir_is_io_error() {
        let err = load_dir(Path::new("/nonexistent/apps")).unwrap_err();
        assert!(matches!(err, Error::Io { .. }));
    }

    #[test]
    fn malformed_file_reports_its_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("bad.json"), "{ nope").expect("write");
        let err = load_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("bad.json"), "got: {err}");
    }

    #[test]
    fn duplicate_api_id_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_def(dir.path(), "one.json", "same", "/one/");
        write_def(dir.path(), "two.json", "same", "/two/");
        let err = load_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("api_id"), "got: {err}");
    }

    #[test]
    fn duplicate_listen_path_is_rejected_modulo_trailing_slash() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_def(dir.path(), "one.json", "one", "/users/");
        write_def(dir.path(), "two.json", "two", "/users");
        let err = load_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("listen_path"), "got: {err}");
    }

    #[test]
    fn invalid_definition_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_def(dir.path(), "bad.json", "bad", "no-leading-slash");
        assert!(load_dir(dir.path()).is_err());
    }
}
