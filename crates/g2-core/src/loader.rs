//! File-based API definition loading, and merging of definition sources.
//!
//! [`load_dir`] is the file-based source: the gateway scans a
//! directory for `*.json`, `*.yaml`, and `*.yml` files, each containing
//! exactly one [`ApiDefinition`]. A second, storage-backed source lives in
//! `g2-storage` (`load_api_definitions`); [`merge_sources`] combines the two
//! into the one conflict-free set the router is built from (ADR-0002).

use std::collections::{HashMap, HashSet};
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

/// Merges the file-loaded and storage-loaded API definition sets.
///
/// Both inputs are expected to be individually valid (each source validates
/// what it loads); this checks the invariants that only hold *across*
/// sources and returns the combined set sorted by `api_id`. There is no
/// precedence between sources: a duplicate `api_id` or `listen_path` —
/// whether across sources or within one — is an error naming the sources
/// involved, never a silent shadow (ADR-0002).
///
/// # Errors
///
/// Returns [`Error::ConflictingApiDefinitions`] on any duplicate `api_id` or
/// `listen_path` (listen paths compare modulo one trailing slash).
pub fn merge_sources(
    file_defs: Vec<ApiDefinition>,
    storage_defs: Vec<ApiDefinition>,
) -> Result<Vec<ApiDefinition>, Error> {
    let mut ids: HashMap<String, &'static str> = HashMap::new();
    let mut paths: HashMap<String, &'static str> = HashMap::new();
    let labeled = file_defs
        .iter()
        .map(|d| (d, "file"))
        .chain(storage_defs.iter().map(|d| (d, "storage")));
    for (def, source) in labeled {
        if let Some(prev) = ids.insert(def.api_id.clone(), source) {
            return Err(Error::ConflictingApiDefinitions {
                reason: format!(
                    "duplicate api_id `{}` ({prev} source and {source} source)",
                    def.api_id
                ),
            });
        }
        let normalized = def.listen_path.trim_end_matches('/').to_owned();
        if let Some(prev) = paths.insert(normalized, source) {
            return Err(Error::ConflictingApiDefinitions {
                reason: format!(
                    "duplicate listen_path `{}` ({prev} source and {source} source)",
                    def.listen_path
                ),
            });
        }
    }

    let mut defs = file_defs;
    defs.extend(storage_defs);
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

    mod merge_sources {
        use super::*;

        fn def(api_id: &str, listen_path: &str) -> ApiDefinition {
            serde_json::from_str(&format!(
                r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"http://up.internal"}}"#
            ))
            .expect("valid definition JSON")
        }

        #[test]
        fn combines_and_sorts_by_api_id() {
            let merged = merge_sources(
                vec![def("delta", "/d/"), def("alpha", "/a/")],
                vec![def("charlie", "/c/")],
            )
            .expect("merge");
            let ids: Vec<_> = merged.iter().map(|d| d.api_id.as_str()).collect();
            assert_eq!(ids, ["alpha", "charlie", "delta"]);
        }

        #[test]
        fn either_side_may_be_empty() {
            assert_eq!(merge_sources(vec![], vec![]).expect("merge").len(), 0);
            assert_eq!(
                merge_sources(vec![def("a", "/a/")], vec![])
                    .expect("merge")
                    .len(),
                1
            );
            assert_eq!(
                merge_sources(vec![], vec![def("a", "/a/")])
                    .expect("merge")
                    .len(),
                1
            );
        }

        #[test]
        fn cross_source_duplicate_api_id_names_both_sources() {
            let err = merge_sources(vec![def("same", "/one/")], vec![def("same", "/two/")])
                .expect_err("conflict");
            let msg = err.to_string();
            assert!(msg.contains("api_id `same`"), "got: {msg}");
            assert!(
                msg.contains("file source") && msg.contains("storage source"),
                "got: {msg}"
            );
        }

        #[test]
        fn cross_source_duplicate_listen_path_is_rejected_modulo_trailing_slash() {
            let err = merge_sources(vec![def("one", "/users/")], vec![def("two", "/users")])
                .expect_err("conflict");
            assert!(err.to_string().contains("listen_path"), "got: {err}");
        }

        #[test]
        fn duplicates_within_one_source_are_still_rejected() {
            let err = merge_sources(vec![], vec![def("same", "/one/"), def("same", "/two/")])
                .expect_err("conflict");
            assert!(
                err.to_string()
                    .contains("storage source and storage source"),
                "got: {err}"
            );
        }
    }
}
