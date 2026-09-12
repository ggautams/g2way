//! Listen-path routing: mapping a request path to an API definition.

use std::sync::Arc;

use g2_core::{ApiDefinition, Error};
use http::uri::{Authority, Scheme};

/// One routable API: a validated [`ApiDefinition`] plus everything
/// precomputed at build time so per-request matching does no parsing.
#[derive(Debug, Clone)]
pub struct Route {
    /// The API definition this route was built from.
    pub def: ApiDefinition,
    /// `listen_path` with any trailing `/` removed (`"/users"`; empty for `"/"`).
    pub listen_prefix: String,
    /// Upstream scheme parsed from `target_url`.
    pub target_scheme: Scheme,
    /// Upstream `host[:port]` parsed from `target_url`.
    pub target_authority: Authority,
    /// Upstream base path from `target_url` (`""` when the URL has no path).
    pub target_base_path: String,
}

impl Route {
    fn build(def: ApiDefinition) -> Result<Self, Error> {
        def.validate()?;
        let target = def.target_uri();
        let scheme = target.scheme().expect("validated scheme").clone();
        let authority = target.authority().expect("validated authority").clone();
        let base_path = target.path().trim_end_matches('/').to_owned();
        let listen_prefix = def.listen_path.trim_end_matches('/').to_owned();
        Ok(Self {
            def,
            listen_prefix,
            target_scheme: scheme,
            target_authority: authority,
            target_base_path: base_path,
        })
    }

    /// Whether `path` falls under this route's listen path.
    ///
    /// `/users` matches `/users` and `/users/42` but not `/users2`. A listen
    /// path of `/` matches every path.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        if self.listen_prefix.is_empty() {
            return true;
        }
        match path.strip_prefix(self.listen_prefix.as_str()) {
            Some(rest) => rest.is_empty() || rest.starts_with('/'),
            None => false,
        }
    }
}

/// An immutable, prebuilt routing table.
///
/// Built once per config (re)load from the full set of API definitions and
/// swapped into the gateway atomically. Matching scans routes ordered by
/// listen-path length, so the most specific (longest) prefix wins.
#[derive(Debug, Default)]
pub struct RouteTable {
    /// Routes sorted by `listen_prefix` length, longest first.
    routes: Vec<Arc<Route>>,
}

impl RouteTable {
    /// Builds a table from definitions, skipping inactive ones.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] if any definition (active or
    /// not) fails validation — a broken definition should fail loudly at load
    /// time, not silently at request time.
    pub fn build(defs: Vec<ApiDefinition>) -> Result<Self, Error> {
        let mut routes = Vec::with_capacity(defs.len());
        for def in defs {
            let active = def.active;
            let route = Route::build(def)?;
            if active {
                routes.push(Arc::new(route));
            } else {
                tracing::info!(api_id = %route.def.api_id, "skipping inactive API");
            }
        }
        routes.sort_by(|a, b| {
            b.listen_prefix
                .len()
                .cmp(&a.listen_prefix.len())
                .then_with(|| a.listen_prefix.cmp(&b.listen_prefix))
        });
        Ok(Self { routes })
    }

    /// Finds the route for `path`, preferring the longest listen-path match.
    #[must_use]
    pub fn match_path(&self, path: &str) -> Option<&Arc<Route>> {
        self.routes.iter().find(|r| r.matches(path))
    }

    /// All active routes, most specific first (for status/introspection APIs).
    #[must_use]
    pub fn routes(&self) -> &[Arc<Route>] {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(api_id: &str, listen_path: &str, target_url: &str) -> ApiDefinition {
        serde_json::from_str(&format!(
            r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"{target_url}"}}"#
        ))
        .expect("valid definition")
    }

    #[test]
    fn longest_prefix_wins() {
        let table = RouteTable::build(vec![
            def("all", "/", "http://all.internal"),
            def("users", "/users/", "http://users.internal"),
            def("user-admin", "/users/admin/", "http://admin.internal"),
        ])
        .expect("build");

        let hit = |p: &str| table.match_path(p).expect("route").def.api_id.clone();
        assert_eq!(hit("/users/admin/x"), "user-admin");
        assert_eq!(hit("/users/admin"), "user-admin");
        assert_eq!(hit("/users/42"), "users");
        assert_eq!(hit("/other"), "all");
        assert_eq!(hit("/"), "all");
    }

    #[test]
    fn prefix_matches_whole_segments_only() {
        let table =
            RouteTable::build(vec![def("users", "/users", "http://u.internal")]).expect("build");
        assert!(table.match_path("/users").is_some());
        assert!(table.match_path("/users/").is_some());
        assert!(table.match_path("/users/42").is_some());
        assert!(table.match_path("/users2").is_none());
        assert!(table.match_path("/user").is_none());
    }

    #[test]
    fn trailing_slash_in_listen_path_is_ignored_for_matching() {
        let with = RouteTable::build(vec![def("a", "/svc/", "http://u.internal")]).expect("build");
        let without =
            RouteTable::build(vec![def("a", "/svc", "http://u.internal")]).expect("build");
        for t in [&with, &without] {
            assert!(t.match_path("/svc").is_some());
            assert!(t.match_path("/svc/x").is_some());
        }
    }

    #[test]
    fn inactive_apis_are_not_routed() {
        let mut d = def("off", "/off/", "http://u.internal");
        d.active = false;
        let table = RouteTable::build(vec![d]).expect("build");
        assert!(table.match_path("/off/x").is_none());
        assert!(table.routes().is_empty());
    }

    #[test]
    fn invalid_definition_fails_the_whole_build() {
        let bad = def("bad", "/ok/", "not-a-url");
        assert!(RouteTable::build(vec![bad]).is_err());
    }

    #[test]
    fn route_precomputes_target_parts() {
        let table = RouteTable::build(vec![def("a", "/a/", "https://api.internal:8443/base/")])
            .expect("build");
        let route = table.match_path("/a/x").expect("route");
        assert_eq!(route.target_scheme.as_str(), "https");
        assert_eq!(route.target_authority.as_str(), "api.internal:8443");
        assert_eq!(route.target_base_path, "/base");
    }

    #[test]
    fn empty_table_matches_nothing() {
        let table = RouteTable::build(vec![]).expect("build");
        assert!(table.match_path("/anything").is_none());
    }
}
