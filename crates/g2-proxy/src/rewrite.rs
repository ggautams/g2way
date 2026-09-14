//! Pure request-rewriting helpers: path mapping (regex URL rewrites and
//! listen-path strip/join), hop-by-hop header removal, and `X-Forwarded-*`
//! header injection.

use std::net::IpAddr;

use g2_core::transform::UrlRewriteRule;
use g2_core::Error;
use http::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST};
use regex::Regex;

use crate::forward::{UpstreamAddr, UpstreamTarget};

/// One URL rewrite rule with its pattern compiled at route-build time
/// (ADR-0001 hot-path rule: no per-request regex parsing).
#[derive(Debug, Clone)]
pub(crate) struct CompiledRewrite {
    pattern: Regex,
    rewrite: String,
}

impl CompiledRewrite {
    /// Compiles `rule`'s pattern; `api_id` names the API in errors.
    ///
    /// Definitions are validated before routes are built, so a failure here
    /// indicates a validation gap — surfaced loudly rather than panicking.
    pub(crate) fn compile(rule: &UrlRewriteRule, api_id: &str) -> Result<Self, Error> {
        let pattern = Regex::new(&rule.pattern).map_err(|err| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason: format!("invalid `url_rewrites` pattern `{}`: {err}", rule.pattern),
        })?;
        Ok(Self {
            pattern,
            rewrite: rule.rewrite.clone(),
        })
    }

    /// Expands the rewrite template if `path` matches, else `None`.
    fn apply(&self, path: &str) -> Option<String> {
        let caps = self.pattern.captures(path)?;
        let mut expanded = String::with_capacity(self.rewrite.len());
        caps.expand(&self.rewrite, &mut expanded);
        Some(expanded)
    }
}

/// Headers that are connection-local per RFC 9110 §7.6.1 and must not be
/// forwarded by an intermediary.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Computes the upstream `path?query` for a request matched to `target`,
/// bound for `addr` (the address picked from the target's rotation, whose
/// base path the result is joined onto).
///
/// The target's URL rewrite rules are tried first, in order, against the
/// full client path; the first match's expansion replaces the listen-path
/// strip as the upstream tail (any query it carries comes before the
/// client's). Otherwise, with `strip_listen_path` (the default) the
/// listen-path prefix is removed and the remainder is appended to the
/// upstream base path; without it the full original path is appended. The
/// client's query string is always forwarded untouched.
pub(crate) fn upstream_path_and_query(
    target: &UpstreamTarget,
    addr: &UpstreamAddr,
    req_path: &str,
    query: Option<&str>,
) -> String {
    let query = query.filter(|q| !q.is_empty());
    let rewritten = target.rewrites.iter().find_map(|r| r.apply(req_path));
    let (tail, rewrite_query) = match &rewritten {
        Some(expanded) => match expanded.split_once('?') {
            Some((path, q)) => (path, (!q.is_empty()).then_some(q)),
            None => (expanded.as_str(), None),
        },
        None if target.strip_listen_path => (
            // `Route::matches()` guaranteed the prefix is present.
            req_path
                .strip_prefix(target.listen_prefix.as_str())
                .unwrap_or(req_path),
            None,
        ),
        None => (req_path, None),
    };

    let mut path = join_paths(&addr.base_path, tail);
    for (i, q) in rewrite_query.iter().chain(query.iter()).enumerate() {
        path.push(if i == 0 { '?' } else { '&' });
        path.push_str(q);
    }
    path
}

/// Joins an upstream base path (already trailing-slash-trimmed, possibly
/// empty) with a request tail, producing a path that always starts with `/`.
fn join_paths(base: &str, tail: &str) -> String {
    let tail = tail.trim_start_matches('/');
    if tail.is_empty() {
        if base.is_empty() {
            "/".to_owned()
        } else {
            base.to_owned()
        }
    } else {
        format!("{base}/{tail}")
    }
}

/// Removes hop-by-hop headers: the RFC 9110 set plus anything the request's
/// own `Connection` header names.
pub(crate) fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    // Headers named by `Connection: a, b` are connection-local too.
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| name.trim().parse::<HeaderName>().ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Sets the standard `X-Forwarded-For/-Host/-Proto` headers.
///
/// An existing `X-Forwarded-For` chain is extended with `client_ip`;
/// `X-Forwarded-Host`/`-Proto` are only set if absent, preserving values from
/// a trusted upstream proxy in front of the gateway.
pub(crate) fn apply_forwarded_headers(
    headers: &mut HeaderMap,
    client_ip: IpAddr,
    original_host: Option<&HeaderValue>,
    tls: bool,
) {
    const XFF: HeaderName = HeaderName::from_static("x-forwarded-for");
    const XFH: HeaderName = HeaderName::from_static("x-forwarded-host");
    const XFP: HeaderName = HeaderName::from_static("x-forwarded-proto");

    let chain = match headers.get(&XFF).and_then(|v| v.to_str().ok()) {
        Some(existing) => format!("{existing}, {client_ip}"),
        None => client_ip.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&chain) {
        headers.insert(XFF, v);
    }

    if !headers.contains_key(&XFH) {
        if let Some(host) = original_host {
            headers.insert(XFH, host.clone());
        }
    }
    if !headers.contains_key(&XFP) {
        // `tls` reports whether the gateway terminated TLS on this
        // connection (from `ConnectionInfo`, stamped by the accept loop).
        headers.insert(
            XFP,
            HeaderValue::from_static(if tls { "https" } else { "http" }),
        );
    }
}

/// Prepares request headers for forwarding to the upstream of `target`.
///
/// Removes hop-by-hop headers, applies the `preserve_host_header` policy
/// (dropping `Host` lets the client fill in the upstream authority), and adds
/// the `X-Forwarded-*` set.
pub(crate) fn prepare_upstream_headers(
    headers: &mut HeaderMap,
    target: &UpstreamTarget,
    client_ip: IpAddr,
    tls: bool,
) {
    let original_host = headers.get(HOST).cloned();
    strip_hop_by_hop_headers(headers);
    if !target.preserve_host_header {
        headers.remove(HOST);
    }
    apply_forwarded_headers(headers, client_ip, original_host.as_ref(), tls);
}

#[cfg(test)]
mod tests {
    use super::*;
    use g2_core::ApiDefinition;

    /// Path computation against the target's first (and in these tests only)
    /// upstream address.
    fn pq(target: &UpstreamTarget, path: &str, query: Option<&str>) -> String {
        let set = target.target_set();
        upstream_path_and_query(target, &set.addrs[0], path, query)
    }

    fn route(
        listen_path: &str,
        target_url: &str,
        strip: bool,
        preserve_host: bool,
    ) -> UpstreamTarget {
        let mut def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"t","name":"t","listen_path":"{listen_path}","target_url":"{target_url}"}}"#
        ))
        .expect("def");
        def.strip_listen_path = strip;
        def.preserve_host_header = preserve_host;
        UpstreamTarget::build(&def).expect("target")
    }

    #[test]
    fn strips_listen_path_onto_bare_target() {
        let r = route("/users/", "http://u.internal", true, false);
        assert_eq!(pq(&r, "/users/42", None), "/42");
        assert_eq!(pq(&r, "/users", None), "/");
        assert_eq!(pq(&r, "/users/", None), "/");
    }

    #[test]
    fn strips_listen_path_onto_target_base_path() {
        let r = route("/users/", "http://u.internal/api/v1/", true, false);
        assert_eq!(pq(&r, "/users/42", None), "/api/v1/42");
        assert_eq!(pq(&r, "/users", None), "/api/v1");
    }

    #[test]
    fn no_strip_forwards_full_path() {
        let r = route("/users/", "http://u.internal/base", false, false);
        assert_eq!(pq(&r, "/users/42", None), "/base/users/42");
    }

    #[test]
    fn query_string_is_forwarded() {
        let r = route("/users/", "http://u.internal", true, false);
        assert_eq!(pq(&r, "/users/42", Some("a=1&b=2")), "/42?a=1&b=2");
    }

    #[test]
    fn root_listen_path_maps_everything() {
        let r = route("/", "http://u.internal", true, false);
        assert_eq!(pq(&r, "/any/thing", None), "/any/thing");
        assert_eq!(pq(&r, "/", None), "/");
    }

    fn route_with_rewrites(target_url: &str, rules: &str) -> UpstreamTarget {
        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"t","name":"t","listen_path":"/users/","target_url":"{target_url}",
                 "url_rewrites":{rules}}}"#
        ))
        .expect("def");
        UpstreamTarget::build(&def).expect("target")
    }

    #[test]
    fn url_rewrite_replaces_strip_and_joins_base_path() {
        let r = route_with_rewrites(
            "http://u.internal/api/v1",
            r#"[{"pattern": "^/users/(\\d+)/profile$", "rewrite": "/profiles/$1"}]"#,
        );
        assert_eq!(pq(&r, "/users/42/profile", None), "/api/v1/profiles/42");
        // Non-matching paths keep the normal strip/join.
        assert_eq!(pq(&r, "/users/42", None), "/api/v1/42");
    }

    #[test]
    fn first_matching_rewrite_rule_wins() {
        let r = route_with_rewrites(
            "http://u.internal",
            r#"[{"pattern": "^/users/me$", "rewrite": "/self"},
                {"pattern": "^/users/(\\w+)$", "rewrite": "/accounts/$1"}]"#,
        );
        assert_eq!(pq(&r, "/users/me", None), "/self");
        assert_eq!(pq(&r, "/users/bob", None), "/accounts/bob");
    }

    #[test]
    fn rewrite_query_precedes_the_clients() {
        let r = route_with_rewrites(
            "http://u.internal",
            r#"[{"pattern": "^/users/legacy$", "rewrite": "/v2/users?compat=1"}]"#,
        );
        assert_eq!(
            pq(&r, "/users/legacy", Some("limit=5")),
            "/v2/users?compat=1&limit=5"
        );
        assert_eq!(pq(&r, "/users/legacy", None), "/v2/users?compat=1");
    }

    #[test]
    fn rewrite_with_named_groups_expands() {
        let r = route_with_rewrites(
            "http://u.internal",
            r#"[{"pattern": "^/users/(?<id>\\d+)$", "rewrite": "/people/${id}"}]"#,
        );
        assert_eq!(pq(&r, "/users/7", None), "/people/7");
    }

    #[test]
    fn hop_by_hop_headers_are_removed() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-custom"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("x-custom", HeaderValue::from_static("conn-local"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        h.insert("x-app", HeaderValue::from_static("kept"));
        strip_hop_by_hop_headers(&mut h);
        assert!(h.get(CONNECTION).is_none());
        assert!(h.get("keep-alive").is_none());
        assert!(h.get("x-custom").is_none(), "Connection-named header kept");
        assert!(h.get("upgrade").is_none());
        assert_eq!(h.get("x-app").expect("kept").as_bytes(), b"kept");
    }

    #[test]
    fn xff_chain_is_extended() {
        let ip: IpAddr = "10.0.0.9".parse().expect("ip");
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        apply_forwarded_headers(&mut h, ip, None, false);
        assert_eq!(
            h.get("x-forwarded-for").expect("xff").as_bytes(),
            b"1.2.3.4, 10.0.0.9"
        );
    }

    #[test]
    fn forwarded_host_and_proto_are_set_once() {
        let ip: IpAddr = "10.0.0.9".parse().expect("ip");
        let mut h = HeaderMap::new();
        let host = HeaderValue::from_static("api.example.com");
        apply_forwarded_headers(&mut h, ip, Some(&host), false);
        assert_eq!(
            h.get("x-forwarded-host").expect("xfh").as_bytes(),
            b"api.example.com"
        );
        assert_eq!(h.get("x-forwarded-proto").expect("xfp").as_bytes(), b"http");

        // Pre-set values (from a trusted fronting proxy) are preserved.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        apply_forwarded_headers(&mut h, ip, Some(&host), false);
        assert_eq!(
            h.get("x-forwarded-proto").expect("xfp").as_bytes(),
            b"https"
        );
    }

    #[test]
    fn forwarded_proto_reflects_terminated_tls() {
        let ip: IpAddr = "10.0.0.9".parse().expect("ip");
        let mut h = HeaderMap::new();
        apply_forwarded_headers(&mut h, ip, None, true);
        assert_eq!(
            h.get("x-forwarded-proto").expect("xfp").as_bytes(),
            b"https"
        );
    }

    #[test]
    fn host_header_dropped_unless_preserved() {
        let ip: IpAddr = "10.0.0.9".parse().expect("ip");

        let r = route("/a/", "http://u.internal", true, false);
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("public.example.com"));
        prepare_upstream_headers(&mut h, &r, ip, false);
        assert!(h.get(HOST).is_none(), "host dropped by default");
        // …but still recorded for the upstream's benefit.
        assert_eq!(
            h.get("x-forwarded-host").expect("xfh").as_bytes(),
            b"public.example.com"
        );

        let r = route("/a/", "http://u.internal", true, true);
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("public.example.com"));
        prepare_upstream_headers(&mut h, &r, ip, false);
        assert_eq!(
            h.get(HOST).expect("host preserved").as_bytes(),
            b"public.example.com"
        );
    }
}
