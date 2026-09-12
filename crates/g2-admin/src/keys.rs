//! `/g2/keys` — CRUD for stored [`KeySession`]s.
//!
//! Keys are stored hashed (see [`g2_core::session::hash_key`]), so the raw
//! key exists only in the `POST` response that created it. `GET`, `PUT` and
//! `DELETE` address a key by its **raw value** in the path by default; pass
//! `?hashed=true` to address by the stored hash instead (the only handle an
//! operator has once the raw key is gone).
//!
//! Basic-auth users are ordinary sessions stored under the virtual raw key
//! `basic:{username}` — `PUT /g2/keys/basic:alice` with a session carrying
//! `basic_auth.password_hash` provisions one.
//!
//! `GET`/`DELETE` take an optional `?org_id=` (defaulting to the single-org
//! default); `POST`/`PUT` take the organization from the session body.
//! `GET /g2/keys` lists the organization's stored **key hashes** — raw
//! keys are unrecoverable by design.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use g2_core::session::{hash_key, session_key_prefix, session_storage_key};
use g2_core::KeySession;
use serde::Deserialize;

use crate::{error_response, AdminState};

/// How `GET`/`PUT`/`DELETE /g2/keys/{key}` interpret the path parameter.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct KeyAddress {
    /// When `true`, the path parameter is the stored key hash itself
    /// instead of a raw key.
    #[serde(default)]
    hashed: bool,

    /// Organization the key belongs to (`GET`/`DELETE` only; `POST`/`PUT`
    /// read it from the session body). Defaults to the single-org default.
    org_id: Option<String>,
}

impl KeyAddress {
    fn key_hash(&self, param: &str) -> String {
        if self.hashed {
            param.to_owned()
        } else {
            hash_key(param)
        }
    }

    fn org(&self) -> &str {
        self.org_id.as_deref().unwrap_or(g2_core::DEFAULT_ORG_ID)
    }
}

/// Serializes a session for storage, or the ready-to-send 400 for an
/// invalid one.
// The large Err is a rejection Response built once on the cold path; boxing
// it would just move the allocation.
#[allow(clippy::result_large_err)]
fn storable_session(session: &KeySession) -> Result<String, Response> {
    session
        .validate()
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(serde_json::to_string(session).expect("KeySession always serializes"))
}

/// Maps a storage failure to the ready-to-send 503.
fn storage_unavailable(err: &g2_storage::StorageError) -> Response {
    tracing::error!(error = %err, "admin key operation failed against storage");
    error_response(StatusCode::SERVICE_UNAVAILABLE, "key storage unavailable")
}

/// `POST /g2/keys` — create a session under a freshly generated key.
///
/// The raw key is returned **only here**; it is stored hashed and cannot be
/// recovered later.
#[utoipa::path(post, path = "/g2/keys", tag = "keys",
    security(("admin_secret" = [])),
    request_body = KeySession,
    responses(
        (status = 201, description = "Created; `key` (raw, shown once) and `key_hash`"),
        (status = 400, description = "Session failed validation"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn create_key(
    State(state): State<AdminState>,
    Json(session): Json<KeySession>,
) -> Response {
    let record = match storable_session(&session) {
        Ok(record) => record,
        Err(resp) => return resp,
    };
    let raw_key = hex::encode(rand::random::<[u8; 32]>());
    let key_hash = hash_key(&raw_key);
    let storage_key = session_storage_key(&session.org_id, &key_hash);
    if let Err(e) = state.storage.set(&storage_key, &record, None).await {
        return storage_unavailable(&e);
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "key": raw_key,
            "key_hash": key_hash,
            "action": "added",
        })),
    )
        .into_response()
}

/// `GET /g2/keys` — list the organization's stored key hashes, sorted.
///
/// Returns `{"keys": ["<hash>", …]}`. Hashes are the only listable handle:
/// raw keys are never stored. Takes an optional `?org_id=`.
#[utoipa::path(get, path = "/g2/keys", tag = "keys",
    security(("admin_secret" = [])),
    params(KeyAddress),
    responses(
        (status = 200, description = "Sorted stored key hashes: `{\"keys\": […]}`"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn list_keys(
    State(state): State<AdminState>,
    Query(addr): Query<KeyAddress>,
) -> Response {
    let prefix = session_key_prefix(addr.org());
    match state.storage.scan_prefix(&prefix).await {
        // scan_prefix returns full storage keys; the hash is the suffix.
        Ok(keys) => {
            let mut hashes: Vec<String> = keys
                .into_iter()
                .filter_map(|k| k.strip_prefix(&prefix).map(str::to_owned))
                .collect();
            hashes.sort_unstable();
            Json(serde_json::json!({ "keys": hashes })).into_response()
        }
        Err(e) => storage_unavailable(&e),
    }
}

/// `PUT /g2/keys/{key}` — create or update the session stored for `key`.
#[utoipa::path(put, path = "/g2/keys/{key}", tag = "keys",
    security(("admin_secret" = [])),
    params(("key" = String, Path, description = "Raw key (or stored hash with `hashed=true`)"), KeyAddress),
    request_body = KeySession,
    responses(
        (status = 200, description = "Stored; `action` is `added` or `modified`"),
        (status = 400, description = "Session failed validation"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn put_key(
    State(state): State<AdminState>,
    Path(key): Path<String>,
    Query(addr): Query<KeyAddress>,
    Json(session): Json<KeySession>,
) -> Response {
    let record = match storable_session(&session) {
        Ok(record) => record,
        Err(resp) => return resp,
    };
    let key_hash = addr.key_hash(&key);
    let storage_key = session_storage_key(&session.org_id, &key_hash);
    let action = match state.storage.get(&storage_key).await {
        Ok(Some(_)) => "modified",
        Ok(None) => "added",
        Err(e) => return storage_unavailable(&e),
    };
    if let Err(e) = state.storage.set(&storage_key, &record, None).await {
        return storage_unavailable(&e);
    }
    Json(serde_json::json!({ "key_hash": key_hash, "action": action })).into_response()
}

/// `GET /g2/keys/{key}` — fetch the session stored for `key`.
#[utoipa::path(get, path = "/g2/keys/{key}", tag = "keys",
    security(("admin_secret" = [])),
    params(("key" = String, Path, description = "Raw key (or stored hash with `hashed=true`)"), KeyAddress),
    responses(
        (status = 200, description = "The stored session", body = KeySession),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 404, description = "No session under this key"),
        (status = 500, description = "Stored record is corrupt"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn get_key(
    State(state): State<AdminState>,
    Path(key): Path<String>,
    Query(addr): Query<KeyAddress>,
) -> Response {
    let key_hash = addr.key_hash(&key);
    let storage_key = session_storage_key(addr.org(), &key_hash);
    let record = match state.storage.get(&storage_key).await {
        Ok(Some(record)) => record,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "key not found"),
        Err(e) => return storage_unavailable(&e),
    };
    match serde_json::from_str::<KeySession>(&record) {
        Ok(session) => Json(session).into_response(),
        Err(e) => {
            tracing::error!(key_hash = %key_hash, error = %e, "stored key session is not valid JSON");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "malformed key session record",
            )
        }
    }
}

/// `DELETE /g2/keys/{key}` — remove the session stored for `key`.
#[utoipa::path(delete, path = "/g2/keys/{key}", tag = "keys",
    security(("admin_secret" = [])),
    params(("key" = String, Path, description = "Raw key (or stored hash with `hashed=true`)"), KeyAddress),
    responses(
        (status = 200, description = "Deleted"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 404, description = "No session under this key"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn delete_key(
    State(state): State<AdminState>,
    Path(key): Path<String>,
    Query(addr): Query<KeyAddress>,
) -> Response {
    let key_hash = addr.key_hash(&key);
    let storage_key = session_storage_key(addr.org(), &key_hash);
    match state.storage.delete(&storage_key).await {
        Ok(true) => Json(serde_json::json!({ "action": "deleted" })).into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "key not found"),
        Err(e) => storage_unavailable(&e),
    }
}
