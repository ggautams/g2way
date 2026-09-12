//! Generic CRUD for storage-backed configuration resources.
//!
//! API definitions (`/g2/apis`) and policies (`/g2/policies`) are both
//! JSON records stored under a deterministic per-org key (ADR-0002),
//! addressed by their own id.
//! One set of generic handlers serves both; [`StoredResource`] supplies the
//! per-type key schema and validation.
//!
//! **Mutations do not touch the running route table.** A create/
//! update/delete becomes live only when the gateway reloads (`POST
//! /g2/reload`, or startup).
//!
//! Responses: `GET` returns the stored record (list on the collection
//! route), mutations return `{"id": …, "action": "added"|"modified"|
//! "deleted"}`. Invalid bodies are `400` with the validation reason, a
//! `POST` of an existing id is `409` (use `PUT` to update), a `PUT` whose
//! body id disagrees with the path is `400`, and unknown ids are `404`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use g2_core::{ApiDefinition, Policy};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{error_response, AdminState};

/// A configuration record the generic CRUD handlers can manage.
pub(crate) trait StoredResource: Serialize + DeserializeOwned + Send + 'static {
    /// Human-readable kind for log and error messages ("API definition").
    const KIND: &'static str;

    /// The resource's own identifier (`api_id` / `policy_id`).
    fn id(&self) -> &str;

    /// The owning organization.
    fn org_id(&self) -> &str;

    /// Storage key for the record with `id` in `org_id`.
    fn storage_key(org_id: &str, id: &str) -> String;

    /// Prefix under which every record of this kind in `org_id` lives.
    fn key_prefix(org_id: &str) -> String;

    /// Semantic validation, run before every write.
    fn validate(&self) -> Result<(), g2_core::Error>;
}

impl StoredResource for ApiDefinition {
    const KIND: &'static str = "API definition";

    fn id(&self) -> &str {
        &self.api_id
    }
    fn org_id(&self) -> &str {
        &self.org_id
    }
    fn storage_key(org_id: &str, id: &str) -> String {
        g2_core::api_definition::api_definition_storage_key(org_id, id)
    }
    fn key_prefix(org_id: &str) -> String {
        g2_core::api_definition::api_definition_key_prefix(org_id)
    }
    fn validate(&self) -> Result<(), g2_core::Error> {
        self.validate()
    }
}

impl StoredResource for Policy {
    const KIND: &'static str = "policy";

    fn id(&self) -> &str {
        &self.policy_id
    }
    fn org_id(&self) -> &str {
        &self.org_id
    }
    fn storage_key(org_id: &str, id: &str) -> String {
        g2_core::policy::policy_storage_key(org_id, id)
    }
    fn key_prefix(org_id: &str) -> String {
        g2_core::policy::policy_key_prefix(org_id)
    }
    fn validate(&self) -> Result<(), g2_core::Error> {
        self.validate()
    }
}

/// Optional `?org_id=` on `GET`/`DELETE` routes (mutating routes read the
/// organization from the resource body). Defaults to the single-org default.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct OrgQuery {
    org_id: Option<String>,
}

impl OrgQuery {
    fn org(&self) -> &str {
        self.org_id.as_deref().unwrap_or(g2_core::DEFAULT_ORG_ID)
    }
}

/// Validates and serializes a resource for storage, or the ready-to-send
/// 400 for an invalid one.
// The large Err is a rejection Response built once on the cold path; boxing
// it would just move the allocation.
#[allow(clippy::result_large_err)]
fn storable<R: StoredResource>(resource: &R) -> Result<String, Response> {
    resource
        .validate()
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(serde_json::to_string(resource).expect("resource always serializes"))
}

/// Maps a storage failure to the ready-to-send 503.
fn storage_unavailable(kind: &str, err: &g2_storage::StorageError) -> Response {
    tracing::error!(kind, error = %err, "admin resource operation failed against storage");
    error_response(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
}

/// The 500 for a stored record that no longer parses as its type.
fn corrupt_record(kind: &str, storage_key: &str, err: &serde_json::Error) -> Response {
    tracing::error!(kind, storage_key, error = %err, "stored record is not valid JSON");
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "malformed stored record")
}

/// `GET /g2/{collection}` — every record of this kind in the organization,
/// sorted by id.
pub(crate) async fn list<R: StoredResource>(
    State(state): State<AdminState>,
    Query(query): Query<OrgQuery>,
) -> Response {
    let keys = match state.storage.scan_prefix(&R::key_prefix(query.org())).await {
        Ok(keys) => keys,
        Err(e) => return storage_unavailable(R::KIND, &e),
    };
    let mut resources = Vec::with_capacity(keys.len());
    for key in keys {
        // A record deleted between scan and read is simply not listed.
        let record = match state.storage.get(&key).await {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(e) => return storage_unavailable(R::KIND, &e),
        };
        match serde_json::from_str::<R>(&record) {
            Ok(resource) => resources.push(resource),
            Err(e) => return corrupt_record(R::KIND, &key, &e),
        }
    }
    resources.sort_by(|a, b| a.id().cmp(b.id()));
    Json(resources).into_response()
}

/// `GET /g2/{collection}/{id}` — one record.
pub(crate) async fn get<R: StoredResource>(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(query): Query<OrgQuery>,
) -> Response {
    let storage_key = R::storage_key(query.org(), &id);
    let record = match state.storage.get(&storage_key).await {
        Ok(Some(record)) => record,
        Ok(None) => return not_found(R::KIND),
        Err(e) => return storage_unavailable(R::KIND, &e),
    };
    match serde_json::from_str::<R>(&record) {
        Ok(resource) => Json(resource).into_response(),
        Err(e) => corrupt_record(R::KIND, &storage_key, &e),
    }
}

/// `POST /g2/{collection}` — create a record; the id comes from the body.
///
/// Creating an id that already exists is a `409`: an accidental double-POST
/// must not silently overwrite (that is what `PUT` is for).
pub(crate) async fn create<R: StoredResource>(
    State(state): State<AdminState>,
    Json(resource): Json<R>,
) -> Response {
    let record = match storable(&resource) {
        Ok(record) => record,
        Err(resp) => return resp,
    };
    let storage_key = R::storage_key(resource.org_id(), resource.id());
    match state.storage.get(&storage_key).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                &format!(
                    "{} `{}` already exists; use PUT to update",
                    R::KIND,
                    resource.id()
                ),
            );
        }
        Err(e) => return storage_unavailable(R::KIND, &e),
    }
    if let Err(e) = state.storage.set(&storage_key, &record, None).await {
        return storage_unavailable(R::KIND, &e);
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": resource.id(), "action": "added" })),
    )
        .into_response()
}

/// `PUT /g2/{collection}/{id}` — create or update the record at `id`.
///
/// The body's own id must equal the path id: a mismatch is always a typo,
/// and honoring either one silently would misfile the record.
pub(crate) async fn put<R: StoredResource>(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(resource): Json<R>,
) -> Response {
    if resource.id() != id {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("body id `{}` does not match path id `{id}`", resource.id()),
        );
    }
    let record = match storable(&resource) {
        Ok(record) => record,
        Err(resp) => return resp,
    };
    let storage_key = R::storage_key(resource.org_id(), resource.id());
    let action = match state.storage.get(&storage_key).await {
        Ok(Some(_)) => "modified",
        Ok(None) => "added",
        Err(e) => return storage_unavailable(R::KIND, &e),
    };
    if let Err(e) = state.storage.set(&storage_key, &record, None).await {
        return storage_unavailable(R::KIND, &e);
    }
    Json(serde_json::json!({ "id": resource.id(), "action": action })).into_response()
}

/// `DELETE /g2/{collection}/{id}` — remove the record at `id`.
pub(crate) async fn delete<R: StoredResource>(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(query): Query<OrgQuery>,
) -> Response {
    match state
        .storage
        .delete(&R::storage_key(query.org(), &id))
        .await
    {
        Ok(true) => Json(serde_json::json!({ "id": id, "action": "deleted" })).into_response(),
        Ok(false) => not_found(R::KIND),
        Err(e) => storage_unavailable(R::KIND, &e),
    }
}

fn not_found(kind: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, &format!("{kind} not found"))
}

// Concrete, OpenAPI-documented bindings of the generic handlers — one per
// route the router mounts. utoipa's `#[utoipa::path]` describes exactly one
// path, so generic handlers cannot carry the annotation themselves.

#[utoipa::path(get, path = "/g2/apis", tag = "apis",
    security(("admin_secret" = [])), params(OrgQuery),
    responses(
        (status = 200, description = "Every stored API definition, sorted by id", body = Vec<ApiDefinition>),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn list_apis(state: State<AdminState>, query: Query<OrgQuery>) -> Response {
    list::<ApiDefinition>(state, query).await
}

#[utoipa::path(post, path = "/g2/apis", tag = "apis",
    security(("admin_secret" = [])), request_body = ApiDefinition,
    responses(
        (status = 201, description = "Created (live after the next reload)"),
        (status = 400, description = "Definition failed validation"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 409, description = "api_id already exists; use PUT to update"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn create_api(state: State<AdminState>, body: Json<ApiDefinition>) -> Response {
    create::<ApiDefinition>(state, body).await
}

#[utoipa::path(get, path = "/g2/apis/{id}", tag = "apis",
    security(("admin_secret" = [])),
    params(("id" = String, Path, description = "The api_id"), OrgQuery),
    responses(
        (status = 200, description = "The stored definition", body = ApiDefinition),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 404, description = "No definition under this id"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn get_api(
    state: State<AdminState>,
    id: Path<String>,
    query: Query<OrgQuery>,
) -> Response {
    get::<ApiDefinition>(state, id, query).await
}

#[utoipa::path(put, path = "/g2/apis/{id}", tag = "apis",
    security(("admin_secret" = [])),
    params(("id" = String, Path, description = "The api_id; must equal the body's api_id")),
    request_body = ApiDefinition,
    responses(
        (status = 200, description = "Stored; `action` is `added` or `modified` (live after the next reload)"),
        (status = 400, description = "Validation failed or body id disagrees with path id"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn put_api(
    state: State<AdminState>,
    id: Path<String>,
    body: Json<ApiDefinition>,
) -> Response {
    put::<ApiDefinition>(state, id, body).await
}

#[utoipa::path(delete, path = "/g2/apis/{id}", tag = "apis",
    security(("admin_secret" = [])),
    params(("id" = String, Path, description = "The api_id"), OrgQuery),
    responses(
        (status = 200, description = "Deleted (unrouted after the next reload)"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 404, description = "No definition under this id"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn delete_api(
    state: State<AdminState>,
    id: Path<String>,
    query: Query<OrgQuery>,
) -> Response {
    delete::<ApiDefinition>(state, id, query).await
}

#[utoipa::path(get, path = "/g2/policies", tag = "policies",
    security(("admin_secret" = [])), params(OrgQuery),
    responses(
        (status = 200, description = "Every stored policy, sorted by id", body = Vec<Policy>),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn list_policies(state: State<AdminState>, query: Query<OrgQuery>) -> Response {
    list::<Policy>(state, query).await
}

#[utoipa::path(post, path = "/g2/policies", tag = "policies",
    security(("admin_secret" = [])), request_body = Policy,
    responses(
        (status = 201, description = "Created"),
        (status = 400, description = "Policy failed validation"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 409, description = "policy_id already exists; use PUT to update"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn create_policy(state: State<AdminState>, body: Json<Policy>) -> Response {
    create::<Policy>(state, body).await
}

#[utoipa::path(get, path = "/g2/policies/{id}", tag = "policies",
    security(("admin_secret" = [])),
    params(("id" = String, Path, description = "The policy_id"), OrgQuery),
    responses(
        (status = 200, description = "The stored policy", body = Policy),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 404, description = "No policy under this id"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn get_policy(
    state: State<AdminState>,
    id: Path<String>,
    query: Query<OrgQuery>,
) -> Response {
    get::<Policy>(state, id, query).await
}

#[utoipa::path(put, path = "/g2/policies/{id}", tag = "policies",
    security(("admin_secret" = [])),
    params(("id" = String, Path, description = "The policy_id; must equal the body's policy_id")),
    request_body = Policy,
    responses(
        (status = 200, description = "Stored; `action` is `added` or `modified`"),
        (status = 400, description = "Validation failed or body id disagrees with path id"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn put_policy(
    state: State<AdminState>,
    id: Path<String>,
    body: Json<Policy>,
) -> Response {
    put::<Policy>(state, id, body).await
}

#[utoipa::path(delete, path = "/g2/policies/{id}", tag = "policies",
    security(("admin_secret" = [])),
    params(("id" = String, Path, description = "The policy_id"), OrgQuery),
    responses(
        (status = 200, description = "Deleted"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 404, description = "No policy under this id"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
pub(crate) async fn delete_policy(
    state: State<AdminState>,
    id: Path<String>,
    query: Query<OrgQuery>,
) -> Response {
    delete::<Policy>(state, id, query).await
}
