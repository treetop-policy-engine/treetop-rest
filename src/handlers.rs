use actix_web::{HttpMessage, HttpRequest, HttpResponse, http::header, web};
use futures_util::StreamExt;
use prometheus_client::registry::Registry;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tracing::debug;
use treetop_core::PolicyVersion;
use url::form_urlencoded;
use utoipa::{
    Modify, OpenApi, PartialSchema, ToSchema,
    openapi::{
        Content, Ref, RefOr,
        header::HeaderBuilder,
        path::Operation,
        response::ResponseBuilder,
        schema::{AnyOfBuilder, ObjectBuilder, Schema},
        security::{
            ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme,
        },
    },
};

use crate::build_info::build_info;
use crate::config::{BundleEngineMode, BundleRuntimeConfig, SchemaValidationMode};
use crate::errors::{ErrorResponse, ServiceError};
use crate::metrics;
use crate::models::{
    AuthRequest, AuthorizeBriefResponse, AuthorizeDecisionBrief, AuthorizeDecisionDetailed,
    AuthorizeDetailedResponse, AuthorizeRequest, AuthorizeResponseVariant, BatchResult,
    IndexedResult, PoliciesDownload, PoliciesMetadata, RequestLimits, SchemaDownload,
    StatusResponse, UserPolicies,
};
use crate::parallel::ParallelConfig;
use crate::state::SharedPolicyStore;
use treetop_bundle::{ArchiveLimits, BundleArchive, PreparedEngine, PreparedEvaluationSession};

/// Canonical HTTP path for the generated OpenAPI document.
pub const OPENAPI_JSON_PATH: &str = "/openapi.json";
const UPLOAD_TOKEN_SECURITY_SCHEME: &str = "upload_token";
const ACCESS_TOKEN_SECURITY_SCHEME: &str = "access_token";

fn parse_query_params(req: &HttpRequest) -> (Vec<String>, Vec<String>, Option<String>) {
    let mut groups = Vec::new();
    let mut namespaces = Vec::new();
    let mut format = None;

    for (key, value) in form_urlencoded::parse(req.query_string().as_bytes()) {
        match key.as_ref() {
            "groups" | "groups[]" => groups.push(value.into_owned()),
            "namespaces" | "namespaces[]" => namespaces.push(value.into_owned()),
            "format" => format = Some(value.into_owned()),
            _ => {}
        }
    }

    (groups, namespaces, format)
}

fn should_return_raw_format(format: Option<&str>) -> bool {
    matches!(format, Some(fmt) if fmt.eq_ignore_ascii_case("raw") || fmt.eq_ignore_ascii_case("text"))
}

#[derive(Deserialize, ToSchema)]
struct Upload {
    policies: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SchemaUpload {
    Wrapped { schema: String },
    Raw(serde_json::Value),
}

impl PartialSchema for SchemaUpload {
    fn schema() -> RefOr<Schema> {
        AnyOfBuilder::new()
            .item(
                ObjectBuilder::new()
                    .property("schema", String::schema())
                    .required("schema")
                    .description(Some(
                        "Wrapper containing a Cedar schema encoded as a JSON string",
                    )),
            )
            .item(ObjectBuilder::new().description(Some("Raw Cedar schema JSON document")))
            .description(Some(
                "A Cedar schema supplied as either a JSON wrapper or a raw JSON document",
            ))
            .into()
    }
}

impl ToSchema for SchemaUpload {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRuntimeConfig {
    pub max_batch_size: usize,
    pub max_context_bytes: usize,
    pub max_context_depth: usize,
    pub max_context_keys: usize,
}

impl Default for AuthorizeRuntimeConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 1024,
            max_context_bytes: 16 * 1024,
            max_context_depth: 8,
            max_context_keys: 64,
        }
    }
}

fn check_upload_auth(
    req: &HttpRequest,
    allow_upload: bool,
    token: Option<&str>,
) -> Result<(), ServiceError> {
    if !allow_upload {
        return Err(ServiceError::UploadNotAllowed);
    }

    let Some(expected_token) = token else {
        return Err(ServiceError::UploadTokenNotSet);
    };

    if req
        .headers()
        .get("X-Upload-Token")
        .is_none_or(|h| h.to_str().unwrap_or("") != expected_token)
    {
        return Err(ServiceError::InvalidUploadToken);
    }

    Ok(())
}

/// Configure routes for the service.
pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/livez", web::get().to(livez))
        .route("/readyz", web::get().to(readyz))
        .route(OPENAPI_JSON_PATH, web::get().to(openapi_json))
        .route("/api/v1/status", web::get().to(get_status))
        .route("/api/v1/version", web::get().to(version))
        // New unified endpoint
        .route("/api/v1/authorize", web::post().to(authorize))
        .route("/api/v1/policies", web::get().to(get_policies))
        .route("/api/v1/policies", web::post().to(upload_policies))
        .route("/api/v1/bundle", web::post().to(upload_bundle))
        .route("/api/v1/schema", web::get().to(get_schema))
        .route("/api/v1/schema", web::post().to(upload_schema))
        .route("/api/v1/policies/{user}", web::get().to(list_policies))
        .route("/metrics", web::get().to(metrics));
}

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "Treetop REST API", description = "API for Treetop policy management and evaluation")
    ),
    paths(
        authorize,
        get_policies,
        upload_policies,
        upload_bundle,
        get_schema,
        upload_schema,
        list_policies,
        get_status,
        livez,
        readyz,
        version,
        metrics,
        openapi_json,
    ),
    modifiers(&AdmissionSecurity),
)]
pub struct ApiDoc;

struct AdmissionSecurity;

impl Modify for AdmissionSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_default();
        components.add_security_scheme(
            UPLOAD_TOKEN_SECURITY_SCHEME,
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-Upload-Token",
                "Token printed at startup when uploads are enabled",
            ))),
        );
        components.add_security_scheme(
            ACCESS_TOKEN_SECURITY_SCHEME,
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "Opaque operator-provided Bearer token. Required for /api/v1/** and /metrics only when TREETOP_ACCESS_TOKENS is configured.",
                    ))
                    .build(),
            ),
        );

        for (path, path_item) in &mut openapi.paths.paths {
            if !crate::middleware::is_protected_path(path) {
                continue;
            }

            for operation in operations_mut(path_item) {
                add_admission_responses(operation);
                operation.security = Some(
                    if matches!(
                        operation.operation_id.as_deref(),
                        Some("upload_policies" | "upload_schema" | "upload_bundle")
                    ) {
                        let upload = SecurityRequirement::new(
                            UPLOAD_TOKEN_SECURITY_SCHEME,
                            Vec::<String>::new(),
                        );
                        vec![
                            upload
                                .clone()
                                .add(ACCESS_TOKEN_SECURITY_SCHEME, Vec::<String>::new()),
                            upload,
                        ]
                    } else {
                        vec![
                            SecurityRequirement::new(
                                ACCESS_TOKEN_SECURITY_SCHEME,
                                Vec::<String>::new(),
                            ),
                            SecurityRequirement::default(),
                        ]
                    },
                );
            }
        }
    }
}

fn operations_mut(
    path_item: &mut utoipa::openapi::path::PathItem,
) -> impl Iterator<Item = &mut Operation> {
    [
        &mut path_item.get,
        &mut path_item.put,
        &mut path_item.post,
        &mut path_item.delete,
        &mut path_item.options,
        &mut path_item.head,
        &mut path_item.patch,
        &mut path_item.trace,
    ]
    .into_iter()
    .filter_map(Option::as_mut)
}

fn add_admission_responses(operation: &mut Operation) {
    let error_content = || Content::new(Some(Ref::from_schema_name("ErrorResponse")));
    operation
        .responses
        .responses
        .entry("401".to_owned())
        .or_insert_with(|| {
            ResponseBuilder::new()
                .description("Missing, malformed, or invalid Bearer token")
                .header(
                    "WWW-Authenticate",
                    HeaderBuilder::new()
                        .description(Some("Bearer authentication challenge"))
                        .build(),
                )
                .content("application/json", error_content())
                .build()
                .into()
        });
    operation
        .responses
        .responses
        .entry("403".to_owned())
        .or_insert_with(|| {
            ResponseBuilder::new()
                .description("Client IP is not allowed or cannot be resolved")
                .content("application/json", error_content())
                .build()
                .into()
        });
}

static OPENAPI_DOCUMENT: LazyLock<utoipa::openapi::OpenApi> = LazyLock::new(ApiDoc::openapi);

/// Return the generated document shared by the HTTP endpoint and static export.
pub fn openapi_document() -> &'static utoipa::openapi::OpenApi {
    &OPENAPI_DOCUMENT
}

#[utoipa::path(
        get,
        tag = "Treetop REST API",
        path = "/openapi.json",
        responses(
            (status = 200, description = "OpenAPI specification for the Treetop REST API", content_type = "application/json"),
        ),
    )]
pub async fn openapi_json() -> HttpResponse {
    HttpResponse::Ok().json(openapi_document())
}

fn probe_response(ready: bool) -> HttpResponse {
    let mut response = if ready {
        HttpResponse::Ok()
    } else {
        HttpResponse::ServiceUnavailable()
    };

    response
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .content_type("text/plain; charset=utf-8")
        .body(if ready { "ok\n" } else { "not ready\n" })
}

#[utoipa::path(
        get,
        tag = "Treetop REST API",
        path = "/livez",
        responses(
            (status = 200, description = "Process is live", body = String, content_type = "text/plain"),
        ),
    )]
pub async fn livez() -> HttpResponse {
    probe_response(true)
}

#[utoipa::path(
        get,
        tag = "Treetop REST API",
        path = "/readyz",
        responses(
            (status = 200, description = "Service is ready to accept traffic", body = String, content_type = "text/plain"),
            (status = 503, description = "Service is not ready to accept traffic", body = String, content_type = "text/plain"),
        ),
    )]
pub async fn readyz(store: web::Data<SharedPolicyStore>) -> HttpResponse {
    let ready = store
        .try_read()
        .map(|store| store.configured_sources_loaded())
        .unwrap_or(false);

    probe_response(ready)
}

#[derive(Serialize, ToSchema, Deserialize)]
pub struct Core {
    pub version: String,
    pub cedar: String,
}

#[derive(Serialize, ToSchema, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub core: Core,
    pub policies: PolicyVersion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaVersionInfo>,
}

#[derive(Serialize, ToSchema, Deserialize)]
pub struct SchemaVersionInfo {
    pub hash: String,
    pub loaded_at: String,
}

#[utoipa::path(
        get,
        tag = "Treetop REST API",
        path = "/api/v1/version",
        responses(
            (status = 200, description = "Version information", body = VersionInfo),
        ),
    )]
pub async fn version(
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<VersionInfo>, ServiceError> {
    let build_info = build_info();
    let store = store.read()?;
    let schema = if store.schema.sha256.is_empty() {
        None
    } else {
        Some(SchemaVersionInfo {
            hash: store.schema.sha256.clone(),
            loaded_at: store.schema.timestamp.to_rfc3339(),
        })
    };
    Ok(web::Json(VersionInfo {
        version: build_info.version.clone(),
        core: Core {
            version: build_info.core.clone(),
            cedar: build_info.cedar.to_string(),
        },
        policies: store.engine.current_version(),
        schema,
    }))
}

#[derive(Debug, Clone, Copy)]
enum DetailLevel {
    Brief,
    Full,
}

impl DetailLevel {
    fn from_query(detail: Option<&str>) -> Self {
        match detail {
            Some(d) if d.eq_ignore_ascii_case("full") || d.eq_ignore_ascii_case("detailed") => {
                DetailLevel::Full
            }
            _ => DetailLevel::Brief,
        }
    }
}

fn context_value_depth(value: &treetop_core::AttrValue) -> usize {
    match value {
        treetop_core::AttrValue::Set(xs) => {
            1 + xs.iter().map(context_value_depth).max().unwrap_or(0)
        }
        _ => 1,
    }
}

fn validate_request_context(
    auth_req: &AuthRequest,
    runtime: &AuthorizeRuntimeConfig,
    strict_schema: bool,
    schema_loaded: bool,
) -> Result<(), ServiceError> {
    let Some(context) = auth_req.context.as_ref() else {
        return Ok(());
    };

    if context.len() > runtime.max_context_keys {
        metrics::record_context_validation_failure("too_many_keys");
        return Err(ServiceError::ContextValidationError(format!(
            "context has too many keys: {} > {}",
            context.len(),
            runtime.max_context_keys
        )));
    }

    let bytes = serde_json::to_vec(context)
        .map_err(|e| ServiceError::ContextValidationError(e.to_string()))?
        .len();
    if bytes > runtime.max_context_bytes {
        metrics::record_context_validation_failure("too_many_bytes");
        return Err(ServiceError::ContextValidationError(format!(
            "context payload too large: {} bytes > {} bytes",
            bytes, runtime.max_context_bytes
        )));
    }

    let depth = context.values().map(context_value_depth).max().unwrap_or(0);
    if depth > runtime.max_context_depth {
        metrics::record_context_validation_failure("too_deep");
        return Err(ServiceError::ContextValidationError(format!(
            "context nesting depth too high: {} > {}",
            depth, runtime.max_context_depth
        )));
    }

    if strict_schema && !schema_loaded {
        metrics::record_context_validation_failure("missing_schema_strict");
        return Err(ServiceError::ContextValidationError(
            "context requires an uploaded schema in strict validation mode".to_string(),
        ));
    }
    Ok(())
}

fn to_request_context(
    context: Option<&HashMap<String, treetop_core::AttrValue>>,
) -> Option<treetop_core::RequestContext> {
    let context = context?;
    let mut request_context = treetop_core::RequestContext::new();
    for (key, value) in context {
        request_context.insert(key.clone(), value.clone());
    }
    Some(request_context)
}

/// Evaluate a single authorization request and produce an indexed result.
fn eval_one<T, F>(
    index: usize,
    auth_req: &AuthRequest,
    engine_snapshot: &PreparedEvaluationSession,
    runtime: &AuthorizeRuntimeConfig,
    strict_schema: bool,
    schema_loaded: bool,
    map_fn: &F,
) -> IndexedResult<T>
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    if let Err(e) = validate_request_context(auth_req, runtime, strict_schema, schema_loaded) {
        return IndexedResult::new(
            index,
            auth_req.id.clone(),
            BatchResult::Failed {
                message: e.to_string(),
            },
        );
    }

    let request_context = to_request_context(auth_req.context.as_ref());
    let evaluation = match request_context.as_ref() {
        Some(context) => engine_snapshot.evaluate_with_context(&auth_req.request, context),
        None => engine_snapshot.evaluate(&auth_req.request),
    };
    let result = match evaluation {
        Ok(decision) => BatchResult::Success {
            data: map_fn(decision),
        },
        Err(e) => BatchResult::Failed {
            message: e.to_string(),
        },
    };
    IndexedResult::new(index, auth_req.id.clone(), result)
}

/// Generic helper to evaluate batch requests and return results with counts
fn evaluate_batch_requests<T, F>(
    requests: &[AuthRequest],
    engine_snapshot: &PreparedEvaluationSession,
    parallel: &ParallelConfig,
    runtime: &AuthorizeRuntimeConfig,
    strict_schema: bool,
    schema_loaded: bool,
    map_fn: F,
) -> (Vec<IndexedResult<T>>, usize, usize)
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    let use_parallel = parallel.allow_parallel && requests.len() >= parallel.par_threshold;

    let (results, successful) = if use_parallel {
        let results: Vec<IndexedResult<T>> = requests
            .par_iter()
            .with_min_len(parallel.par_threshold)
            .enumerate()
            .map(|(index, auth_req)| {
                eval_one(
                    index,
                    auth_req,
                    engine_snapshot,
                    runtime,
                    strict_schema,
                    schema_loaded,
                    &map_fn,
                )
            })
            .collect();
        // Count successes in the collected results
        let successful = results
            .iter()
            .filter(|r| matches!(r.result(), BatchResult::Success { .. }))
            .count();
        (results, successful)
    } else {
        let mut results = Vec::with_capacity(requests.len());
        let mut successful = 0;
        for (index, auth_req) in requests.iter().enumerate() {
            let result = eval_one(
                index,
                auth_req,
                engine_snapshot,
                runtime,
                strict_schema,
                schema_loaded,
                &map_fn,
            );
            if matches!(result.result(), BatchResult::Success { .. }) {
                successful += 1;
            }
            results.push(result);
        }
        (results, successful)
    };
    let failed = results.len() - successful;

    (results, successful, failed)
}

#[doc(hidden)]
pub fn evaluate_batch_requests_for_bench<T, F>(
    requests: &[AuthRequest],
    engine_snapshot: &std::sync::Arc<PreparedEngine>,
    parallel: &ParallelConfig,
    map_fn: F,
) -> (Vec<IndexedResult<T>>, usize, usize)
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    evaluate_batch_requests(
        requests,
        &engine_snapshot.session(),
        parallel,
        &AuthorizeRuntimeConfig::default(),
        false,
        false,
        map_fn,
    )
}

#[derive(serde::Deserialize)]
pub struct AuthorizeQuery {
    /// Response detail level: 'brief' (default) or 'full'
    detail: Option<String>,
}

#[utoipa::path(
        post,
        tag = "Treetop REST API",
        path = "/api/v1/authorize",
        request_body(
            content = AuthorizeRequest,
            description = "Authorization checks, limited by the configured maximum batch size"
        ),
        params(
            ("detail" = Option<String>, Query, description = "Response detail level: 'brief' (default) or 'full'"),
        ),
        responses(
            (status = 200, description = "Authorize performed successfully", body = AuthorizeResponseVariant),
            (status = 400, description = "Bad request", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        ),
    )]
pub async fn authorize(
    http_req: HttpRequest,
    store: web::Data<SharedPolicyStore>,
    parallel: web::Data<ParallelConfig>,
    runtime_cfg: Option<web::Data<AuthorizeRuntimeConfig>>,
    query: web::Query<AuthorizeQuery>,
    req: web::Json<AuthorizeRequest>,
) -> Result<web::Json<AuthorizeResponseVariant>, ServiceError> {
    let runtime_cfg = runtime_cfg.map(|cfg| *cfg.get_ref()).unwrap_or_default();
    if req.requests.len() > runtime_cfg.max_batch_size {
        return Err(ServiceError::ValidationError(format!(
            "authorization batch has too many requests: {} > {}",
            req.requests.len(),
            runtime_cfg.max_batch_size
        )));
    }
    http_req
        .extensions_mut()
        .insert(metrics::AcceptedAuthorizationBatch::new(req.requests.len()));

    let store = store.read()?;
    let engine_snapshot = store.engine.session();
    let version = engine_snapshot.version();
    let strict_schema = store.schema_validation_mode == SchemaValidationMode::Strict;
    let schema_loaded = !store.schema.content.is_empty();

    // Release the lock before parallel processing
    drop(store);

    let detail_level = DetailLevel::from_query(query.detail.as_deref());

    match detail_level {
        DetailLevel::Full => {
            let (results, successful, failed) = evaluate_batch_requests(
                &req.requests,
                &engine_snapshot,
                &parallel,
                &runtime_cfg,
                strict_schema,
                schema_loaded,
                AuthorizeDecisionDetailed::from,
            );

            Ok(web::Json(AuthorizeResponseVariant::Detailed(
                AuthorizeDetailedResponse::new(results, version, successful, failed),
            )))
        }
        DetailLevel::Brief => {
            let (results, successful, failed) = evaluate_batch_requests(
                &req.requests,
                &engine_snapshot,
                &parallel,
                &runtime_cfg,
                strict_schema,
                schema_loaded,
                AuthorizeDecisionBrief::from,
            );

            Ok(web::Json(AuthorizeResponseVariant::Brief(
                AuthorizeBriefResponse::new(results, version, successful, failed),
            )))
        }
    }
}

#[utoipa::path(
        get,
        tag = "Treetop REST API",
        path = "/api/v1/policies",
        params(
            ("format" = Option<String>, Query, description = "Response format: 'json' (default) or 'raw'/'text' for plain text"),
        ),
        responses(
            (status = 200, description = "Policies retrieved successfully", content(
                (PoliciesDownload = "application/json"),
                (String = "text/plain")
            )),
            (status = 400, description = "Bad request", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        ),
    )]
pub async fn get_policies(
    query: web::Query<HashMap<String, String>>,
    store: web::Data<SharedPolicyStore>,
) -> Result<HttpResponse, ServiceError> {
    let format = query.get("format").map(String::as_str);
    let store = store.read()?;

    if should_return_raw_format(format) {
        Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(store.policies.content.clone()))
    } else {
        Ok(HttpResponse::Ok().json(PoliciesDownload {
            policies: store.policies.clone(),
        }))
    }
}

#[utoipa::path(
        post,
        tag = "Treetop REST API",
        path = "/api/v1/policies",
        request_body(
            description = "Cedar policies as a JSON wrapper or plain Cedar text",
            content(
                (Upload = "application/json"),
                (String = "text/plain")
            )
        ),
        security(("upload_token" = [])),
        responses(
            (status = 200, description = "Policies uploaded successfully", body = PoliciesMetadata),
            (status = 400, description = "Bad request", body = ErrorResponse),
            (status = 403, description = "Client admission failed, uploads are disabled, or the upload token is invalid", body = ErrorResponse),
            (status = 409, description = "Independent uploads are disabled while bundle URL mode is active", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        ),
    )]
pub async fn upload_policies(
    req: HttpRequest,
    body: web::Bytes,
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    // Reject unauthorized requests before parsing or copying the buffered request body.
    {
        let guard = store.read()?;
        check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;
        if guard.bundle_url_mode {
            return Err(ServiceError::BundleModeConflict);
        }
    }

    let content_type = req.content_type();
    let dsl_string = if content_type.starts_with("application/json") {
        let upload: Upload = serde_json::from_slice(&body)?;
        upload.policies
    } else {
        String::from_utf8(body.to_vec()).map_err(|_| ServiceError::InvalidTextPayload)?
    };

    if dsl_string.is_empty() {
        return Err(ServiceError::InvalidTextPayload);
    }

    let mut guard = store.write()?;
    // Recheck under the write lock so configuration cannot change between parsing and applying.
    check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;
    if guard.bundle_url_mode {
        return Err(ServiceError::BundleModeConflict);
    }

    guard.set_dsl(&dsl_string, None, None)?;

    Ok(web::Json((&*guard).into()))
}

#[utoipa::path(
    post,
    tag = "Treetop REST API",
    path = "/api/v1/bundle",
    request_body(
        description = "A gzip-compressed Treetop bundle archive",
        content(
            (String = "application/gzip"),
            (String = "application/x-gzip")
        )
    ),
    security(("upload_token" = [])),
    responses(
        (status = 200, description = "Bundle verified and atomically applied", body = PoliciesMetadata),
        (status = 400, description = "Invalid archive, signature, policy, schema, or labels", body = ErrorResponse),
        (status = 403, description = "Client admission failed, uploads are disabled, or the upload token is invalid", body = ErrorResponse),
        (status = 413, description = "Compressed bundle exceeds the bundle or global request-size limit", body = ErrorResponse),
        (status = 415, description = "Unsupported media type", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
pub async fn upload_bundle(
    req: HttpRequest,
    mut payload: web::Payload,
    store: web::Data<SharedPolicyStore>,
    runtime: web::Data<BundleRuntimeConfig>,
    configured_engine_mode: Option<web::Data<BundleEngineMode>>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    // Authentication is deliberately checked before the request body is polled.
    let (allow_upload, schema_validation_mode) = {
        let guard = store.read()?;
        check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;
        (guard.allow_upload, guard.schema_validation_mode)
    };
    if !matches!(
        req.content_type(),
        "application/gzip" | "application/x-gzip"
    ) {
        return Err(ServiceError::UnsupportedBundleMediaType);
    }

    let upload_limit = runtime.max_compressed_bytes.min(runtime.max_request_bytes);
    let declared_size = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared_size.is_some_and(|size| size > upload_limit) {
        metrics::record_bundle_failure(metrics::BundleFailureReason::SizeLimit);
        return Err(ServiceError::BundleTooLarge(format!(
            "compressed bundle exceeds {} bytes",
            upload_limit
        )));
    }

    let mut bytes = Vec::with_capacity(declared_size.unwrap_or_default());
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|error| ServiceError::InvalidBundle(error.to_string()))?;
        if bytes.len().saturating_add(chunk.len()) > upload_limit {
            metrics::record_bundle_failure(metrics::BundleFailureReason::SizeLimit);
            return Err(ServiceError::BundleTooLarge(format!(
                "compressed bundle exceeds {} bytes",
                upload_limit
            )));
        }
        bytes.extend_from_slice(&chunk);
    }

    let limits = ArchiveLimits::new(runtime.max_compressed_bytes, runtime.max_uncompressed_bytes)?;
    let signature_policy = runtime.signature_policy;
    let engine_mode = configured_engine_mode.map_or(BundleEngineMode::Monolithic, |mode| **mode);
    let trust_store = runtime.trust_store.clone();
    let (prepared, mut response, bundle_id, signing_key_id) = web::block(move || {
        let archive = BundleArchive::from_bytes(bytes);
        let validated = archive
            .validate(signature_policy, &trust_store, limits)
            .map_err(|error| {
                metrics::record_bundle_failure(crate::fetcher::reason_for_bundle_error(&error));
                ServiceError::from(error)
            })?;
        let bundle_id = validated.bundle_id().to_owned();
        let signing_key_id = validated
            .verified_signature()
            .key_id()
            .map(ToOwned::to_owned);
        let prepared = crate::state::PolicyStore::prepare_bundle_with_engine_mode(
            &validated,
            None,
            None,
            schema_validation_mode,
            engine_mode,
        )
        .inspect_err(|_| {
            metrics::record_bundle_failure(metrics::BundleFailureReason::Validation);
        })?;
        let response = prepared.metadata(allow_upload, schema_validation_mode);
        Ok::<_, ServiceError>((prepared, response, bundle_id, signing_key_id))
    })
    .await
    .map_err(|error| {
        ServiceError::EvaluationError(format!("bundle preparation task failed: {error}"))
    })??;

    let mut guard = store.write()?;
    check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;
    response.allow_upload = guard.allow_upload;
    response.schema_validation_mode = guard.schema_validation_mode.to_string();
    guard.apply_prepared_bundle(prepared).inspect_err(|error| {
        let reason = if matches!(error, ServiceError::SchemaValidationError(_)) {
            metrics::BundleFailureReason::Validation
        } else {
            metrics::BundleFailureReason::Store
        };
        metrics::record_bundle_failure(reason);
    })?;
    drop(guard);
    metrics::record_bundle_reload();
    debug!(
        message = "uploaded bundle applied",
        bundle_id,
        engine_mode = %engine_mode,
        key_id = signing_key_id.as_deref()
    );
    Ok(web::Json(response))
}

#[utoipa::path(
        get,
        tag = "Treetop REST API",
        path = "/api/v1/schema",
        params(
            ("format" = Option<String>, Query, description = "Response format: 'json' (default) or 'raw'/'text' for plain text"),
        ),
        responses(
            (status = 200, description = "Schema retrieved successfully", content(
                (SchemaDownload = "application/json"),
                (String = "text/plain")
            )),
            (status = 400, description = "Bad request", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        ),
    )]
pub async fn get_schema(
    query: web::Query<HashMap<String, String>>,
    store: web::Data<SharedPolicyStore>,
) -> Result<HttpResponse, ServiceError> {
    let format = query.get("format").map(String::as_str);
    let store = store.read()?;

    if should_return_raw_format(format) {
        Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(store.schema.content.clone()))
    } else {
        Ok(HttpResponse::Ok().json(SchemaDownload {
            schema: store.schema.clone(),
        }))
    }
}

#[utoipa::path(
        post,
        tag = "Treetop REST API",
        path = "/api/v1/schema",
        request_body(
            description = "Cedar schema as a JSON wrapper, raw JSON document, or plain text",
            content(
                (SchemaUpload = "application/json"),
                (String = "text/plain")
            )
        ),
        security(("upload_token" = [])),
        responses(
            (status = 200, description = "Schema uploaded successfully", body = PoliciesMetadata),
            (status = 400, description = "Bad request", body = ErrorResponse),
            (status = 403, description = "Client admission failed, uploads are disabled, or the upload token is invalid", body = ErrorResponse),
            (status = 409, description = "Independent uploads are disabled while bundle URL mode is active", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        ),
    )]
pub async fn upload_schema(
    req: HttpRequest,
    body: web::Bytes,
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    // Reject unauthorized requests before parsing or copying the buffered request body.
    {
        let guard = store.read()?;
        check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;
        if guard.bundle_url_mode {
            return Err(ServiceError::BundleModeConflict);
        }
    }

    let content_type = req.content_type();
    let schema_string = if content_type.starts_with("application/json") {
        match serde_json::from_slice::<SchemaUpload>(&body)? {
            SchemaUpload::Wrapped { schema } => schema,
            SchemaUpload::Raw(value) => serde_json::to_string(&value)
                .map_err(|e| ServiceError::InvalidJsonPayload(e.to_string()))?,
        }
    } else {
        String::from_utf8(body.to_vec()).map_err(|_| ServiceError::InvalidTextPayload)?
    };

    if schema_string.trim().is_empty() {
        return Err(ServiceError::InvalidTextPayload);
    }

    let mut guard = store.write()?;
    // Recheck under the write lock so configuration cannot change between parsing and applying.
    check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;
    if guard.bundle_url_mode {
        return Err(ServiceError::BundleModeConflict);
    }
    guard.set_schema(&schema_string, None, None)?;

    Ok(web::Json((&*guard).into()))
}

#[utoipa::path(
        get,
        tag = "Treetop REST API",
        path = "/api/v1/policies/{user}",
        params(
            ("user" = String, Path, description = "User principal identifier"),
            ("groups" = Option<Vec<String>>, Query, description = "List of group names"),
            ("namespaces" = Option<Vec<String>>, Query, description = "List of namespaces"),
            ("format" = Option<String>, Query, description = "Response format: 'json' (default) or 'raw'/'text' for plain text"),
        ),
        responses(
            (status = 200, description = "Policies for user retrieved successfully", content(
                (UserPolicies = "application/json"),
                (String = "text/plain")
            )),
            (status = 400, description = "Bad request", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        ),
    )]
pub async fn list_policies(
    store: web::Data<SharedPolicyStore>,
    user: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    let store = store.read()?;

    // User path parameter is just the entity ID
    let entity_id = user.into_inner();

    // Use namespace and groups from query parameters
    let (groups, namespaces, format) = parse_query_params(&req);

    debug!(message = "Listing policies for user", entity = %entity_id, namespaces = ?namespaces, groups = ?groups);

    // Check format query parameter
    if should_return_raw_format(format.as_deref()) {
        let content: std::sync::Arc<String> =
            store.list_policies_raw(entity_id, groups, namespaces)?;
        // Clone the Arc (cheap pointer copy), then clone the String for response
        return Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body((*content).clone()));
    }

    // Default: return as JSON
    let response: std::sync::Arc<UserPolicies> =
        store.list_policies_json(entity_id, groups, namespaces)?;
    Ok(HttpResponse::Ok().json(response.as_ref()))
}

#[utoipa::path(
    get,
    tag = "Treetop REST API",
    path = "/api/v1/status",
    responses(
        (status = 200, description = "Service status retrieved successfully", body = StatusResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
pub async fn get_status(
    store: web::Data<SharedPolicyStore>,
    parallel: web::Data<ParallelConfig>,
    runtime_cfg: Option<web::Data<AuthorizeRuntimeConfig>>,
) -> Result<web::Json<StatusResponse>, ServiceError> {
    let store = store.read()?;
    let runtime_cfg = runtime_cfg.map(|cfg| *cfg.get_ref()).unwrap_or_default();
    let request_limits = RequestLimits {
        max_batch_size: runtime_cfg.max_batch_size,
        max_context_bytes: runtime_cfg.max_context_bytes,
        max_context_depth: runtime_cfg.max_context_depth,
        max_context_keys: runtime_cfg.max_context_keys,
    };
    let policy_configuration: PoliciesMetadata = (&*store).into();
    let status = StatusResponse {
        policy_configuration,
        parallel_configuration: *parallel.get_ref(),
        request_limits,
        request_context: store.request_context_status,
    };

    Ok(web::Json(status))
}

#[utoipa::path(
    get,
    tag = "Treetop REST API",
    path = "/metrics",
    responses(
        (status = 200, description = "OpenMetrics text, including authorization batch-size metrics, or Prometheus protobuf containing HTTP, authorization, and policy-evaluation native histograms when requested by Accept", content(
            (String = "application/openmetrics-text"),
            (String = "application/vnd.google.protobuf")
        )),
    ),
)]
pub async fn metrics(
    req: HttpRequest,
    registry: web::Data<Arc<Registry>>,
) -> Result<HttpResponse, ServiceError> {
    if accepts_prometheus_protobuf(&req) {
        crate::metrics::encode_registry_protobuf(&registry)
            .map(|body| {
                HttpResponse::Ok()
                    .content_type(crate::metrics::PROMETHEUS_PROTOBUF_CONTENT_TYPE)
                    .body(body)
            })
            .map_err(|error| ServiceError::EvaluationError(error.to_string()))
    } else {
        crate::metrics::encode_registry_text(&registry)
            .map(|body| {
                HttpResponse::Ok()
                    .content_type(crate::metrics::OPENMETRICS_CONTENT_TYPE)
                    .body(body)
            })
            .map_err(|error| ServiceError::EvaluationError(error.to_string()))
    }
}

fn accepts_prometheus_protobuf(req: &HttpRequest) -> bool {
    req.headers()
        .get_all(header::ACCEPT)
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|media_range| {
            let mut parts = media_range.split(';').map(str::trim);
            if !parts.next().is_some_and(|media_type| {
                media_type.eq_ignore_ascii_case("application/vnd.google.protobuf")
            }) {
                return false;
            }

            let mut prometheus_metric_family = false;
            let mut delimited = false;
            let mut enabled = true;

            for parameter in parts {
                let Some((name, value)) = parameter.split_once('=') else {
                    continue;
                };
                let value = value.trim().trim_matches('"');
                match name.trim().to_ascii_lowercase().as_str() {
                    "proto" => {
                        prometheus_metric_family = value == "io.prometheus.client.MetricFamily";
                    }
                    "encoding" => delimited = value.eq_ignore_ascii_case("delimited"),
                    "q" => enabled = value.parse::<f32>().is_ok_and(|quality| quality > 0.0),
                    _ => {}
                }
            }

            enabled && prometheus_metric_family && delimited
        })
}
