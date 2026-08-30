use actix_web::{App, HttpServer, middleware::Condition};
use clap::Parser;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use treetop_bundle::ArchiveLimits;
use treetop_rest::build_info::build_info;
use treetop_rest::config::{AdmissionConfig, Config};
use treetop_rest::fetcher::{
    BundleFetcher, LabelFetchAdapter, PolicyFetchAdapter, SchemaFetchAdapter,
};
use treetop_rest::handlers::{AuthorizeRuntimeConfig, OPENAPI_JSON_PATH};
use treetop_rest::middleware::{AccessControlMiddleware, TracingMiddleware};
use treetop_rest::state::PolicyStore;

use utoipa_swagger_ui::{Config as SwaggerUiConfig, SwaggerUi};

fn swagger_ui() -> SwaggerUi {
    SwaggerUi::new("/swagger-ui/{_:.*}").config(SwaggerUiConfig::new([OPENAPI_JSON_PATH]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .with_current_span(true)
        .init();

    let config = Config::parse();

    if config.version {
        println!(
            "Treetop REST API version: {} (core: {}, cedar: {})",
            build_info().version,
            build_info().core,
            build_info().cedar
        );
        return Ok(());
    }

    let bundle_runtime = config.bundle_runtime_config().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid bundle configuration: {error}"),
        )
    })?;
    let bundle_engine_mode = config.bundle_engine_mode;

    let admission = AdmissionConfig::from_env().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid admission configuration: {error}"),
        )
    })?;
    info!(
        message = "Admission controls configured",
        acl_enabled = admission.has_acl(),
        access_token_count = admission.access_tokens.len(),
        trusted_proxy_count = admission.trusted_proxies.len(),
    );

    let parallel_config = treetop_rest::parallel::init_parallelism(
        config.workers,
        config.rayon_threads,
        config.par_threshold,
    );

    info!(
        message = "Scale out config",
        cpu_count = parallel_config.cpu_count,
        actix_workers = parallel_config.workers,
        rayon_threads = parallel_config.rayon_threads,
        parallel_threshold = parallel_config.par_threshold,
        allow_parallel = parallel_config.allow_parallel
    );

    // Initialize Prometheus metrics and set treetop-core sink
    let metrics_registry =
        treetop_rest::metrics::init_prometheus().expect("Failed to init metrics");

    let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));

    info!(
        message = "Initializing server",
        version = build_info().version,
        core = build_info().core,
        cedar = build_info().cedar
    );

    if config.allow_upload {
        store.write().unwrap().allow_upload = true;
        let token = uuid::Uuid::new_v4().to_string();
        warn!(message = "Uploads enabled", token = token);
        store.write().unwrap().upload_token = Some(token);
    }
    store
        .write()
        .unwrap()
        .set_schema_validation_mode(config.schema_validation_mode);

    if let Some(url) = config.policy_url.clone() {
        let freq = config.update_frequency.unwrap_or(60) as u64;
        PolicyFetchAdapter::new(store.clone()).spawn(url, freq);
    }

    if let Some(hurl) = config.labels_url.clone() {
        let freq = config.labels_refresh.unwrap_or(60) as u64;
        LabelFetchAdapter::new(store.clone()).spawn(hurl, freq);
    }

    if let Some(surl) = config.schema_url.clone() {
        let freq = config.schema_refresh.unwrap_or(60) as u64;
        SchemaFetchAdapter::new(store.clone()).spawn(surl, freq);
    }

    if let Some(bundle_url) = config.bundle_url.clone() {
        let limits = ArchiveLimits::new(
            bundle_runtime.max_compressed_bytes,
            bundle_runtime.max_uncompressed_bytes,
        )
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        BundleFetcher::new_with_engine_mode(
            store.clone(),
            bundle_url,
            config.bundle_refresh,
            limits,
            bundle_runtime.signature_policy,
            bundle_runtime.trust_store.clone(),
            bundle_engine_mode,
        )
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid bundle fetch configuration: {error}"),
            )
        })?
        .spawn();
    }

    let authorize_runtime = AuthorizeRuntimeConfig {
        max_batch_size: config.max_batch_size,
        max_context_bytes: config.max_context_bytes,
        max_context_depth: config.max_context_depth,
        max_context_keys: config.max_context_keys,
    };

    let max_request_size = config.max_request_size;
    let admission_enabled = admission.enabled();

    HttpServer::new(move || {
        App::new()
            .wrap(TracingMiddleware::new())
            .wrap(Condition::new(
                admission_enabled,
                AccessControlMiddleware::new(admission.clone()),
            ))
            .service(swagger_ui())
            .app_data(actix_web::web::JsonConfig::default().limit(max_request_size))
            .app_data(actix_web::web::PayloadConfig::default().limit(max_request_size))
            .app_data(actix_web::web::Data::new(store.clone()))
            .app_data(actix_web::web::Data::new(parallel_config))
            .app_data(actix_web::web::Data::new(authorize_runtime))
            .app_data(actix_web::web::Data::new(bundle_runtime.clone()))
            .app_data(actix_web::web::Data::new(bundle_engine_mode))
            .app_data(actix_web::web::Data::new(metrics_registry.clone()))
            .configure(treetop_rest::handlers::init)
    })
    .bind((config.host.as_str(), config.port))?
    .workers(parallel_config.workers)
    .shutdown_timeout(30)
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, http::StatusCode, test};

    #[actix_web::test]
    async fn swagger_ui_loads_canonical_openapi_document() {
        let app = test::init_service(
            App::new()
                .service(swagger_ui())
                .configure(treetop_rest::handlers::init),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/swagger-ui/swagger-initializer.js")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains(r#""url": "/openapi.json""#));
    }
}
