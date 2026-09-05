use actix_web::{App, http::StatusCode, http::header, test, web};
use prometheus_client::registry::Registry;
use std::str::FromStr;
use std::sync::{Arc, OnceLock, RwLock};
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::config::AdmissionConfig;
use treetop_rest::handlers;
use treetop_rest::middleware::{AccessControlMiddleware, TracingMiddleware};
use treetop_rest::models::AuthorizeRequest;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

// Shared metrics registry for all tests
static METRICS_REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();

fn get_metrics_registry() -> Arc<Registry> {
    METRICS_REGISTRY
        .get_or_init(|| treetop_rest::metrics::init_prometheus().expect("Failed to init metrics"))
        .clone()
}

/// Helper to create a test app with metrics support
fn create_test_app_with_metrics(
    store: Arc<RwLock<PolicyStore>>,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    // Get the shared registry
    let registry = get_metrics_registry();
    let parallel = ParallelConfig::new(
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        1,
        None,
    );

    App::new()
        .wrap(treetop_rest::middleware::TracingMiddleware::new())
        .app_data(web::Data::new(store))
        .app_data(web::Data::new(registry))
        .app_data(web::Data::new(parallel))
        .configure(handlers::init)
}

/// Helper to create a test policy store with default policies
fn create_test_store() -> Arc<RwLock<PolicyStore>> {
    // Initialize metrics BEFORE creating the policy store/engine
    // This ensures the metrics sink is set up when the engine is created
    let _ = get_metrics_registry();

    let mut store = PolicyStore::new().unwrap();

    let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);

forbid (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    store.set_dsl(dsl, None, None).unwrap();
    Arc::new(RwLock::new(store))
}

#[actix_web::test]
async fn test_metrics_endpoint_exists() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_metrics_content_type() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let content_type = resp.headers().get("content-type").unwrap();
    assert!(
        content_type
            .to_str()
            .unwrap()
            .starts_with("application/openmetrics-text")
    );
}

#[actix_web::test]
async fn test_metrics_negotiates_prometheus_protobuf() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get()
        .uri("/metrics")
        .insert_header((
            header::ACCEPT,
            treetop_rest::metrics::PROMETHEUS_PROTOBUF_CONTENT_TYPE,
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    assert!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("application/vnd.google.protobuf")
    );
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
    assert!(!body.starts_with(b"# HELP"));
}

#[actix_web::test]
async fn test_metrics_rejects_zero_quality_protobuf() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get()
        .uri("/metrics")
        .insert_header((
            header::ACCEPT,
            format!(
                "{}; q=0.000",
                treetop_rest::metrics::PROMETHEUS_PROTOBUF_CONTENT_TYPE
            ),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    assert!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("application/openmetrics-text")
    );
}

#[actix_web::test]
async fn test_metrics_contains_build_info() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Check for build info metric
    assert!(
        body_str.contains("treetop_build_info"),
        "Metrics should contain treetop_build_info"
    );
    assert!(
        body_str.contains("app_version"),
        "Build info should have app_version label"
    );
    assert!(
        body_str.contains("core_version"),
        "Build info should have core_version label"
    );
    assert!(
        body_str.contains("cedar_version"),
        "Build info should have cedar_version label"
    );
}

#[actix_web::test]
async fn test_metrics_has_policy_eval_metrics() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an evaluation to ensure metrics are generated
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg").unwrap();

    let check_req = Request {
        principal: principal.clone(),
        action: action.clone(),
        resource: resource.clone(),
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    // Also perform a denied evaluation
    let action_edit = Action::from_str("Action::\"edit\"").unwrap();
    let check_req_denied = Request {
        principal: principal.clone(),
        action: action_edit,
        resource: resource.clone(),
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check_req_denied))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Now check metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Check for policy evaluation metrics
    assert!(
        body_str.contains("policy_evals_total"),
        "Metrics should contain policy_evals_total"
    );
    assert!(
        body_str.contains("policy_evals_allowed_total"),
        "Metrics should contain policy_evals_allowed_total"
    );
    assert!(
        body_str.contains("policy_evals_denied_total"),
        "Metrics should contain policy_evals_denied_total"
    );
    assert!(
        body_str.contains("policy_eval_duration_seconds"),
        "Metrics should contain policy_eval_duration_seconds"
    );
    assert!(
        body_str.contains("policy_eval_phase_duration_seconds"),
        "Metrics should contain policy_eval_phase_duration_seconds"
    );
    for phase in [
        "apply_labels",
        "construct_entities",
        "resolve_groups",
        "cedar_authorize",
        "overhead",
    ] {
        assert!(
            body_str.contains(&format!("phase=\"{phase}\"")),
            "Metrics should contain the {phase} phase"
        );
    }
    assert!(
        body_str.contains("policy_reloads_total"),
        "Metrics should contain policy_reloads_total"
    );
}

#[actix_web::test]
async fn test_metrics_updated_after_evaluation() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an authorization check (alice viewing photo - should be allowed)
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg").unwrap();

    let check_req = Request {
        principal,
        action,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Get metrics and verify they contain our specific evaluation
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // In a parallel test environment, we can't rely on exact counts
    // Instead, verify that the metrics exist and contain our specific labels
    // The metrics should have labels for principal and action
    assert!(
        body_str.contains("policy_evals_total"),
        "Metrics should contain policy_evals_total"
    );
    assert!(
        body_str.contains("policy_evals_allowed_total"),
        "Metrics should contain policy_evals_allowed_total"
    );

    // Verify that metrics with our specific labels exist
    // In Prometheus format, labels use escaped quotes like: principal="User::\"alice\""
    let has_alice_view = body_str.lines().any(|line| {
        line.contains("policy_evals_total")
            && line.contains("Action::")
            && line.contains("view")
            && !line.starts_with('#')
    });

    assert!(
        has_alice_view,
        "Metrics should contain an evaluation for Action::view"
    );
}

#[actix_web::test]
async fn test_metrics_tracks_allowed_and_denied() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an allowed evaluation (alice viewing photo)
    let principal_alice = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action_view = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg").unwrap();

    let check_req = Request {
        principal: principal_alice.clone(),
        action: action_view,
        resource: resource.clone(),
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Perform a denied evaluation (alice editing photo - explicitly forbidden)
    let action_edit = Action::from_str("Action::\"edit\"").unwrap();
    let check_req_denied = Request {
        principal: principal_alice,
        action: action_edit,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check_req_denied))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Check metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Both allowed and denied should have non-zero values
    let allowed_count = extract_metric_value(body_str, "policy_evals_allowed_total");
    let denied_count = extract_metric_value(body_str, "policy_evals_denied_total");

    assert!(
        allowed_count > 0.0,
        "Should have at least one allowed evaluation"
    );
    assert!(
        denied_count > 0.0,
        "Should have at least one denied evaluation"
    );
}

#[actix_web::test]
async fn test_metrics_prometheus_format() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an evaluation to ensure counter metrics are present
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg").unwrap();

    let check_req = Request {
        principal,
        action,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Now check metrics format
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Verify Prometheus format characteristics
    assert!(
        body_str.contains("# HELP"),
        "Prometheus metrics should contain HELP comments"
    );
    assert!(
        body_str.contains("# TYPE"),
        "Prometheus metrics should contain TYPE comments"
    );

    // Verify metric types
    assert!(
        body_str.contains("# TYPE policy_evals counter"),
        "policy_evals_total should be a counter"
    );
    assert!(
        body_str.contains("# TYPE policy_eval_duration_seconds histogram"),
        "policy_eval_duration_seconds should be a histogram"
    );

    // Verify HTTP metrics types
    assert!(
        body_str.contains("# TYPE http_requests counter"),
        "http_requests_total should be a counter"
    );
    assert!(
        body_str.contains("# TYPE http_request_duration_seconds histogram"),
        "http_request_duration_seconds should be a histogram"
    );
}

#[actix_web::test]
async fn test_http_metrics_after_health_request() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Hit health endpoint to generate HTTP metrics
    let req = test::TestRequest::get().uri("/api/v1/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Get metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    assert!(
        body_str.contains("http_requests_total"),
        "HTTP request counter should be present"
    );
    assert!(
        body_str.contains("http_request_duration_seconds"),
        "HTTP request duration histogram should be present"
    );
}

#[actix_web::test]
async fn test_openapi_endpoint_uses_fixed_metrics_path() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get()
        .uri(handlers::OPENAPI_JSON_PATH)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body = std::str::from_utf8(&body).unwrap();

    assert!(body.lines().any(|line| {
        line.starts_with("http_requests_total")
            && line.contains("method=\"GET\"")
            && line.contains("path=\"/openapi.json\"")
            && line.contains("status_code=\"200\"")
    }));
}

#[actix_web::test]
async fn test_http_metrics_use_route_templates_and_bound_unmatched_paths() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    for path in [
        "/api/v1/policies/alice",
        "/api/v1/policies/bob",
        "/not-a-route/first",
        "/not-a-route/second",
    ] {
        let req = test::TestRequest::get().uri(path).to_request();
        let _ = test::call_service(&app, req).await;
    }

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body = std::str::from_utf8(&body).unwrap();

    assert!(body.lines().any(|line| {
        line.starts_with("http_request_duration_seconds_count")
            && line.contains("path=\"/api/v1/policies/{user}\"")
    }));
    assert!(body.lines().any(|line| {
        line.starts_with("http_request_duration_seconds_count")
            && line.contains("path=\"unmatched\"")
    }));
    assert!(!body.contains("path=\"/api/v1/policies/alice\""));
    assert!(!body.contains("path=\"/api/v1/policies/bob\""));
    assert!(!body.contains("path=\"/not-a-route/first\""));
    assert!(!body.contains("path=\"/not-a-route/second\""));
}

#[actix_web::test]
async fn test_metrics_has_histogram_buckets() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an evaluation to generate histogram data
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg").unwrap();

    let check_req = Request {
        principal,
        action,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Get metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Verify the histogram has useful sub-millisecond buckets plus sum and count.
    assert!(
        body_str.contains("policy_eval_duration_seconds_bucket"),
        "Duration histogram should have buckets"
    );
    for metric in [
        "http_request_duration_seconds_bucket",
        "policy_eval_duration_seconds_bucket",
    ] {
        for boundary in [
            "0.00001", "0.000025", "0.00005", "0.0001", "0.00025", "0.0005", "0.001", "0.0025",
        ] {
            assert!(
                body_str.lines().any(|line| {
                    line.starts_with(metric) && line.contains(&format!("le=\"{boundary}\""))
                }),
                "{metric} should include the {boundary} second boundary"
            );
        }
    }
    assert!(
        body_str.contains("policy_eval_duration_seconds_sum"),
        "Duration histogram should have sum"
    );
    assert!(
        body_str.contains("policy_eval_duration_seconds_count"),
        "Duration histogram should have count"
    );
}

#[actix_web::test]
async fn test_http_metrics_include_client_ip_label() {
    let store = create_test_store();
    // Resolve the forwarded client once in access control and share it with tracing.
    let registry = get_metrics_registry();
    let admission = AdmissionConfig::parse(Some("203.0.113.10"), None, Some("127.0.0.1")).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(TracingMiddleware::new())
            .wrap(AccessControlMiddleware::new(admission))
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(registry.clone()))
            .configure(handlers::init),
    )
    .await;

    // Send a request with a specific client IP
    let req = test::TestRequest::get()
        .uri("/api/v1/health")
        .peer_addr("127.0.0.1:1234".parse().unwrap())
        .insert_header(("x-forwarded-for", "203.0.113.10"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Fetch metrics and verify the client_ip label is present with our value
    let req = test::TestRequest::get()
        .uri("/metrics")
        .peer_addr("127.0.0.1:1234".parse().unwrap())
        .insert_header(("x-forwarded-for", "203.0.113.10"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    let has_client_ip = body_str.lines().any(|line| {
        line.starts_with("http_requests_total")
            && line.contains("client_ip=\"203.0.113.10\"")
            && !line.starts_with('#')
    });
    assert!(
        has_client_ip,
        "HTTP metrics should include client_ip label with the forwarded IP: {body_str}"
    );
}

#[actix_web::test]
async fn test_authorization_metrics_correlate_accepted_batch_size_and_exclude_rejections() {
    let store = create_test_store();
    let registry = get_metrics_registry();
    let parallel = ParallelConfig::new(1, 1, None);
    let runtime = handlers::AuthorizeRuntimeConfig {
        max_batch_size: 33,
        ..handlers::AuthorizeRuntimeConfig::default()
    };
    let app = test::init_service(
        App::new()
            .wrap(TracingMiddleware::new())
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(registry))
            .app_data(web::Data::new(parallel))
            .app_data(web::Data::new(runtime))
            .configure(handlers::init),
    )
    .await;

    let check = Request {
        principal: Principal::User(User::from_str("User::\"alice\"").unwrap()),
        action: Action::from_str("Action::\"view\"").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(AuthorizeRequest::single(check.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let accepted = AuthorizeRequest::from_requests(std::iter::repeat_n(check.clone(), 33));
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(accepted)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let over_limit = AuthorizeRequest::from_requests(std::iter::repeat_n(check, 34));
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(over_limit)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload("{not-json")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body = std::str::from_utf8(&body).unwrap();

    assert!(
        body.contains(
            "# HELP authorization_batch_size Authorization checks per completed, accepted"
        )
    );
    assert!(body.contains("over-limit batches are excluded"));
    assert!(body.lines().any(|line| {
        line.starts_with("authorization_request_duration_seconds_count{")
            && line.contains("batch_size_class=\"1\"")
    }));
    assert_eq!(
        extract_labeled_metric_value(
            body,
            "authorization_request_duration_seconds_count",
            &["batch_size_class=\"33-128\""],
        ),
        1.0
    );
    let through_32 =
        extract_labeled_metric_value(body, "authorization_batch_size_bucket", &["le=\"32.0\""]);
    let through_128 =
        extract_labeled_metric_value(body, "authorization_batch_size_bucket", &["le=\"128.0\""]);
    assert_eq!(through_128 - through_32, 1.0);
    assert!(body.lines().any(|line| {
        line.starts_with("http_request_duration_seconds_count{")
            && line.contains("path=\"/api/v1/authorize\"")
            && line.contains("status_code=\"200\"")
    }));
}

/// Helper function to extract a metric value from Prometheus text format
/// This is a simple parser that finds the first occurrence of the metric name
/// and extracts its value (works for counters without labels at the end)
fn extract_metric_value(metrics: &str, metric_name: &str) -> f64 {
    for line in metrics.lines() {
        // Skip comments
        if line.starts_with('#') {
            continue;
        }
        // Look for lines starting with the metric name
        if line.starts_with(metric_name) {
            // Split by whitespace and get the last part (the value)
            if let Some(value_str) = line.split_whitespace().last()
                && let Ok(value) = value_str.parse::<f64>()
            {
                return value;
            }
        }
    }
    0.0
}

fn extract_labeled_metric_value(metrics: &str, metric_name: &str, labels: &[&str]) -> f64 {
    metrics
        .lines()
        .find(|line| {
            line.starts_with(metric_name)
                && !line.starts_with('#')
                && labels.iter().all(|label| line.contains(label))
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}
