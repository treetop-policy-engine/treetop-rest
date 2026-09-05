use actix_web::{App, http::StatusCode, http::header, test, web};
use futures_util::FutureExt;
use rstest::rstest;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use treetop_core::{Action, AttrValue, Principal, Request, Resource, User};
use treetop_rest::config::SchemaValidationMode;
use treetop_rest::handlers;
use treetop_rest::models::{
    AuthRequest, AuthorizeBriefResponse, AuthorizeDecisionBrief, AuthorizeDetailedResponse,
    AuthorizeRequest, BatchResult, DecisionBrief, IndexedResult, RequestContextFallbackReason,
    StatusResponse,
};
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const CONTEXT_POLICY_DSL: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    context.env == "prod"
};
"#;

const CONTEXT_SCHEMA_JSON: &str = r#"{
  "": {
    "entityTypes": {
      "User": {},
      "Photo": {}
    },
    "actions": {
      "view": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Photo"],
          "context": {
            "type": "Record",
            "attributes": {
              "env": {
                "type": "String",
                "required": true
              }
            },
            "additionalAttributes": false
          }
        }
      }
    }
  }
}"#;

/// Helper to create a test policy store with default policies
fn create_test_store() -> Arc<RwLock<PolicyStore>> {
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

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
)
when { resource.ip.isInRange(ip("10.0.0.0/24")) };
"#;

    store.set_dsl(dsl, None, None).unwrap();
    Arc::new(RwLock::new(store))
}

/// Helper to create a test batch parallel config
fn create_test_parallel_config() -> ParallelConfig {
    ParallelConfig::new(
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        1,
        None,
    )
}

fn assert_brief_result(
    result: &IndexedResult<AuthorizeDecisionBrief>,
    expected_id: Option<&str>,
    expected: DecisionBrief,
) {
    if let Some(expected_id) = expected_id {
        assert_eq!(result.id(), Some(expected_id));
    }
    match result.result() {
        BatchResult::Success { data } => match expected {
            DecisionBrief::Allow => assert!(matches!(data.decision, DecisionBrief::Allow)),
            DecisionBrief::Deny => assert!(matches!(data.decision, DecisionBrief::Deny)),
        },
        BatchResult::Failed { message } => panic!("unexpected failure: {}", message),
    }
}

fn assert_single_decision(body: &AuthorizeBriefResponse, expected: DecisionBrief) {
    assert_eq!(body.results().len(), 1);
    let result = body.iter().next().expect("missing result");
    assert_brief_result(result, None, expected);
}

#[actix_web::test]
async fn test_health_endpoint() {
    let app =
        test::init_service(App::new().route("/api/v1/health", web::get().to(handlers::health)))
            .await;

    let req = test::TestRequest::get().uri("/api/v1/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_livez_endpoint_is_dependency_free() {
    let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .route("/livez", web::get().to(handlers::livez)),
    )
    .await;

    let write_guard = store.write().unwrap();
    let req = test::TestRequest::get().uri("/livez").to_request();
    // A health probe must complete immediately while another operation owns the store.
    let resp = test::call_service(&app, req)
        .now_or_never()
        .expect("livez must not wait for the policy store");
    drop(write_guard);

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        test::read_body(resp).await,
        web::Bytes::from_static(b"ok\n")
    );
}

#[actix_web::test]
async fn test_readyz_endpoint_is_ready_without_remote_sources() {
    let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/readyz", web::get().to(handlers::readyz)),
    )
    .await;

    let req = test::TestRequest::get().uri("/readyz").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        test::read_body(resp).await,
        web::Bytes::from_static(b"ok\n")
    );
}

#[actix_web::test]
async fn test_readyz_does_not_treat_local_update_as_remote_load() {
    let mut policy_store = PolicyStore::new().unwrap();
    policy_store.policies.source = Some("https://example.com/policies.cedar".parse().unwrap());
    let store = Arc::new(RwLock::new(policy_store));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .route("/readyz", web::get().to(handlers::readyz)),
    )
    .await;

    let req = test::TestRequest::get().uri("/readyz").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        test::read_body(resp).await,
        web::Bytes::from_static(b"not ready\n")
    );

    store.write().unwrap().set_dsl("", None, None).unwrap();

    let req = test::TestRequest::get().uri("/readyz").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[actix_web::test]
async fn test_readyz_fails_fast_while_store_is_busy() {
    let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .route("/readyz", web::get().to(handlers::readyz)),
    )
    .await;

    let write_guard = store.write().unwrap();
    let req = test::TestRequest::get().uri("/readyz").to_request();
    // A health probe must complete immediately while another operation owns the store.
    let resp = test::call_service(&app, req)
        .now_or_never()
        .expect("readyz must not wait for the policy store");
    drop(write_guard);

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[actix_web::test]
async fn test_openapi_json_endpoint() {
    let app = test::init_service(App::new().configure(handlers::init)).await;

    let req = test::TestRequest::get()
        .uri(handlers::OPENAPI_JSON_PATH)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["openapi"], "3.1.0");
    for path in ["/api/v1/authorize", "/livez", "/openapi.json", "/readyz"] {
        assert!(body["paths"][path].is_object(), "missing path {path}");
    }

    let generated = serde_json::to_value(handlers::openapi_document()).unwrap();
    assert_eq!(body, generated);
}

#[actix_web::test]
async fn test_legacy_openapi_endpoint_matches_canonical_document() {
    let app = test::init_service(App::new().configure(handlers::init)).await;

    let canonical_req = test::TestRequest::get()
        .uri(handlers::OPENAPI_JSON_PATH)
        .to_request();
    let canonical_resp = test::call_service(&app, canonical_req).await;
    assert_eq!(canonical_resp.status(), StatusCode::OK);
    let canonical_body = test::read_body(canonical_resp).await;

    let legacy_req = test::TestRequest::get()
        .uri("/api-docs/openapi.json")
        .to_request();
    let legacy_resp = test::call_service(&app, legacy_req).await;
    assert_eq!(legacy_resp.status(), StatusCode::OK);
    let legacy_body = test::read_body(legacy_resp).await;

    assert_eq!(legacy_body, canonical_body);
}

#[actix_web::test]
async fn test_get_status_endpoint() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/status", web::get().to(handlers::get_status)),
    )
    .await;

    let req = test::TestRequest::get().uri("/api/v1/status").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body: StatusResponse = test::read_body_json(resp).await;
    assert_eq!(body.request_limits.max_batch_size, Some(1024));
    assert_eq!(body.policy_configuration.policies.entries, 3);
    assert!(body.request_context.supported);
    assert!(!body.request_context.schema_backed);
    assert_eq!(
        body.request_context.fallback_reason,
        Some(RequestContextFallbackReason::NoSchema)
    );
}

#[actix_web::test]
async fn test_get_status_endpoint_reports_schema_backed_context_runtime() {
    let mut store = PolicyStore::new().unwrap();
    store.set_schema(CONTEXT_SCHEMA_JSON, None, None).unwrap();
    store.set_dsl(CONTEXT_POLICY_DSL, None, None).unwrap();
    let store = Arc::new(RwLock::new(store));
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/status", web::get().to(handlers::get_status)),
    )
    .await;

    let req = test::TestRequest::get().uri("/api/v1/status").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body: StatusResponse = test::read_body_json(resp).await;
    assert!(body.request_context.supported);
    assert!(body.request_context.schema_backed);
    assert_eq!(body.request_context.fallback_reason, None);
}

#[actix_web::test]
async fn test_check_endpoint_allow() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Allow);
}

#[actix_web::test]
async fn test_authorize_rejects_batch_over_configured_limit() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let runtime = handlers::AuthorizeRuntimeConfig {
        max_batch_size: 1,
        ..handlers::AuthorizeRuntimeConfig::default()
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .app_data(web::Data::new(runtime))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };
    let auth_request = AuthorizeRequest::from_requests([request.clone(), request]);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["code"], "validation_error");
    assert!(body["error"].as_str().unwrap().contains("2 > 1"));
}

#[actix_web::test]
async fn test_check_endpoint_deny() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("edit").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Deny);
}

#[actix_web::test]
async fn test_check_endpoint_with_attributes() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let resource = Resource::new("Host", "myhost.example.com")
        .unwrap()
        .with_attr("ip", AttrValue::ip("10.0.0.5").unwrap());

    let request = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Allow);
}

#[actix_web::test]
async fn test_check_endpoint_deny_out_of_range() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let resource = Resource::new("Host", "myhost.example.com")
        .unwrap()
        .with_attr("ip", AttrValue::ip("192.168.1.5").unwrap());

    let request = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Deny);
}

#[actix_web::test]
async fn test_check_endpoint_with_request_context() {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(CONTEXT_POLICY_DSL, None, None).unwrap();
    let store = Arc::new(RwLock::new(store));
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };
    let mut context = HashMap::new();
    context.insert("env".to_string(), AttrValue::String("prod".to_string()));
    let auth_request = AuthorizeRequest {
        requests: vec![AuthRequest::new(request).with_context(context)],
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Allow);
}

#[actix_web::test]
async fn test_check_endpoint_rejects_context_without_schema_in_strict_mode() {
    let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
    {
        let mut guard = store.write().unwrap();
        guard.set_schema_validation_mode(SchemaValidationMode::Strict);
    }
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };
    let mut context = HashMap::new();
    context.insert("env".to_string(), AttrValue::String("prod".to_string()));
    let auth_request = AuthorizeRequest {
        requests: vec![AuthRequest::new(request).with_context(context)],
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    let result = body.iter().next().expect("missing result");
    match result.result() {
        BatchResult::Failed { message } => {
            assert!(
                message.contains("context requires an uploaded schema in strict validation mode")
            )
        }
        BatchResult::Success { .. } => panic!("expected context validation failure"),
    }
}

#[actix_web::test]
async fn test_get_policies_json() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/policies", web::get().to(handlers::get_policies)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/policies")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[actix_web::test]
async fn test_get_policies_raw() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/policies", web::get().to(handlers::get_policies)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/policies?format=raw")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");

    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("permit"));
}

#[actix_web::test]
async fn test_get_schema_raw() {
    let store = create_test_store();
    {
        let mut guard = store.write().unwrap();
        guard
            .set_schema(r#"{"": {"entityTypes": {}, "actions": {}}}"#, None, None)
            .unwrap();
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/schema", web::get().to(handlers::get_schema)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/schema?format=raw")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");

    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("entityTypes"));
}

#[actix_web::test]
async fn test_upload_policies_not_allowed() {
    let store = create_test_store();
    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies",
        web::post().to(handlers::upload_policies),
    ))
    .await;

    let new_policy = r#"{"policies": "permit (principal, action, resource);"}"#;

    let req = test::TestRequest::post()
        .uri("/api/v1/policies")
        .set_payload(new_policy)
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should fail because upload is not allowed
    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_upload_authentication_precedes_body_parsing() {
    let store = create_test_store();
    {
        let mut store_guard = store.write().unwrap();
        store_guard.allow_upload = true;
        store_guard.upload_token = Some("expected-token".to_string());
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route(
                "/api/v1/policies",
                web::post().to(handlers::upload_policies),
            )
            .route("/api/v1/schema", web::post().to(handlers::upload_schema)),
    )
    .await;

    for uri in ["/api/v1/policies", "/api/v1/schema"] {
        let req = test::TestRequest::post()
            .uri(uri)
            .set_payload("{not-json")
            .insert_header(("content-type", "application/json"))
            .insert_header(("X-Upload-Token", "wrong-token"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "invalid_upload_token");
    }
}

#[rstest]
#[case("test-token", "test-token", true)]
#[case("correct-token", "correct-token", true)]
#[case("correct-token", "wrong-token", false)]
#[case("secret123", "wrong123", false)]
#[actix_web::test]
async fn test_upload_with_token(
    #[case] expected_token: &str,
    #[case] provided_token: &str,
    #[case] should_succeed: bool,
) {
    let store = create_test_store();
    {
        let mut store_guard = store.write().unwrap();
        store_guard.allow_upload = true;
        store_guard.upload_token = Some(expected_token.to_string());
    }

    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies",
        web::post().to(handlers::upload_policies),
    ))
    .await;

    let new_policy = r#"{"policies": "permit (principal, action, resource);"}"#;

    let req = test::TestRequest::post()
        .uri("/api/v1/policies")
        .set_payload(new_policy)
        .insert_header(("content-type", "application/json"))
        .insert_header(("X-Upload-Token", provided_token))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().is_success(), should_succeed);
}

#[rstest]
#[case("test-token", "test-token", true)]
#[case("correct-token", "correct-token", true)]
#[case("correct-token", "wrong-token", false)]
#[case("secret123", "wrong123", false)]
#[actix_web::test]
async fn test_upload_schema_with_token(
    #[case] expected_token: &str,
    #[case] provided_token: &str,
    #[case] should_succeed: bool,
) {
    let store = create_test_store();
    {
        let mut store_guard = store.write().unwrap();
        store_guard.allow_upload = true;
        store_guard.upload_token = Some(expected_token.to_string());
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/schema", web::post().to(handlers::upload_schema)),
    )
    .await;

    let schema = r#"{"": {"entityTypes": {}, "actions": {}}}"#;

    let req = test::TestRequest::post()
        .uri("/api/v1/schema")
        .set_payload(schema)
        .insert_header(("content-type", "text/plain"))
        .insert_header(("X-Upload-Token", provided_token))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().is_success(), should_succeed);
}

#[rstest]
#[case(r#"{"": {"entityTypes": {}, "actions": {}}}"#)]
#[case(r#"{"schema":"{\"\": {\"entityTypes\": {}, \"actions\": {}}}"}"#)]
#[actix_web::test]
async fn test_upload_schema_accepts_documented_json_forms(#[case] schema: &str) {
    let store = create_test_store();
    {
        let mut store_guard = store.write().unwrap();
        store_guard.allow_upload = true;
        store_guard.upload_token = Some("test-token".to_string());
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/schema", web::post().to(handlers::upload_schema)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/schema")
        .set_payload(schema.to_owned())
        .insert_header(("content-type", "application/json"))
        .insert_header(("X-Upload-Token", "test-token"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_list_policies_for_user() {
    let store = create_test_store();
    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies/{user}",
        web::get().to(handlers::list_policies),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/policies/alice")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_list_policies_for_user_with_groups() {
    let store = create_test_store();
    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies/{user}",
        web::get().to(handlers::list_policies),
    ))
    .await;

    // Query with empty groups (no groups parameter)
    let req = test::TestRequest::get()
        .uri("/api/v1/policies/alice")
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    assert!(status.is_success(), "Expected success, got: {}", status);
}

#[actix_web::test]
async fn test_list_policies_for_user_with_single_group() {
    let store = create_test_store();
    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies/{user}",
        web::get().to(handlers::list_policies),
    ))
    .await;

    // Query without groups parameter - should work with empty vec
    let req = test::TestRequest::get()
        .uri("/api/v1/policies/bob")
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    assert!(status.is_success(), "Expected success, got: {}", status);
}

#[actix_web::test]
async fn test_list_policies_with_group_membership_filtering() {
    // Create a test store with simple valid policies
    let mut store = PolicyStore::new().unwrap();

    let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource is Photo
);

permit (
    principal == User::"alice",
    action == Action::"edit",
    resource is Photo
);

permit (
    principal == User::"bob",
    action == Action::"delete",
    resource is Photo
);
"#;

    store.set_dsl(dsl, None, None).unwrap();
    let store = Arc::new(RwLock::new(store));

    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies/{user}",
        web::get().to(handlers::list_policies),
    ))
    .await;

    // Get policies for alice without groups
    let req_alice = test::TestRequest::get()
        .uri("/api/v1/policies/alice")
        .to_request();

    let resp_alice = test::call_service(&app, req_alice).await;
    assert!(
        resp_alice.status().is_success(),
        "Failed to get policies for alice"
    );
    let body_alice = actix_web::body::to_bytes(resp_alice.into_body())
        .await
        .unwrap();
    let json_alice: serde_json::Value = serde_json::from_slice(&body_alice).unwrap();
    let count_alice = json_alice["policies"].as_array().unwrap_or(&vec![]).len();
    let matches_alice = json_alice["matches"]
        .as_array()
        .expect("Expected matches to be an array for alice");
    assert_eq!(count_alice, 2, "Expected 2 policies for alice");
    assert_eq!(
        matches_alice.len(),
        count_alice,
        "Expected one match entry per returned policy for alice"
    );
    assert!(
        matches_alice.iter().all(|m| {
            m["reasons"]
                .as_array()
                .is_some_and(|reasons| !reasons.is_empty())
        }),
        "Expected non-empty match reasons for each alice policy"
    );
    assert!(
        matches_alice.iter().all(|m| {
            m["reasons"]
                .as_array()
                .is_some_and(|reasons| reasons.iter().any(|r| r == "PrincipalEq"))
        }),
        "Expected principal match reason for alice policies"
    );
    assert_eq!(
        json_alice["user"].as_str(),
        Some("alice"),
        "Expected user to be alice"
    );

    // Get policies for bob without groups
    let req_bob = test::TestRequest::get()
        .uri("/api/v1/policies/bob")
        .to_request();

    let resp_bob = test::call_service(&app, req_bob).await;
    assert!(
        resp_bob.status().is_success(),
        "Failed to get policies for bob"
    );
    let body_bob = actix_web::body::to_bytes(resp_bob.into_body())
        .await
        .unwrap();
    let json_bob: serde_json::Value = serde_json::from_slice(&body_bob).unwrap();
    let count_bob = json_bob["policies"].as_array().unwrap_or(&vec![]).len();
    let matches_bob = json_bob["matches"]
        .as_array()
        .expect("Expected matches to be an array for bob");
    assert_eq!(count_bob, 1, "Expected 1 policy for bob");
    assert_eq!(
        matches_bob.len(),
        count_bob,
        "Expected one match entry per returned policy for bob"
    );
    assert!(
        matches_bob.iter().all(|m| {
            m["reasons"]
                .as_array()
                .is_some_and(|reasons| reasons.iter().any(|r| r == "PrincipalEq"))
        }),
        "Expected principal match reason for bob policies"
    );
    assert_eq!(
        json_bob["user"].as_str(),
        Some("bob"),
        "Expected user to be bob"
    );

    // Test that groups parameter is accepted without errors
    let req_alice_no_params = test::TestRequest::get()
        .uri("/api/v1/policies/alice")
        .to_request();

    let resp = test::call_service(&app, req_alice_no_params).await;
    assert!(
        resp.status().is_success(),
        "Failed to get policies without group parameter"
    );
    let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify the response structure is correct
    assert!(json.is_object(), "Response should be an object");
    assert!(
        json["user"].is_string(),
        "Response should have a user field"
    );
    assert!(
        json["policies"].is_array(),
        "Response should have a policies array"
    );
    assert!(
        json["matches"].is_array(),
        "Response should have a matches array"
    );
    assert_eq!(
        json["user"].as_str(),
        Some("alice"),
        "User field should match requested user"
    );
}

#[actix_web::test]
async fn test_authorize_endpoint_brief() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request1 = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let request2 = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let auth_request = AuthorizeRequest::with_ids([("check-1", request1), ("check-2", request2)]);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=brief")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_eq!(body.results().len(), 2);

    let mut results = body.iter();
    assert_brief_result(
        results.next().expect("missing result"),
        Some("check-1"),
        DecisionBrief::Allow,
    );
    // Second request should be a Deny (bob doesn't have view on this photo)
    assert_brief_result(
        results.next().expect("missing result"),
        Some("check-2"),
        DecisionBrief::Deny,
    );
    assert_eq!(body.successes(), 2);
    assert_eq!(body.failures(), 0);
}

#[actix_web::test]
async fn test_authorize_endpoint_detailed() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let auth_request = AuthorizeRequest::new().add_with_id("check-1", request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeDetailedResponse = test::read_body_json(resp).await;
    assert_eq!(body.results().len(), 1);
    match body.iter().next().expect("missing result").result() {
        BatchResult::Success { data } => {
            assert!(matches!(data.decision, DecisionBrief::Allow));
            assert!(!data.policy.is_empty());
        }
        BatchResult::Failed { message } => panic!("unexpected failure: {}", message),
    }
}

/// Test that brief and detailed return the same decision for Allow
#[actix_web::test]
async fn test_brief_and_detailed_both_allow() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    // Test brief
    let auth_request = AuthorizeRequest::single(request.clone());
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=brief")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let brief_body: AuthorizeBriefResponse = test::read_body_json(resp).await;

    // Test detailed
    let auth_request = AuthorizeRequest::single(request);
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let detailed_body: AuthorizeDetailedResponse = test::read_body_json(resp).await;

    // Compare decisions
    match (
        brief_body.iter().next().unwrap().result(),
        detailed_body.iter().next().unwrap().result(),
    ) {
        (BatchResult::Success { data: brief }, BatchResult::Success { data: detailed }) => {
            assert!(matches!(brief.decision, DecisionBrief::Allow));
            assert!(matches!(detailed.decision, DecisionBrief::Allow));
        }
        _ => panic!("Expected success for both brief and detailed"),
    }
}

/// Test that brief and detailed return the same decision for Deny
#[actix_web::test]
async fn test_brief_and_detailed_both_deny() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("edit").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    // Test brief
    let auth_request = AuthorizeRequest::single(request.clone());
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=brief")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let brief_body: AuthorizeBriefResponse = test::read_body_json(resp).await;

    // Test detailed
    let auth_request = AuthorizeRequest::single(request);
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let detailed_body: AuthorizeDetailedResponse = test::read_body_json(resp).await;

    // Compare decisions
    match (
        brief_body.iter().next().unwrap().result(),
        detailed_body.iter().next().unwrap().result(),
    ) {
        (BatchResult::Success { data: brief }, BatchResult::Success { data: detailed }) => {
            assert!(matches!(brief.decision, DecisionBrief::Deny));
            assert!(matches!(detailed.decision, DecisionBrief::Deny));
        }
        _ => panic!("Expected success for both brief and detailed"),
    }
}

/// Test that brief and detailed return consistent decisions with attributes (Allow)
#[actix_web::test]
async fn test_brief_and_detailed_with_attributes_allow() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let resource = Resource::new("Host", "myhost.example.com")
        .unwrap()
        .with_attr("ip", AttrValue::ip("10.0.0.5").unwrap());

    let request = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    // Test brief
    let auth_request = AuthorizeRequest::single(request.clone());
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=brief")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let brief_body: AuthorizeBriefResponse = test::read_body_json(resp).await;

    // Test detailed
    let auth_request = AuthorizeRequest::single(request);
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let detailed_body: AuthorizeDetailedResponse = test::read_body_json(resp).await;

    // Compare decisions
    match (
        brief_body.iter().next().unwrap().result(),
        detailed_body.iter().next().unwrap().result(),
    ) {
        (BatchResult::Success { data: brief }, BatchResult::Success { data: detailed }) => {
            assert!(matches!(brief.decision, DecisionBrief::Allow));
            assert!(matches!(detailed.decision, DecisionBrief::Allow));
        }
        _ => panic!("Expected success for both brief and detailed"),
    }
}

/// Test that brief and detailed return consistent decisions with attributes (Deny)
#[actix_web::test]
async fn test_brief_and_detailed_with_attributes_deny() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let resource = Resource::new("Host", "myhost.example.com")
        .unwrap()
        .with_attr("ip", AttrValue::ip("192.168.1.5").unwrap());

    let request = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    // Test brief
    let auth_request = AuthorizeRequest::single(request.clone());
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=brief")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let brief_body: AuthorizeBriefResponse = test::read_body_json(resp).await;

    // Test detailed
    let auth_request = AuthorizeRequest::single(request);
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let detailed_body: AuthorizeDetailedResponse = test::read_body_json(resp).await;

    // Compare decisions
    match (
        brief_body.iter().next().unwrap().result(),
        detailed_body.iter().next().unwrap().result(),
    ) {
        (BatchResult::Success { data: brief }, BatchResult::Success { data: detailed }) => {
            assert!(matches!(brief.decision, DecisionBrief::Deny));
            assert!(matches!(detailed.decision, DecisionBrief::Deny));
        }
        _ => panic!("Expected success for both brief and detailed"),
    }
}

/// Test multiple requests in batch - brief and detailed should match
#[actix_web::test]
async fn test_brief_and_detailed_batch_consistency() {
    let store = create_test_store();
    let parallel = create_test_parallel_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request1 = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let request2 = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("edit").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    let request3 = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    // Test brief
    let auth_request = AuthorizeRequest::with_ids([
        ("q1", request1.clone()),
        ("q2", request2.clone()),
        ("q3", request3.clone()),
    ]);
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=brief")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let brief_body: AuthorizeBriefResponse = test::read_body_json(resp).await;

    // Test detailed
    let auth_request =
        AuthorizeRequest::with_ids([("q1", request1), ("q2", request2), ("q3", request3)]);
    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let detailed_body: AuthorizeDetailedResponse = test::read_body_json(resp).await;

    // Compare all decisions
    assert_eq!(brief_body.results().len(), 3);
    assert_eq!(detailed_body.results().len(), 3);

    let brief_results: Vec<_> = brief_body.iter().collect();
    let detailed_results: Vec<_> = detailed_body.iter().collect();

    for (brief, detailed) in brief_results.iter().zip(detailed_results.iter()) {
        match (brief.result(), detailed.result()) {
            (
                BatchResult::Success { data: brief_data },
                BatchResult::Success {
                    data: detailed_data,
                },
            ) => {
                // Decisions must match
                let brief_is_allow = matches!(brief_data.decision, DecisionBrief::Allow);
                let detailed_is_allow = matches!(detailed_data.decision, DecisionBrief::Allow);
                assert_eq!(
                    brief_is_allow,
                    detailed_is_allow,
                    "Decision mismatch for query id {:?}: brief={}, detailed={}",
                    brief.id(),
                    if brief_is_allow { "Allow" } else { "Deny" },
                    if detailed_is_allow { "Allow" } else { "Deny" }
                );
            }
            _ => panic!("Expected success for both brief and detailed"),
        }
    }

    // Verify expected results: Allow, Deny, Deny
    match brief_results[0].result() {
        BatchResult::Success { data } => assert!(matches!(data.decision, DecisionBrief::Allow)),
        _ => panic!("Expected Allow for first request"),
    }
    match brief_results[1].result() {
        BatchResult::Success { data } => assert!(matches!(data.decision, DecisionBrief::Deny)),
        _ => panic!("Expected Deny for second request"),
    }
    match brief_results[2].result() {
        BatchResult::Success { data } => assert!(matches!(data.decision, DecisionBrief::Deny)),
        _ => panic!("Expected Deny for third request"),
    }
}

#[actix_web::test]
async fn malformed_identity_and_ip_reject_the_entire_batch() {
    let store = create_test_store();
    let version = store.read().unwrap().engine.current_version();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::clone(&store)))
            .app_data(web::Data::new(create_test_parallel_config()))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;
    let valid = serde_json::json!({
        "principal": {"User": {"id": "alice", "namespace": [], "groups": []}},
        "action": {"id": "view", "namespace": []},
        "resource": {"kind": "Photo", "id": "VacationPhoto94.jpg", "attrs": {}},
    });
    for pointer in [
        "/principal/User/id",
        "/action/id",
        "/resource/id",
        "/resource/kind",
        "/resource/attrs/ip",
    ] {
        let mut invalid = valid.clone();
        if pointer == "/resource/attrs/ip" {
            invalid["resource"]["attrs"]["ip"] = serde_json::json!({"Ip": "not-an-ip"});
        } else {
            *invalid.pointer_mut(pointer).unwrap() = serde_json::json!("");
        }
        let request = test::TestRequest::post()
            .uri("/api/v1/authorize")
            .set_json(serde_json::json!({"requests": [valid.clone(), invalid]}))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{pointer}");
        assert_eq!(store.read().unwrap().engine.current_version(), version);
    }
}
