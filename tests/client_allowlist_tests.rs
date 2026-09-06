use actix_web::{
    App, HttpResponse,
    http::{StatusCode, header},
    middleware::Condition,
    test, web,
};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use treetop_rest::config::AdmissionConfig;
use treetop_rest::handlers;
use treetop_rest::middleware::AccessControlMiddleware;
use treetop_rest::state::PolicyStore;

const ALLOWED_TOKEN: &str = "correct-token";

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn peer(address: &str) -> SocketAddr {
    address.parse().unwrap()
}

async fn assert_error_body(response: actix_web::dev::ServiceResponse, code: &str) {
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["code"], code);
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );
}

#[actix_web::test]
async fn supports_open_acl_token_and_combined_modes() {
    let cases = [
        (None, None, "192.0.2.4:1234", None, StatusCode::OK),
        (
            Some("192.0.2.0/24"),
            None,
            "192.0.2.4:1234",
            None,
            StatusCode::OK,
        ),
        (
            None,
            Some(ALLOWED_TOKEN),
            "192.0.2.4:1234",
            Some(ALLOWED_TOKEN),
            StatusCode::OK,
        ),
        (
            Some("192.0.2.0/24"),
            Some(ALLOWED_TOKEN),
            "192.0.2.4:1234",
            Some(ALLOWED_TOKEN),
            StatusCode::OK,
        ),
    ];

    for (allowlist, tokens, peer_address, token, expected) in cases {
        let config = AdmissionConfig::parse(allowlist, tokens, None).unwrap();
        let app = test::init_service(
            App::new()
                .wrap(Condition::new(
                    config.enabled(),
                    AccessControlMiddleware::new(config),
                ))
                .route("/api/v1/test", web::get().to(ok_handler)),
        )
        .await;
        let mut request = test::TestRequest::get()
            .uri("/api/v1/test")
            .peer_addr(peer(peer_address));
        if let Some(token) = token {
            request = request.insert_header((header::AUTHORIZATION, format!("Bearer {token}")));
        }

        let response = test::call_service(&app, request.to_request()).await;
        assert_eq!(response.status(), expected);
    }
}

#[actix_web::test]
async fn acl_runs_before_token_authentication() {
    let config = AdmissionConfig::parse(Some("192.0.2.0/24"), Some(ALLOWED_TOKEN), None).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;
    let request = test::TestRequest::get()
        .uri("/api/v1/test")
        .peer_addr(peer("198.51.100.2:1234"))
        .to_request();

    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_error_body(response.map_into_boxed_body(), "client_not_allowed").await;
}

#[actix_web::test]
async fn bearer_failures_share_one_response_and_challenge() {
    let config = AdmissionConfig::parse(None, Some(ALLOWED_TOKEN), None).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;

    let requests = [
        test::TestRequest::get().uri("/api/v1/test").to_request(),
        test::TestRequest::get()
            .uri("/api/v1/test")
            .insert_header((header::AUTHORIZATION, "Bearer wrong-token"))
            .to_request(),
        test::TestRequest::get()
            .uri("/api/v1/test")
            .insert_header((header::AUTHORIZATION, "Basic credential"))
            .to_request(),
        test::TestRequest::get()
            .uri("/api/v1/test")
            .insert_header((header::AUTHORIZATION, "Bearer token with spaces"))
            .to_request(),
        test::TestRequest::get()
            .uri("/api/v1/test")
            .append_header((header::AUTHORIZATION, "Bearer wrong-token"))
            .append_header((header::AUTHORIZATION, format!("Bearer {ALLOWED_TOKEN}")))
            .to_request(),
    ];

    for request in requests {
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );
        assert_error_body(response.map_into_boxed_body(), "invalid_access_token").await;
    }
}

#[actix_web::test]
async fn public_routes_bypass_both_controls() {
    let config = AdmissionConfig::parse(
        Some("10.0.0.0/8"),
        Some(ALLOWED_TOKEN),
        Some("192.0.2.0/24"),
    )
    .unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/livez", web::get().to(ok_handler))
            .route("/readyz", web::get().to(ok_handler))
            .route("/openapi.json", web::get().to(ok_handler))
            .route("/swagger-ui/{tail:.*}", web::get().to(ok_handler)),
    )
    .await;

    for path in [
        "/livez",
        "/readyz",
        "/openapi.json",
        "/swagger-ui/index.html",
    ] {
        let request = test::TestRequest::get()
            .uri(path)
            .peer_addr(peer("192.0.2.5:1234"))
            .insert_header(("x-forwarded-for", "malformed"))
            .to_request();
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK,
            "{path}"
        );
    }
}

#[actix_web::test]
async fn metrics_is_protected() {
    let config = AdmissionConfig::parse(None, Some(ALLOWED_TOKEN), None).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/metrics", web::get().to(ok_handler)),
    )
    .await;

    let denied = test::TestRequest::get().uri("/metrics").to_request();
    assert_eq!(
        test::call_service(&app, denied).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let allowed = test::TestRequest::get()
        .uri("/metrics")
        .insert_header((header::AUTHORIZATION, format!("Bearer {ALLOWED_TOKEN}")))
        .to_request();
    assert_eq!(
        test::call_service(&app, allowed).await.status(),
        StatusCode::OK
    );
}

#[actix_web::test]
async fn percent_encoded_protected_routes_cannot_bypass_admission() {
    let config = AdmissionConfig::parse(None, Some(ALLOWED_TOKEN), None).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/api/v1/test", web::get().to(ok_handler))
            .route("/metrics", web::get().to(ok_handler)),
    )
    .await;

    for path in ["/%61pi/v1/test", "/%6Detrics"] {
        let denied = test::TestRequest::get().uri(path).to_request();
        assert_eq!(
            test::call_service(&app, denied).await.status(),
            StatusCode::UNAUTHORIZED,
            "{path}"
        );

        let allowed = test::TestRequest::get()
            .uri(path)
            .insert_header((header::AUTHORIZATION, format!("Bearer {ALLOWED_TOKEN}")))
            .to_request();
        assert_eq!(
            test::call_service(&app, allowed).await.status(),
            StatusCode::OK,
            "{path}"
        );
    }
}

#[actix_web::test]
async fn trusted_proxy_chain_is_walked_from_the_peer() {
    let config =
        AdmissionConfig::parse(Some("198.51.100.0/24"), None, Some("203.0.113.0/24")).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/api/v1/test")
        .peer_addr(peer("203.0.113.8:443"))
        .insert_header(("x-forwarded-for", "192.0.2.99, 198.51.100.7, 203.0.113.9"))
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::OK
    );
}

#[actix_web::test]
async fn untrusted_peers_cannot_spoof_forwarding_headers() {
    let config =
        AdmissionConfig::parse(Some("198.51.100.0/24"), None, Some("203.0.113.0/24")).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;
    let request = test::TestRequest::get()
        .uri("/api/v1/test")
        .peer_addr(peer("192.0.2.9:1234"))
        .insert_header(("x-forwarded-for", "198.51.100.7"))
        .to_request();

    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[actix_web::test]
async fn irrelevant_forwarding_headers_are_not_parsed() {
    let acl = AdmissionConfig::parse(Some("192.0.2.0/24"), None, None).unwrap();
    let acl_app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(acl))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;
    let direct = test::TestRequest::get()
        .uri("/api/v1/test")
        .peer_addr(peer("192.0.2.9:1234"))
        .insert_header(("x-forwarded-for", "malformed"))
        .to_request();
    assert_eq!(
        test::call_service(&acl_app, direct).await.status(),
        StatusCode::OK
    );

    let token = AdmissionConfig::parse(None, Some(ALLOWED_TOKEN), None).unwrap();
    let token_app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(token))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;
    let token_only = test::TestRequest::get()
        .uri("/api/v1/test")
        .insert_header(("x-forwarded-for", "malformed"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {ALLOWED_TOKEN}")))
        .to_request();
    assert_eq!(
        test::call_service(&token_app, token_only).await.status(),
        StatusCode::OK
    );
}

#[actix_web::test]
async fn malformed_or_missing_trusted_proxy_chains_fail_closed() {
    let config =
        AdmissionConfig::parse(Some("198.51.100.0/24"), None, Some("203.0.113.0/24")).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;

    for forwarded in [
        None,
        Some("198.51.100.7, malformed"),
        Some("[2001:db8::1]junk"),
    ] {
        let mut request = test::TestRequest::get()
            .uri("/api/v1/test")
            .peer_addr(peer("203.0.113.8:443"));
        if let Some(forwarded) = forwarded {
            request = request.insert_header(("x-forwarded-for", forwarded));
        }
        assert_eq!(
            test::call_service(&app, request.to_request())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[actix_web::test]
async fn ipv6_addresses_and_trusted_proxies_are_supported() {
    let config =
        AdmissionConfig::parse(Some("2001:db8:1::/48"), None, Some("2001:db8:2::/48")).unwrap();
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .route("/api/v1/test", web::get().to(ok_handler)),
    )
    .await;
    let request = test::TestRequest::get()
        .uri("/api/v1/test")
        .peer_addr(peer("[2001:db8:2::8]:443"))
        .insert_header(("x-forwarded-for", "2001:db8:1::7"))
        .to_request();

    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::OK
    );
}

#[actix_web::test]
async fn uploads_require_access_and_upload_tokens_together() {
    let config = AdmissionConfig::parse(None, Some(ALLOWED_TOKEN), None).unwrap();
    let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
    {
        let mut guard = store.write().unwrap();
        guard.allow_upload = true;
        guard.upload_token = Some("upload-token".to_owned());
    }
    let app = test::init_service(
        App::new()
            .wrap(AccessControlMiddleware::new(config))
            .app_data(web::Data::new(store))
            .configure(handlers::init),
    )
    .await;

    let without_access = test::TestRequest::post()
        .uri("/api/v1/policies")
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .insert_header(("x-upload-token", "upload-token"))
        .set_payload(include_str!("../testdata/default.cedar"))
        .to_request();
    assert_eq!(
        test::call_service(&app, without_access).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let without_upload = test::TestRequest::post()
        .uri("/api/v1/policies")
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {ALLOWED_TOKEN}")))
        .set_payload(include_str!("../testdata/default.cedar"))
        .to_request();
    assert_eq!(
        test::call_service(&app, without_upload).await.status(),
        StatusCode::FORBIDDEN
    );

    let both = test::TestRequest::post()
        .uri("/api/v1/policies")
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {ALLOWED_TOKEN}")))
        .insert_header(("x-upload-token", "upload-token"))
        .set_payload(include_str!("../testdata/default.cedar"))
        .to_request();
    assert_eq!(
        test::call_service(&app, both).await.status(),
        StatusCode::OK
    );
}
