use actix_web::{App, HttpMessage, http::StatusCode, test, web};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Parser;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tempfile::TempDir;
use treetop_bundle::{BundleBuilder, SignaturePolicy, SigningKey, TrustStore, TrustedKey};
use treetop_core::{Action, Decision, Principal, Request, Resource, User};
use treetop_rest::config::{BundleEngineMode, BundleRuntimeConfig, Config};
use treetop_rest::handlers;
use treetop_rest::state::{PolicyStore, parse_labels};

struct BundleFixture {
    _temporary: TempDir,
    manifest: PathBuf,
}

impl BundleFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        write(
            root.join("policy.cedar"),
            r#"
@id("dns.read")
permit (
    principal,
    action == ExampleCo::DNS::Action::"read",
    resource
);
"#,
        );
        write(
            root.join("treetop-module.toml"),
            r#"
format_version = 1
name = "dns"
namespace = "ExampleCo::DNS"
policies = ["policy.cedar"]
"#,
        );
        let manifest = root.join("treetop-bundle.toml");
        write(
            &manifest,
            r#"
format_version = 1
name = "test"

[[modules]]
manifest = "treetop-module.toml"
role = "ordinary"
"#,
        );
        Self {
            _temporary: temporary,
            manifest,
        }
    }

    fn archive(&self) -> Vec<u8> {
        BundleBuilder::from_manifest(&self.manifest)
            .unwrap()
            .build(None)
            .unwrap()
            .into_bytes()
    }

    fn signed_archive(&self, signing_key: &SigningKey) -> Vec<u8> {
        BundleBuilder::from_manifest(&self.manifest)
            .unwrap()
            .build(Some(signing_key))
            .unwrap()
            .into_bytes()
    }
}

#[actix_web::test]
async fn legacy_labels_use_shared_strict_validation() {
    let error = parse_labels(
        r#"[{"kind":"App::Host","field":"name","output":"labels","patterns":[{"name":"prod","regex":"prod"}],"unexpected":true}]"#,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("unknown field"));
}

#[actix_web::test]
async fn bundle_upload_applies_complete_state_and_metadata() {
    let fixture = BundleFixture::new();
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(runtime(SignaturePolicy::AllowUnsigned)))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/api/v1/bundle")
        .insert_header(("content-type", "application/gzip"))
        .insert_header(("X-Upload-Token", "test-token"))
        .set_payload(fixture.archive())
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["bundle"]["format_version"], 1);
    assert_eq!(body["bundle"]["module_count"], 1);
    assert_eq!(body["bundle"]["signed"], false);
    let store = store.read().unwrap();
    assert!(store.policies.content.contains("dns.read"));
    assert_eq!(store.policies.entries, 1);
    assert_eq!(store.labels.entries, 0);
    assert_eq!(store.schema.entries, 0);
    assert!(store.bundle.is_some());
    assert!(store.engine.policy_store_ids().is_none());
}

#[actix_web::test]
async fn bundle_module_mode_builds_namespace_policy_stores() {
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(runtime(SignaturePolicy::AllowUnsigned)))
            .app_data(web::Data::new(BundleEngineMode::BundleModules))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let response = test::call_service(&app, bundle_request(policy_store_archive())).await;

    assert_eq!(response.status(), StatusCode::OK);
    let store = store.read().unwrap();
    let store_ids = store.engine.policy_store_ids().unwrap();
    assert_eq!(store_ids[0].as_str(), "dns");
    assert_eq!(store_ids[1].as_str(), "www");
    let request = Request {
        principal: Principal::User(User::new(
            "blocked",
            None,
            Some(vec!["Organization".to_string()]),
        )),
        action: Action::new(
            "read",
            Some(vec!["ExampleCo".to_string(), "DNS".to_string()]),
        ),
        resource: Resource::new("ExampleCo::DNS::Host", "host-1"),
    };
    assert!(matches!(
        store.engine.evaluate(&request).unwrap(),
        Decision::Deny { .. }
    ));
}

#[actix_web::test]
async fn strict_mode_rejects_bundle_without_schema() {
    let fixture = BundleFixture::new();
    let store = upload_store();
    store
        .write()
        .unwrap()
        .set_schema_validation_mode(treetop_rest::config::SchemaValidationMode::Strict);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(runtime(SignaturePolicy::AllowUnsigned)))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let response = test::call_service(&app, bundle_request(fixture.archive())).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["code"], "schema_validation_error");
    let store = store.read().unwrap();
    assert!(store.policies.content.is_empty());
    assert!(store.bundle.is_none());
}

#[actix_web::test]
async fn invalid_bundle_upload_preserves_last_known_good_state() {
    let store = upload_store();
    store
        .write()
        .unwrap()
        .set_dsl("permit(principal, action, resource);", None, None)
        .unwrap();
    let previous_hash = store.read().unwrap().policies.sha256.clone();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(runtime(SignaturePolicy::AllowUnsigned)))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/api/v1/bundle")
        .insert_header(("content-type", "application/gzip"))
        .insert_header(("X-Upload-Token", "test-token"))
        .set_payload("not a bundle")
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let store = store.read().unwrap();
    assert_eq!(store.policies.sha256, previous_hash);
    assert!(store.bundle.is_none());
}

#[actix_web::test]
async fn bundle_upload_enforces_media_type_after_authentication() {
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(runtime(SignaturePolicy::AllowUnsigned)))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let unauthorized = test::TestRequest::post()
        .uri("/api/v1/bundle")
        .insert_header(("content-type", "text/plain"))
        .insert_header(("X-Upload-Token", "wrong"))
        .set_payload("ignored")
        .to_request();
    assert_eq!(
        test::call_service(&app, unauthorized).await.status(),
        StatusCode::FORBIDDEN
    );

    let unsupported = test::TestRequest::post()
        .uri("/api/v1/bundle")
        .insert_header(("content-type", "text/plain"))
        .insert_header(("X-Upload-Token", "test-token"))
        .set_payload("ignored")
        .to_request();
    assert_eq!(
        test::call_service(&app, unsupported).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[actix_web::test]
async fn component_upload_conflicts_in_bundle_url_mode() {
    let store = upload_store();
    store.write().unwrap().bundle_url_mode = true;
    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies",
        web::post().to(handlers::upload_policies),
    ))
    .await;
    let request = test::TestRequest::post()
        .uri("/api/v1/policies")
        .insert_header(("content-type", "text/plain"))
        .insert_header(("X-Upload-Token", "test-token"))
        .set_payload("permit(principal, action, resource);")
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::CONFLICT
    );
}

#[actix_web::test]
async fn required_signatures_without_keys_fail_configuration() {
    let config =
        Config::try_parse_from(["treetop-server", "--bundle-signature-policy", "required"])
            .unwrap();
    assert!(
        config
            .bundle_runtime_config()
            .unwrap_err()
            .to_string()
            .contains("at least one trusted key")
    );
}

#[actix_web::test]
async fn required_signature_policy_rejects_unsigned_upload() {
    let fixture = BundleFixture::new();
    let (_, trusted_key) = key_pair(1);
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(runtime_with_keys(
                SignaturePolicy::Required,
                [trusted_key],
            )))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let request = bundle_request(fixture.archive());
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(store.read().unwrap().bundle.is_none());
}

#[actix_web::test]
async fn trusted_keys_support_bundle_signing_key_rotation() {
    let fixture = BundleFixture::new();
    let (first_signing, first_trusted) = key_pair(2);
    let (second_signing, second_trusted) = key_pair(3);
    let first_id = first_signing.key_id();
    let second_id = second_signing.key_id();
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(runtime_with_keys(
                SignaturePolicy::Required,
                [first_trusted, second_trusted],
            )))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let first =
        test::call_service(&app, bundle_request(fixture.signed_archive(&first_signing))).await;
    assert_eq!(first.status(), StatusCode::OK);
    let bundle_id = store
        .read()
        .unwrap()
        .bundle
        .as_ref()
        .unwrap()
        .bundle_id
        .clone();
    assert_eq!(
        store
            .read()
            .unwrap()
            .bundle
            .as_ref()
            .unwrap()
            .signing_key_id
            .as_deref(),
        Some(first_id.as_str())
    );

    let second = test::call_service(
        &app,
        bundle_request(fixture.signed_archive(&second_signing)),
    )
    .await;

    assert_eq!(second.status(), StatusCode::OK);
    let metadata = store.read().unwrap().bundle.clone().unwrap();
    assert_eq!(metadata.bundle_id, bundle_id);
    assert_eq!(metadata.signing_key_id.as_deref(), Some(second_id.as_str()));
}

#[actix_web::test]
async fn bundle_upload_enforces_actual_compressed_size_limit() {
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(BundleRuntimeConfig {
                signature_policy: SignaturePolicy::AllowUnsigned,
                trust_store: Arc::new(TrustStore::new()),
                max_request_bytes: usize::MAX,
                max_compressed_bytes: 4,
                max_uncompressed_bytes: 1024,
            }))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let mut request = bundle_request(vec![0; 5]);
    request.headers_mut().remove("content-length");
    assert!(request.headers().get("content-length").is_none());
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn bundle_upload_rejects_oversized_declared_length_before_reading_body() {
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(BundleRuntimeConfig {
                signature_policy: SignaturePolicy::AllowUnsigned,
                trust_store: Arc::new(TrustStore::new()),
                max_request_bytes: usize::MAX,
                max_compressed_bytes: 4,
                max_uncompressed_bytes: 1024,
            }))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/api/v1/bundle")
        .insert_header(("content-type", "application/gzip"))
        .insert_header(("content-length", "5"))
        .insert_header(("X-Upload-Token", "test-token"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn bundle_upload_enforces_global_request_size_limit() {
    let fixture = BundleFixture::new();
    let archive = fixture.archive();
    let store = upload_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(BundleRuntimeConfig {
                signature_policy: SignaturePolicy::AllowUnsigned,
                trust_store: Arc::new(TrustStore::new()),
                max_request_bytes: archive.len() - 1,
                max_compressed_bytes: archive.len() + 1,
                max_uncompressed_bytes: 50 * 1024 * 1024,
            }))
            .route("/api/v1/bundle", web::post().to(handlers::upload_bundle)),
    )
    .await;

    let mut request = bundle_request(archive);
    request.headers_mut().remove("content-length");
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

fn upload_store() -> Arc<RwLock<PolicyStore>> {
    let mut store = PolicyStore::new().unwrap();
    store.allow_upload = true;
    store.upload_token = Some("test-token".to_string());
    Arc::new(RwLock::new(store))
}

fn runtime(signature_policy: SignaturePolicy) -> BundleRuntimeConfig {
    BundleRuntimeConfig {
        signature_policy,
        trust_store: Arc::new(TrustStore::new()),
        max_request_bytes: 10 * 1024 * 1024,
        max_compressed_bytes: 10 * 1024 * 1024,
        max_uncompressed_bytes: 50 * 1024 * 1024,
    }
}

fn runtime_with_keys<const N: usize>(
    signature_policy: SignaturePolicy,
    trusted_keys: [TrustedKey; N],
) -> BundleRuntimeConfig {
    BundleRuntimeConfig {
        signature_policy,
        trust_store: Arc::new(TrustStore::from_keys(trusted_keys).unwrap()),
        max_request_bytes: 10 * 1024 * 1024,
        max_compressed_bytes: 10 * 1024 * 1024,
        max_uncompressed_bytes: 50 * 1024 * 1024,
    }
}

fn policy_store_archive() -> Vec<u8> {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    write(
        root.join("dns.cedar"),
        r#"
@id("dns.read")
permit (
    principal,
    action == ExampleCo::DNS::Action::"read",
    resource is ExampleCo::DNS::Host
);
"#,
    );
    write(
        root.join("dns-module.toml"),
        r#"
format_version = 1
name = "dns"
namespace = "ExampleCo::DNS"
policies = ["dns.cedar"]
"#,
    );
    write(
        root.join("www.cedar"),
        r#"
@id("www.read")
permit (
    principal,
    action == ExampleCo::WWW::Action::"read",
    resource is ExampleCo::WWW::Page
);
"#,
    );
    write(
        root.join("www-module.toml"),
        r#"
format_version = 1
name = "www"
namespace = "ExampleCo::WWW"
policies = ["www.cedar"]
"#,
    );
    write(
        root.join("global.cedar"),
        r#"
@id("platform.blocked")
forbid (
    principal == Organization::User::"blocked",
    action,
    resource
);
"#,
    );
    write(
        root.join("global-module.toml"),
        r#"
format_version = 1
name = "platform"
namespace = "ExampleCo::Platform"
policies = ["global.cedar"]
"#,
    );
    let manifest = root.join("treetop-bundle.toml");
    write(
        &manifest,
        r#"
format_version = 1
name = "scoped"

[[modules]]
manifest = "dns-module.toml"

[[modules]]
manifest = "www-module.toml"

[[modules]]
manifest = "global-module.toml"
role = "global"
"#,
    );
    BundleBuilder::from_manifest(manifest)
        .unwrap()
        .build(None)
        .unwrap()
        .into_bytes()
}

fn bundle_request(bytes: Vec<u8>) -> actix_http::Request {
    test::TestRequest::post()
        .uri("/api/v1/bundle")
        .insert_header(("content-type", "application/gzip"))
        .insert_header(("X-Upload-Token", "test-token"))
        .set_payload(bytes)
        .to_request()
}

fn key_pair(seed: u8) -> (SigningKey, TrustedKey) {
    let dalek = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let private_pem = pem("PRIVATE KEY", dalek.to_pkcs8_der().unwrap().as_bytes());
    let public_der = dalek.verifying_key().to_public_key_der().unwrap();
    let public_pem = pem("PUBLIC KEY", public_der.as_bytes());
    (
        SigningKey::from_pkcs8_pem(&private_pem).unwrap(),
        TrustedKey::from_spki_pem(&public_pem).unwrap(),
    )
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

fn write(path: impl AsRef<Path>, contents: &str) {
    fs::write(path, contents).unwrap();
}
