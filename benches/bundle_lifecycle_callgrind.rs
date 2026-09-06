use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};
use treetop_bundle::{
    ArchiveLimits, BundleArchive, BundleBuilder, SignaturePolicy, SigningKey, TrustStore,
    TrustedKey, ValidatedBundle,
};
use treetop_rest::config::SchemaValidationMode;
use treetop_rest::state::{PolicyStore, PreparedBundle};

const INITIAL_DSL: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

struct ValidationContext {
    archive: BundleArchive,
    signature_policy: SignaturePolicy,
    trust_store: TrustStore,
}

type ApplyContext = (Arc<RwLock<PolicyStore>>, PreparedBundle);
type ValidationResult = (ValidationContext, ValidatedBundle);

fn archive_limits() -> ArchiveLimits {
    ArchiveLimits::new(10 * 1024 * 1024, 50 * 1024 * 1024).unwrap()
}

fn build_archive(signing_key: Option<&SigningKey>) -> BundleArchive {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    write(
        root.join("policy.cedar"),
        r#"
@id("dns.read")
permit (
    principal is ExampleCo::DNS::User,
    action == ExampleCo::DNS::Action::"read",
    resource is ExampleCo::DNS::Host
);
"#,
    );
    write(
        root.join("schema.cedarschema"),
        r#"
namespace ExampleCo::DNS {
    entity User;
    entity Host = {
        name: String,
        labels: Set<String>,
    };
    action "read" appliesTo {
        principal: User,
        resource: Host,
    };
}
"#,
    );
    write(
        root.join("labels.json"),
        r#"[
  {
    "target": {"resource_type": "ExampleCo::DNS::Host", "attribute": "labels"}, "field": "name",
    "patterns": [{"name": "production", "regex": "^prod-"}]
  }
]"#,
    );
    write(
        root.join("treetop-module.toml"),
        r#"
format_version = 2
name = "dns"
namespace = "ExampleCo::DNS"
policies = ["policy.cedar"]
schemas = ["schema.cedarschema"]
labels = ["labels.json"]
"#,
    );
    let manifest = root.join("treetop-bundle.toml");
    write(
        &manifest,
        r#"
format_version = 2
name = "benchmark"

[[modules]]
manifest = "treetop-module.toml"
role = "ordinary"
"#,
    );

    BundleBuilder::from_manifest(&manifest)
        .unwrap()
        .build(signing_key)
        .unwrap()
}

fn setup_unsigned_validation() -> ValidationContext {
    ValidationContext {
        archive: build_archive(None),
        signature_policy: SignaturePolicy::AllowUnsigned,
        trust_store: TrustStore::new(),
    }
}

fn setup_signed_validation() -> ValidationContext {
    let (signing_key, trusted_key) = key_pair(7);
    ValidationContext {
        archive: build_archive(Some(&signing_key)),
        signature_policy: SignaturePolicy::Required,
        trust_store: TrustStore::from_keys([trusted_key]).unwrap(),
    }
}

fn setup_apply() -> ApplyContext {
    let archive = build_archive(None);
    let validated = archive
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            archive_limits(),
        )
        .unwrap();
    let prepared =
        PolicyStore::prepare_bundle(&validated, None, None, SchemaValidationMode::Strict).unwrap();

    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(INITIAL_DSL, None, None).unwrap();
    store
        .list_policies_raw("alice".to_string(), Vec::new(), Vec::new())
        .unwrap();
    store
        .list_policies_json("alice".to_string(), Vec::new(), Vec::new())
        .unwrap();
    store.set_schema_validation_mode(SchemaValidationMode::Strict);

    (Arc::new(RwLock::new(store)), prepared)
}

fn teardown_validation(_: ValidationResult) {}

fn teardown_store(_: Arc<RwLock<PolicyStore>>) {}

#[library_benchmark(setup = setup_unsigned_validation, teardown = teardown_validation)]
fn validate_unsigned_bundle(context: ValidationContext) -> ValidationResult {
    let validated = context
        .archive
        .validate(
            context.signature_policy,
            &context.trust_store,
            archive_limits(),
        )
        .unwrap();
    (context, validated)
}

#[library_benchmark(setup = setup_signed_validation, teardown = teardown_validation)]
fn validate_signed_bundle(context: ValidationContext) -> ValidationResult {
    let validated = context
        .archive
        .validate(
            context.signature_policy,
            &context.trust_store,
            archive_limits(),
        )
        .unwrap();
    (context, validated)
}

#[library_benchmark(setup = setup_apply, teardown = teardown_store)]
fn apply_prepared_bundle((store, prepared): ApplyContext) -> Arc<RwLock<PolicyStore>> {
    store
        .write()
        .unwrap()
        .apply_prepared_bundle(prepared)
        .unwrap();
    store
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

library_benchmark_group!(
    name = bundle_lifecycle;
    benchmarks = validate_unsigned_bundle, validate_signed_bundle, apply_prepared_bundle
);

main!(library_benchmark_groups = bundle_lifecycle);
