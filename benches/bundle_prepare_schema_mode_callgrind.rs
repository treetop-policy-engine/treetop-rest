use gungraun::{library_benchmark, library_benchmark_group, main};
use std::fs;
use treetop_bundle::{
    ArchiveLimits, BundleArchive, BundleBuilder, SignaturePolicy, TrustStore, ValidatedBundle,
};
use treetop_rest::config::SchemaValidationMode;
use treetop_rest::errors::ServiceError;
use treetop_rest::state::{PolicyStore, PreparedBundle};

type PreparedResult = (ValidatedBundle, PreparedBundle);
type RejectedResult = (ValidatedBundle, ServiceError);

fn setup() -> ValidatedBundle {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    fs::write(
        root.join("policy.cedar"),
        concat!(
            "@id(\"benchmark.allow\")\n",
            "permit (principal, action == Benchmark::Action::\"read\", resource);"
        ),
    )
    .unwrap();
    fs::write(
        root.join("treetop-module.toml"),
        r#"
format_version = 2
name = "benchmark"
namespace = "Benchmark"
policies = ["policy.cedar"]
"#,
    )
    .unwrap();
    let manifest = root.join("treetop-bundle.toml");
    fs::write(
        &manifest,
        r#"
format_version = 2
name = "benchmark"

[[modules]]
manifest = "treetop-module.toml"
role = "ordinary"
"#,
    )
    .unwrap();

    let bytes = BundleBuilder::from_manifest(&manifest)
        .unwrap()
        .build(None)
        .unwrap()
        .into_bytes();
    BundleArchive::from_bytes(bytes)
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::new(10 * 1024 * 1024, 50 * 1024 * 1024).unwrap(),
        )
        .unwrap()
}

fn teardown_prepared(_: PreparedResult) {}

fn teardown_rejected(_: RejectedResult) {}

#[library_benchmark(setup = setup, teardown = teardown_prepared)]
fn prepare_schema_free_permissive(validated: ValidatedBundle) -> PreparedResult {
    let prepared =
        PolicyStore::prepare_bundle(&validated, None, None, SchemaValidationMode::Permissive)
            .unwrap();
    (validated, prepared)
}

#[library_benchmark(setup = setup, teardown = teardown_rejected)]
fn reject_schema_free_strict(validated: ValidatedBundle) -> RejectedResult {
    let error = PolicyStore::prepare_bundle(&validated, None, None, SchemaValidationMode::Strict)
        .err()
        .unwrap();
    (validated, error)
}

library_benchmark_group!(
    name = bundle_prepare_schema_mode;
    benchmarks = prepare_schema_free_permissive, reject_schema_free_strict
);

main!(library_benchmark_groups = bundle_prepare_schema_mode);
