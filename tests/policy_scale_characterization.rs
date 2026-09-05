//! Shared-corpus REST correctness coverage and opt-in scale characterization.
//!
//! The ordinary test exercises a fixed 1,000-policy corpus. The ignored test
//! performs machine-dependent release-mode measurements selected with
//! `TREETOP_SCALE_POLICY_COUNT`.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use actix_web::{App, HttpServer, dev::ServerHandle, test as actix_test, web};
use cedar_policy::SchemaFragment;
use futures_util::{StreamExt, stream};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::watch;
use treetop_core::bench_helpers::policy_scale::{
    CORPUS_VERSION, REVIEWERS_GROUP, ScaleCorpus, TARGET_USER, allow_request,
    configured_policy_count, forbid_request, group_request, no_match_request,
};
use treetop_rest::config::SchemaValidationMode;
use treetop_rest::handlers;
use treetop_rest::middleware::TracingMiddleware;
use treetop_rest::models::AuthorizeRequest;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const SMOKE_POLICY_COUNT: usize = 1_000;
const SOAK_WINDOW: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Workload {
    name: &'static str,
    path: &'static str,
    body: Arc<[u8]>,
    expected_decisions: Arc<[&'static str]>,
}

impl Workload {
    fn authorize(
        name: &'static str,
        path: &'static str,
        requests: impl IntoIterator<Item = treetop_core::Request>,
        expected_decisions: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        let body = serde_json::to_vec(&AuthorizeRequest::from_requests(requests))
            .expect("shared scale request should serialize");
        Self {
            name,
            path,
            body: body.into(),
            expected_decisions: expected_decisions.into_iter().collect::<Vec<_>>().into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RawRun {
    workload: String,
    concurrency: usize,
    elapsed_ns: u128,
    samples_ns: Vec<u128>,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    workload: String,
    concurrency: usize,
    requests_per_second: f64,
    mean_us: f64,
    p50_us: f64,
    p90_us: f64,
    p95_us: f64,
    p99_us: f64,
    max_us: f64,
}

impl RunSummary {
    fn from_run(run: &RawRun) -> Self {
        summarize_durations(
            run.workload.clone(),
            run.concurrency,
            run.elapsed_ns,
            &run.samples_ns,
        )
    }
}

#[derive(Debug, Serialize)]
struct TimedOperation {
    name: String,
    elapsed_us: f64,
    response_bytes: Option<usize>,
}

#[derive(Debug, Serialize)]
struct MemorySample {
    phase: String,
    rss_kib: Option<u64>,
    high_water_rss_kib: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ControlPlaneTimings {
    corpus_generation_ms: f64,
    schema_conversion_ms: f64,
    schema_load_ms: f64,
    initial_policy_load_ms: f64,
    successful_reload_ms: f64,
    rejected_reload_ms: f64,
}

#[derive(Debug, Serialize)]
struct CorpusMetadata {
    version: u32,
    policy_count: usize,
    initial_generation: usize,
    replacement_generation: usize,
    initial_policy_bytes: usize,
    replacement_policy_bytes: usize,
}

#[derive(Debug, Serialize)]
struct AnonymousEnvironment {
    cpu_model: String,
    logical_cpus: usize,
    cpu_affinity: String,
    os: &'static str,
    architecture: &'static str,
    kernel: String,
    cpu_governor: String,
    rust_version: String,
    target: String,
    build_profile: String,
    allocator: &'static str,
    treetop_rest_version: &'static str,
    treetop_rest_sha: String,
    treetop_rest_dirty: bool,
    treetop_core_version: String,
    treetop_core_sha: String,
    treetop_core_dirty: bool,
    cedar_version: &'static str,
    parallel: ParallelConfig,
}

#[derive(Debug, Serialize)]
struct CharacterizationConfig {
    samples_per_workload: usize,
    warmup_requests_per_workload: usize,
    concurrencies: Vec<usize>,
    soak_seconds: u64,
    reload_interval_seconds: u64,
    soak_window_seconds: u64,
}

#[derive(Debug, Serialize)]
struct MetricDistributionSummary {
    metric: String,
    labels: Vec<(String, String)>,
    count: u64,
    mean_us: f64,
    classic_p95_upper_bound_us: Option<f64>,
}

#[derive(Debug, Serialize)]
struct MetricsSummary {
    scrape_bytes: usize,
    scrape_elapsed_us: f64,
    series: usize,
    distributions: Vec<MetricDistributionSummary>,
}

#[derive(Debug, Serialize)]
struct SoakWindowSummary {
    started_after_seconds: f64,
    ended_after_seconds: f64,
    requests: usize,
    requests_per_second: f64,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    max_us: f64,
}

#[derive(Debug, Serialize)]
struct ReloadSummary {
    count: usize,
    mean_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Serialize)]
struct SoakSummary {
    windows: Vec<SoakWindowSummary>,
    reloads: ReloadSummary,
}

#[derive(Debug, Serialize)]
struct ScaleReport {
    schema_version: u8,
    privacy_notice: &'static str,
    environment: AnonymousEnvironment,
    corpus: CorpusMetadata,
    configuration: CharacterizationConfig,
    control_plane: ControlPlaneTimings,
    memory: Vec<MemorySample>,
    http_summaries: Vec<RunSummary>,
    management_operations: Vec<TimedOperation>,
    metrics: MetricsSummary,
    soak: Option<SoakSummary>,
    raw_http_runs: Vec<RawRun>,
}

fn schema_json(corpus: &ScaleCorpus) -> String {
    SchemaFragment::from_cedarschema_str(&corpus.schema_text)
        .expect("shared scale schema should parse")
        .0
        .to_json_string()
        .expect("shared scale schema should serialize as JSON")
}

fn initialize_store(corpus: &ScaleCorpus) -> PolicyStore {
    let mut store = PolicyStore::new().expect("policy store should initialize");
    store.set_schema_validation_mode(SchemaValidationMode::Strict);
    store
        .set_schema(&schema_json(corpus), None, None)
        .expect("shared scale schema should load");
    store
        .set_dsl(&corpus.policy_text, None, None)
        .expect("shared scale policies should load");
    store
}

fn assert_shared_decisions(store: &PolicyStore) {
    assert!(
        store
            .engine
            .evaluate(&allow_request())
            .unwrap()
            .is_allowed()
    );
    assert!(
        !store
            .engine
            .evaluate(&forbid_request())
            .unwrap()
            .is_allowed()
    );
    assert!(
        store
            .engine
            .evaluate(&group_request())
            .unwrap()
            .is_allowed()
    );
    assert!(
        !store
            .engine
            .evaluate(&no_match_request())
            .unwrap()
            .is_allowed()
    );
}

fn workloads() -> Vec<Workload> {
    vec![
        Workload::authorize(
            "authorize_allow_brief",
            "/api/v1/authorize",
            [allow_request()],
            ["Allow"],
        ),
        Workload::authorize(
            "authorize_forbid_brief",
            "/api/v1/authorize",
            [forbid_request()],
            ["Deny"],
        ),
        Workload::authorize(
            "authorize_group_brief",
            "/api/v1/authorize",
            [group_request()],
            ["Allow"],
        ),
        Workload::authorize(
            "authorize_no_match_brief",
            "/api/v1/authorize",
            [no_match_request()],
            ["Deny"],
        ),
        Workload::authorize(
            "authorize_allow_full",
            "/api/v1/authorize?detail=full",
            [allow_request()],
            ["Allow"],
        ),
        Workload::authorize(
            "authorize_forbid_full",
            "/api/v1/authorize?detail=full",
            [forbid_request()],
            ["Deny"],
        ),
        Workload::authorize(
            "authorize_mixed_batch_8_brief",
            "/api/v1/authorize",
            [
                allow_request(),
                forbid_request(),
                group_request(),
                no_match_request(),
                allow_request(),
                forbid_request(),
                group_request(),
                no_match_request(),
            ],
            [
                "Allow", "Deny", "Allow", "Deny", "Allow", "Deny", "Allow", "Deny",
            ],
        ),
        Workload::authorize(
            "authorize_mixed_batch_8_full",
            "/api/v1/authorize?detail=full",
            [
                allow_request(),
                forbid_request(),
                group_request(),
                no_match_request(),
                allow_request(),
                forbid_request(),
                group_request(),
                no_match_request(),
            ],
            [
                "Allow", "Deny", "Allow", "Deny", "Allow", "Deny", "Allow", "Deny",
            ],
        ),
    ]
}

fn assert_response_decisions(body: &[u8], expected: &[&str]) {
    let value: Value = serde_json::from_slice(body).expect("authorization response should be JSON");
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .expect("authorization response should contain results");
    assert_eq!(results.len(), expected.len());
    for (result, expected) in results.iter().zip(expected) {
        assert_eq!(
            result.pointer("/result/decision").and_then(Value::as_str),
            Some(*expected)
        );
    }
}

fn env_positive_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|value| *value > 0)
            .unwrap_or_else(|| panic!("{name} must be a positive integer, got {raw:?}")),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("failed to read {name}: {error}"),
    }
}

fn env_nonnegative_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{name} must be a non-negative integer, got {raw:?}")),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("failed to read {name}: {error}"),
    }
}

fn configured_concurrencies(cpu_count: usize) -> Vec<usize> {
    let mut values = std::env::var("TREETOP_REST_SCALE_CONCURRENCIES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .map(|value| {
                    value.parse::<usize>().ok().filter(|value| *value > 0).unwrap_or_else(|| {
                        panic!(
                            "TREETOP_REST_SCALE_CONCURRENCIES must contain positive integers, got {raw:?}"
                        )
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![1, cpu_count.clamp(1, 8)]);
    values.sort_unstable();
    values.dedup();
    values
}

fn scale_defaults(policy_count: usize) -> (usize, usize) {
    if policy_count <= 1_000 {
        (1_000, 100)
    } else if policy_count <= 10_000 {
        (250, 50)
    } else {
        (25, 5)
    }
}

fn memory_sample(phase: &str) -> MemorySample {
    let status = fs::read_to_string("/proc/self/status").ok();
    let field = |name: &str| {
        status.as_deref().and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
        })
    };
    MemorySample {
        phase: phase.to_owned(),
        rss_kib: field("VmRSS:"),
        high_water_rss_kib: field("VmHWM:"),
    }
}

fn anonymous_environment(parallel: ParallelConfig) -> AnonymousEnvironment {
    let build = treetop_rest::build_info::build_info();
    let cpu_model = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|line| line.split_once(':'))
                    .map(|(_, value)| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let cpu_governor = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let cpu_affinity = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("Cpus_allowed_list:")
                    .map(|value| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());

    AnonymousEnvironment {
        cpu_model,
        logical_cpus: std::thread::available_parallelism().unwrap().get(),
        cpu_affinity,
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        kernel,
        cpu_governor,
        rust_version: build.rustc_semver.unwrap_or("unknown").to_owned(),
        target: build.target_triple.unwrap_or("unknown").to_owned(),
        build_profile: build
            .profile
            .unwrap_or(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .to_owned(),
        allocator: "system",
        treetop_rest_version: build.crate_version,
        treetop_rest_sha: build
            .git
            .as_ref()
            .map(|git| git.sha)
            .filter(|sha| !sha.is_empty())
            .unwrap_or("unknown")
            .to_owned(),
        treetop_rest_dirty: build.git.as_ref().is_some_and(|git| git.dirty),
        treetop_core_version: build.core.clone(),
        treetop_core_sha: build
            .core_sha
            .filter(|sha| !sha.is_empty())
            .unwrap_or("unknown")
            .to_owned(),
        treetop_core_dirty: treetop_core::build_info()
            .git
            .as_ref()
            .is_some_and(|git| git.dirty),
        cedar_version: build.cedar,
        parallel,
    }
}

fn spawn_server(store: Arc<RwLock<PolicyStore>>) -> (String, ServerHandle, ParallelConfig) {
    let registry = treetop_rest::metrics::init_prometheus()
        .expect("Prometheus registry should initialize for scale characterization");
    let parallel = treetop_rest::parallel::init_parallelism(
        std::env::var("TREETOP_REST_SCALE_WORKERS")
            .ok()
            .and_then(|value| value.parse().ok()),
        std::env::var("TREETOP_REST_SCALE_RAYON_THREADS")
            .ok()
            .and_then(|value| value.parse().ok()),
        std::env::var("TREETOP_REST_SCALE_PAR_THRESHOLD")
            .ok()
            .and_then(|value| value.parse().ok()),
    );
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = HttpServer::new(move || {
        App::new()
            .wrap(TracingMiddleware::new())
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(parallel))
            .app_data(web::Data::new(registry.clone()))
            .configure(handlers::init)
    })
    .workers(parallel.workers)
    .listen(listener)
    .unwrap()
    .run();
    let handle = server.handle();
    actix_web::rt::spawn(server);
    (format!("http://{address}"), handle, parallel)
}

async fn send_workload(
    client: &reqwest::Client,
    base_url: &str,
    workload: &Workload,
    validate: bool,
) -> (Duration, usize) {
    let started = Instant::now();
    let response = client
        .post(format!("{base_url}{}", workload.path))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(workload.body.to_vec())
        .send()
        .await
        .unwrap_or_else(|error| panic!("{} request failed: {error}", workload.name));
    let status = response.status();
    let body = response.bytes().await.expect("response body should read");
    assert!(
        status.is_success(),
        "{} returned {status}: {}",
        workload.name,
        String::from_utf8_lossy(&body)
    );
    if validate {
        assert_response_decisions(&body, &workload.expected_decisions);
    }
    (started.elapsed(), body.len())
}

async fn run_workload(
    client: &reqwest::Client,
    base_url: &str,
    workload: &Workload,
    warmup: usize,
    samples: usize,
    concurrency: usize,
) -> RawRun {
    let _ = send_workload(client, base_url, workload, true).await;
    let warmups = stream::iter(0..warmup)
        .map(|_| send_workload(client, base_url, workload, false))
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;
    assert_eq!(warmups.len(), warmup);

    let started = Instant::now();
    let durations = stream::iter(0..samples)
        .map(|_| send_workload(client, base_url, workload, false))
        .buffer_unordered(concurrency)
        .map(|(duration, _)| duration.as_nanos())
        .collect::<Vec<_>>()
        .await;
    RawRun {
        workload: workload.name.to_owned(),
        concurrency,
        elapsed_ns: started.elapsed().as_nanos(),
        samples_ns: durations,
    }
}

async fn timed_get(
    client: &reqwest::Client,
    base_url: &str,
    name: &str,
    path: &str,
) -> TimedOperation {
    let started = Instant::now();
    let response = client
        .get(format!("{base_url}{path}"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("{name} request failed: {error}"));
    let status = response.status();
    let body = response.bytes().await.expect("response body should read");
    assert!(status.is_success(), "{name} returned {status}");
    TimedOperation {
        name: name.to_owned(),
        elapsed_us: started.elapsed().as_secs_f64() * 1_000_000.0,
        response_bytes: Some(body.len()),
    }
}

fn summarize_durations(
    workload: String,
    concurrency: usize,
    elapsed_ns: u128,
    samples: &[u128],
) -> RunSummary {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let mean_ns = sorted.iter().sum::<u128>() as f64 / sorted.len() as f64;
    RunSummary {
        workload,
        concurrency,
        requests_per_second: sorted.len() as f64 / (elapsed_ns as f64 / 1_000_000_000.0),
        mean_us: mean_ns / 1_000.0,
        p50_us: percentile(&sorted, 0.50) / 1_000.0,
        p90_us: percentile(&sorted, 0.90) / 1_000.0,
        p95_us: percentile(&sorted, 0.95) / 1_000.0,
        p99_us: percentile(&sorted, 0.99) / 1_000.0,
        max_us: *sorted.last().expect("summary requires samples") as f64 / 1_000.0,
    }
}

fn percentile(sorted: &[u128], quantile: f64) -> f64 {
    let rank = (quantile * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)] as f64
}

fn metric_value(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    metrics
        .lines()
        .find(|line| {
            line.starts_with(name)
                && labels
                    .iter()
                    .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
}

fn classic_p95_upper_bound(
    metrics: &str,
    name: &str,
    labels: &[(&str, &str)],
    count: f64,
) -> Option<f64> {
    let target = count * 0.95;
    metrics.lines().find_map(|line| {
        if !line.starts_with(&format!("{name}_bucket"))
            || !labels
                .iter()
                .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        {
            return None;
        }
        let observed = line
            .split_whitespace()
            .last()
            .and_then(|value| value.parse::<f64>().ok())?;
        if observed < target {
            return None;
        }
        let le = line
            .split("le=\"")
            .nth(1)
            .and_then(|value| value.split('"').next())?;
        if le == "+Inf" {
            None
        } else {
            le.parse::<f64>().ok().map(|seconds| seconds * 1_000_000.0)
        }
    })
}

fn distribution_summary(
    metrics: &str,
    name: &str,
    labels: &[(&str, &str)],
) -> Option<MetricDistributionSummary> {
    let count = metric_value(metrics, &format!("{name}_count"), labels)?;
    if count == 0.0 {
        return None;
    }
    let sum = metric_value(metrics, &format!("{name}_sum"), labels)?;
    Some(MetricDistributionSummary {
        metric: name.to_owned(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        count: count as u64,
        mean_us: sum / count * 1_000_000.0,
        classic_p95_upper_bound_us: classic_p95_upper_bound(metrics, name, labels, count),
    })
}

fn metrics_summary(metrics: &str, scrape_elapsed: Duration) -> MetricsSummary {
    let mut distributions = Vec::new();
    for path in [
        "/api/v1/authorize",
        "/api/v1/policies",
        "/api/v1/policies/{user}",
        "/metrics",
    ] {
        if let Some(summary) = distribution_summary(
            metrics,
            "http_request_duration_seconds",
            &[("method", "POST"), ("path", path), ("status_code", "200")],
        )
        .or_else(|| {
            distribution_summary(
                metrics,
                "http_request_duration_seconds",
                &[("method", "GET"), ("path", path), ("status_code", "200")],
            )
        }) {
            distributions.push(summary);
        }
    }
    for batch_class in ["1", "5-8"] {
        if let Some(summary) = distribution_summary(
            metrics,
            "authorization_request_duration_seconds",
            &[("batch_size_class", batch_class)],
        ) {
            distributions.push(summary);
        }
    }
    for action in [
        "Action::read",
        "Action::delete",
        "Action::review",
        "Action::noise_00",
    ] {
        if let Some(summary) = distribution_summary(
            metrics,
            "policy_eval_duration_seconds",
            &[("action", action)],
        ) {
            distributions.push(summary);
        }
        for phase in [
            "apply_labels",
            "construct_entities",
            "resolve_groups",
            "cedar_authorize",
            "overhead",
        ] {
            if let Some(summary) = distribution_summary(
                metrics,
                "policy_eval_phase_duration_seconds",
                &[("action", action), ("phase", phase)],
            ) {
                distributions.push(summary);
            }
        }
    }
    MetricsSummary {
        scrape_bytes: metrics.len(),
        scrape_elapsed_us: scrape_elapsed.as_secs_f64() * 1_000_000.0,
        series: metrics
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .count(),
        distributions,
    }
}

async fn scrape_metrics(client: &reqwest::Client, base_url: &str) -> (String, Duration) {
    let _ = client
        .get(format!("{base_url}/metrics"))
        .header(reqwest::header::ACCEPT, "application/openmetrics-text")
        .send()
        .await
        .expect("first metrics scrape should succeed")
        .bytes()
        .await
        .expect("first metrics body should read");
    let started = Instant::now();
    let response = client
        .get(format!("{base_url}/metrics"))
        .header(reqwest::header::ACCEPT, "application/openmetrics-text")
        .send()
        .await
        .expect("captured metrics scrape should succeed");
    assert!(response.status().is_success());
    let metrics = response
        .text()
        .await
        .expect("captured metrics text should read");
    (metrics, started.elapsed())
}

fn summarize_reload_durations(durations: &[Duration]) -> ReloadSummary {
    if durations.is_empty() {
        return ReloadSummary {
            count: 0,
            mean_ms: 0.0,
            p95_ms: 0.0,
            max_ms: 0.0,
        };
    }
    let mut millis = durations
        .iter()
        .map(|duration| duration.as_secs_f64() * 1_000.0)
        .collect::<Vec<_>>();
    millis.sort_by(f64::total_cmp);
    let rank = (millis.len() as f64 * 0.95).ceil() as usize;
    ReloadSummary {
        count: millis.len(),
        mean_ms: millis.iter().sum::<f64>() / millis.len() as f64,
        p95_ms: millis[rank.saturating_sub(1).min(millis.len() - 1)],
        max_ms: *millis.last().unwrap(),
    }
}

struct SoakConfig<'a> {
    client: &'a reqwest::Client,
    base_url: &'a str,
    store: Arc<RwLock<PolicyStore>>,
    workloads: &'a [Workload],
    concurrency: usize,
    duration: Duration,
    reload_interval: Duration,
    initial: Arc<str>,
    replacement: Arc<str>,
}

async fn run_soak(config: SoakConfig<'_>) -> SoakSummary {
    let SoakConfig {
        client,
        base_url,
        store,
        workloads,
        concurrency,
        duration,
        reload_interval,
        initial,
        replacement,
    } = config;
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let reload_task = actix_web::rt::spawn(async move {
        let mut use_replacement = true;
        let mut durations = Vec::new();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(reload_interval) => {}
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                    continue;
                }
            }
            let store = store.clone();
            let policies = if use_replacement {
                replacement.clone()
            } else {
                initial.clone()
            };
            let elapsed = tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                store
                    .write()
                    .expect("scale store write lock should succeed")
                    .set_dsl(&policies, None, None)
                    .expect("soak replacement corpus should load");
                started.elapsed()
            })
            .await
            .expect("reload worker should complete");
            durations.push(elapsed);
            use_replacement = !use_replacement;
        }
        durations
    });

    let soak_started = Instant::now();
    let mut window_started = soak_started;
    let mut window_samples = Vec::new();
    let mut windows = Vec::new();
    let mut next_workload = 0usize;
    while soak_started.elapsed() < duration {
        let chunk = concurrency.saturating_mul(4).max(1);
        let selected = (0..chunk)
            .map(|_| {
                let workload = workloads[next_workload % workloads.len()].clone();
                next_workload += 1;
                workload
            })
            .collect::<Vec<_>>();
        let mut durations = stream::iter(selected)
            .map(|workload| async move {
                send_workload(client, base_url, &workload, false)
                    .await
                    .0
                    .as_nanos()
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;
        window_samples.append(&mut durations);
        if window_started.elapsed() >= SOAK_WINDOW {
            let ended = soak_started.elapsed();
            let window_elapsed = window_started.elapsed();
            window_samples.sort_unstable();
            windows.push(SoakWindowSummary {
                started_after_seconds: ended.as_secs_f64() - window_elapsed.as_secs_f64(),
                ended_after_seconds: ended.as_secs_f64(),
                requests: window_samples.len(),
                requests_per_second: window_samples.len() as f64 / window_elapsed.as_secs_f64(),
                p50_us: percentile(&window_samples, 0.50) / 1_000.0,
                p95_us: percentile(&window_samples, 0.95) / 1_000.0,
                p99_us: percentile(&window_samples, 0.99) / 1_000.0,
                max_us: *window_samples.last().unwrap() as f64 / 1_000.0,
            });
            window_samples.clear();
            window_started = Instant::now();
        }
    }
    if !window_samples.is_empty() {
        let ended = soak_started.elapsed();
        let window_elapsed = window_started.elapsed();
        window_samples.sort_unstable();
        windows.push(SoakWindowSummary {
            started_after_seconds: ended.as_secs_f64() - window_elapsed.as_secs_f64(),
            ended_after_seconds: ended.as_secs_f64(),
            requests: window_samples.len(),
            requests_per_second: window_samples.len() as f64 / window_elapsed.as_secs_f64(),
            p50_us: percentile(&window_samples, 0.50) / 1_000.0,
            p95_us: percentile(&window_samples, 0.95) / 1_000.0,
            p99_us: percentile(&window_samples, 0.99) / 1_000.0,
            max_us: *window_samples.last().unwrap() as f64 / 1_000.0,
        });
    }
    let _ = stop_tx.send(true);
    let reload_durations = reload_task.await.expect("reload task should stop cleanly");
    SoakSummary {
        windows,
        reloads: summarize_reload_durations(&reload_durations),
    }
}

fn markdown_summary(report: &ScaleReport) -> String {
    let mut output = format!(
        "## Treetop REST policy scale: {} policies\n\nCorpus v{}; REST {} / Core {}; Rust {}; {}/{} workers.\n\n",
        report.corpus.policy_count,
        report.corpus.version,
        report.environment.treetop_rest_version,
        report.environment.treetop_core_version,
        report.environment.rust_version,
        report.environment.parallel.workers,
        report.environment.parallel.rayon_threads,
    );
    output.push_str("| control-plane operation | milliseconds |\n| --- | ---: |\n");
    for (name, value) in [
        (
            "corpus generation",
            report.control_plane.corpus_generation_ms,
        ),
        (
            "schema conversion",
            report.control_plane.schema_conversion_ms,
        ),
        ("schema load", report.control_plane.schema_load_ms),
        (
            "initial policy load",
            report.control_plane.initial_policy_load_ms,
        ),
        (
            "successful reload",
            report.control_plane.successful_reload_ms,
        ),
        ("rejected reload", report.control_plane.rejected_reload_ms),
    ] {
        output.push_str(&format!("| {name} | {value:.3} |\n"));
    }
    output.push_str("\n| workload | concurrency | requests/s | p50 µs | p95 µs | p99 µs | max µs |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for summary in &report.http_summaries {
        output.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |\n",
            summary.workload,
            summary.concurrency,
            summary.requests_per_second,
            summary.p50_us,
            summary.p95_us,
            summary.p99_us,
            summary.max_us,
        ));
    }
    output.push_str(&format!(
        "\nCaptured `/metrics`: {} bytes, {} series, {:.1} µs.\n",
        report.metrics.scrape_bytes, report.metrics.series, report.metrics.scrape_elapsed_us,
    ));
    if let Some(soak) = &report.soak {
        output.push_str(&format!(
            "\nSoak: {} windows, {} successful reloads, reload p95 {:.1} ms.\n",
            soak.windows.len(),
            soak.reloads.count,
            soak.reloads.p95_ms
        ));
    }
    output
}

#[actix_web::test]
async fn shared_1k_corpus_loads_serves_reloads_and_preserves_last_known_good() {
    let initial = ScaleCorpus::new(SMOKE_POLICY_COUNT, 0);
    let replacement = ScaleCorpus::new(SMOKE_POLICY_COUNT, 1);
    let mut store = initialize_store(&initial);
    assert_eq!(store.policies.entries, SMOKE_POLICY_COUNT);
    assert_shared_decisions(&store);
    let initial_hash = store.policies.sha256.clone();
    store
        .set_dsl(&replacement.policy_text, None, None)
        .expect("replacement corpus should load");
    assert_ne!(store.policies.sha256, initial_hash);
    assert_shared_decisions(&store);
    let replacement_hash = store.policies.sha256.clone();
    assert!(store.set_dsl("not valid Cedar", None, None).is_err());
    assert_eq!(store.policies.sha256, replacement_hash);
    assert_shared_decisions(&store);
    let listed = store
        .list_policies_json(
            TARGET_USER.to_owned(),
            vec![REVIEWERS_GROUP.to_owned()],
            Vec::new(),
        )
        .expect("target policy list should succeed");
    assert!(!listed.policies.is_empty());

    let registry = treetop_rest::metrics::init_prometheus().unwrap();
    let store = Arc::new(RwLock::new(store));
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let app = actix_test::init_service(
        App::new()
            .wrap(TracingMiddleware::new())
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .app_data(web::Data::new(registry))
            .configure(handlers::init),
    )
    .await;
    for workload in workloads() {
        let request = actix_test::TestRequest::post()
            .uri(workload.path)
            .insert_header(("content-type", "application/json"))
            .set_payload(workload.body.to_vec())
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert!(response.status().is_success());
        let body = actix_test::read_body(response).await;
        assert_response_decisions(&body, &workload.expected_decisions);
    }
    let metrics_request = actix_test::TestRequest::get().uri("/metrics").to_request();
    let metrics_response = actix_test::call_service(&app, metrics_request).await;
    assert!(metrics_response.status().is_success());
    let metrics =
        String::from_utf8(actix_test::read_body(metrics_response).await.to_vec()).unwrap();
    assert!(metrics.contains("policy_eval_duration_seconds"));
    assert!(metrics.contains("authorization_request_duration_seconds"));
}

#[actix_web::test]
#[ignore = "machine-dependent scale characterization; run explicitly in release mode"]
async fn characterize_shared_policy_scale() {
    let policy_count = configured_policy_count();
    let (default_samples, default_warmup) = scale_defaults(policy_count);
    let samples = env_positive_usize("TREETOP_REST_SCALE_SAMPLES", default_samples);
    let warmup = env_positive_usize("TREETOP_REST_SCALE_WARMUP", default_warmup);
    let cpu_count = std::thread::available_parallelism().unwrap().get();
    let concurrencies = configured_concurrencies(cpu_count);
    let soak_seconds = env_nonnegative_u64("TREETOP_REST_SCALE_SOAK_SECONDS", 0);
    let reload_interval_seconds =
        env_nonnegative_u64("TREETOP_REST_SCALE_RELOAD_INTERVAL_SECONDS", 60);
    assert!(
        soak_seconds == 0 || reload_interval_seconds > 0,
        "soak reload interval must be positive"
    );

    let mut memory = vec![memory_sample("baseline")];
    let corpus_started = Instant::now();
    let initial = ScaleCorpus::new(policy_count, 0);
    let replacement = ScaleCorpus::new(policy_count, 1);
    let corpus_generation = corpus_started.elapsed();
    memory.push(memory_sample("after_corpus_generation"));

    let schema_started = Instant::now();
    let schema = schema_json(&initial);
    let schema_conversion = schema_started.elapsed();
    let mut store = PolicyStore::new().unwrap();
    store.set_schema_validation_mode(SchemaValidationMode::Strict);
    let schema_load_started = Instant::now();
    store.set_schema(&schema, None, None).unwrap();
    let schema_load = schema_load_started.elapsed();
    let initial_load_started = Instant::now();
    store.set_dsl(&initial.policy_text, None, None).unwrap();
    let initial_load = initial_load_started.elapsed();
    assert_shared_decisions(&store);
    memory.push(memory_sample("after_initial_load"));

    let reload_started = Instant::now();
    store.set_dsl(&replacement.policy_text, None, None).unwrap();
    let successful_reload = reload_started.elapsed();
    assert_shared_decisions(&store);
    memory.push(memory_sample("after_successful_reload"));
    let replacement_hash = store.policies.sha256.clone();
    let rejected_started = Instant::now();
    assert!(store.set_dsl("not valid Cedar", None, None).is_err());
    let rejected_reload = rejected_started.elapsed();
    assert_eq!(store.policies.sha256, replacement_hash);
    assert_shared_decisions(&store);

    let store = Arc::new(RwLock::new(store));
    let (base_url, server, parallel) = spawn_server(store.clone());
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let workloads = workloads();
    let mut raw_runs = Vec::new();
    for concurrency in concurrencies.iter().copied() {
        for workload in &workloads {
            raw_runs.push(
                run_workload(&client, &base_url, workload, warmup, samples, concurrency).await,
            );
        }
    }

    let mut management_operations = Vec::new();
    for (name, path) in [
        (
            "list_target_json_cold",
            format!("/api/v1/policies/{TARGET_USER}?groups={REVIEWERS_GROUP}"),
        ),
        (
            "list_target_json_hot",
            format!("/api/v1/policies/{TARGET_USER}?groups={REVIEWERS_GROUP}"),
        ),
        (
            "list_target_raw_cold",
            format!("/api/v1/policies/{TARGET_USER}?groups={REVIEWERS_GROUP}&format=raw"),
        ),
        (
            "list_target_raw_hot",
            format!("/api/v1/policies/{TARGET_USER}?groups={REVIEWERS_GROUP}&format=raw"),
        ),
        ("download_all_raw", "/api/v1/policies?format=raw".to_owned()),
        ("download_all_json", "/api/v1/policies".to_owned()),
    ] {
        management_operations.push(timed_get(&client, &base_url, name, &path).await);
    }

    let soak = if soak_seconds > 0 {
        Some(
            run_soak(SoakConfig {
                client: &client,
                base_url: &base_url,
                store,
                workloads: &workloads,
                concurrency: *concurrencies.last().unwrap(),
                duration: Duration::from_secs(soak_seconds),
                reload_interval: Duration::from_secs(reload_interval_seconds),
                initial: initial.policy_text.clone().into(),
                replacement: replacement.policy_text.clone().into(),
            })
            .await,
        )
    } else {
        None
    };
    memory.push(memory_sample("after_http_and_soak"));
    let (metrics_text, metrics_elapsed) = scrape_metrics(&client, &base_url).await;
    let metrics = metrics_summary(&metrics_text, metrics_elapsed);
    server.stop(false).await;

    let report = ScaleReport {
        schema_version: 1,
        privacy_notice: "JSON excludes hostname, username, filesystem paths, Git branch, policy contents, and request bodies. The companion OpenMetrics file is an exact loopback scrape and includes client_ip=127.0.0.1; review all artifacts before sharing.",
        environment: anonymous_environment(parallel),
        corpus: CorpusMetadata {
            version: CORPUS_VERSION,
            policy_count,
            initial_generation: initial.generation,
            replacement_generation: replacement.generation,
            initial_policy_bytes: initial.policy_text.len(),
            replacement_policy_bytes: replacement.policy_text.len(),
        },
        configuration: CharacterizationConfig {
            samples_per_workload: samples,
            warmup_requests_per_workload: warmup,
            concurrencies,
            soak_seconds,
            reload_interval_seconds,
            soak_window_seconds: SOAK_WINDOW.as_secs(),
        },
        control_plane: ControlPlaneTimings {
            corpus_generation_ms: corpus_generation.as_secs_f64() * 1_000.0,
            schema_conversion_ms: schema_conversion.as_secs_f64() * 1_000.0,
            schema_load_ms: schema_load.as_secs_f64() * 1_000.0,
            initial_policy_load_ms: initial_load.as_secs_f64() * 1_000.0,
            successful_reload_ms: successful_reload.as_secs_f64() * 1_000.0,
            rejected_reload_ms: rejected_reload.as_secs_f64() * 1_000.0,
        },
        memory,
        http_summaries: raw_runs.iter().map(RunSummary::from_run).collect(),
        management_operations,
        metrics,
        soak,
        raw_http_runs: raw_runs,
    };
    let markdown = markdown_summary(&report);
    println!("{markdown}");
    if let Ok(raw_output_dir) = std::env::var("TREETOP_REST_SCALE_OUTPUT_DIR") {
        let output_dir = PathBuf::from(raw_output_dir);
        fs::create_dir_all(&output_dir).expect("scale output directory should be created");
        let stem = format!("policy-scale-{policy_count}");
        fs::write(
            output_dir.join(format!("{stem}.json")),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        fs::write(output_dir.join(format!("{stem}.prom")), metrics_text).unwrap();
        fs::write(output_dir.join(format!("{stem}.md")), markdown).unwrap();
    }
}

#[test]
fn report_helpers_are_bounded_and_parse_classic_histograms() {
    let metrics = r#"
policy_eval_duration_seconds_bucket{action="Action::read",le="0.001"} 2
policy_eval_duration_seconds_bucket{action="Action::read",le="0.0025"} 10
policy_eval_duration_seconds_bucket{action="Action::read",le="+Inf"} 10
policy_eval_duration_seconds_sum{action="Action::read"} 0.01
policy_eval_duration_seconds_count{action="Action::read"} 10
"#;
    let summary = distribution_summary(
        metrics,
        "policy_eval_duration_seconds",
        &[("action", "Action::read")],
    )
    .unwrap();
    assert_eq!(summary.count, 10);
    assert_eq!(summary.mean_us, 1_000.0);
    assert_eq!(summary.classic_p95_upper_bound_us, Some(2_500.0));
    assert_eq!(scale_defaults(1_000), (1_000, 100));
    assert_eq!(scale_defaults(10_000), (250, 50));
    assert_eq!(scale_defaults(100_000), (25, 5));
    assert_eq!(summarize_reload_durations(&[]).count, 0);
}
