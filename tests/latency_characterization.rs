//! Opt-in end-to-end latency characterization.
//!
//! This is deliberately ignored by the normal test suite. It measures wall-clock
//! time and reports observations; it does not enforce machine-dependent latency
//! thresholds.

use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use actix_web::{App, HttpServer, dev::ServerHandle, web};
use futures_util::{StreamExt, stream};
use serde::Serialize;
use treetop_core::{Action, AttrValue, Principal, Request, Resource, User};
use treetop_rest::handlers;
use treetop_rest::middleware::TracingMiddleware;
use treetop_rest::models::AuthorizeRequest;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const POLICIES: &str = r#"
permit (
    principal == User::"bench",
    action == Action::"bench_simple",
    resource == Photo::"bench"
);

permit (
    principal == User::"bench",
    action in [
        Action::"bench_labeled",
        Action::"bench_batch_8",
        Action::"bench_batch_128"
    ],
    resource is Host
)
when {
    resource.nameLabels.contains("in_domain")
};
"#;

const LABELS: &str = include_str!("../testdata/labels.json");

#[derive(Clone)]
struct Workload {
    name: &'static str,
    path: &'static str,
    body: Option<Arc<str>>,
    metric_action: Option<&'static str>,
}

impl Workload {
    fn get(name: &'static str, path: &'static str) -> Self {
        Self {
            name,
            path,
            body: None,
            metric_action: None,
        }
    }

    fn post(name: &'static str, body: AuthorizeRequest, metric_action: &'static str) -> Self {
        Self {
            name,
            path: "/api/v1/authorize",
            body: Some(serde_json::to_string(&body).unwrap().into()),
            metric_action: Some(metric_action),
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

#[derive(Debug, Serialize)]
struct PhaseSummary {
    workload: String,
    evaluations: u64,
    total_mean_us: f64,
    apply_labels_mean_us: f64,
    construct_entities_mean_us: f64,
    resolve_groups_mean_us: f64,
    cedar_authorize_mean_us: f64,
    overhead_mean_us: f64,
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
struct CharacterizationConfig<'a> {
    samples_per_workload: usize,
    warmup_requests_per_workload: usize,
    concurrencies: &'a [usize],
}

#[derive(Debug, Serialize)]
struct AnonymousReport<'a> {
    schema_version: u8,
    privacy_notice: &'static str,
    environment: &'a AnonymousEnvironment,
    configuration: CharacterizationConfig<'a>,
    http_summaries: &'a [RunSummary],
    policy_phase_summaries: &'a [PhaseSummary],
    raw_http_runs: &'a [RawRun],
}

impl RunSummary {
    fn from_run(run: &RawRun) -> Self {
        let mut sorted = run.samples_ns.clone();
        sorted.sort_unstable();
        let count = sorted.len();
        let mean_ns = sorted.iter().sum::<u128>() as f64 / count as f64;
        let elapsed_seconds = run.elapsed_ns as f64 / 1_000_000_000.0;

        Self {
            workload: run.workload.clone(),
            concurrency: run.concurrency,
            requests_per_second: count as f64 / elapsed_seconds,
            mean_us: mean_ns / 1_000.0,
            p50_us: percentile_ns(&sorted, 0.50) / 1_000.0,
            p90_us: percentile_ns(&sorted, 0.90) / 1_000.0,
            p95_us: percentile_ns(&sorted, 0.95) / 1_000.0,
            p99_us: percentile_ns(&sorted, 0.99) / 1_000.0,
            max_us: *sorted.last().unwrap() as f64 / 1_000.0,
        }
    }
}

fn percentile_ns(sorted: &[u128], quantile: f64) -> f64 {
    let rank = (quantile * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)] as f64
}

fn simple_request(action: &str) -> Request {
    Request {
        principal: Principal::User(User::from_str("bench").unwrap()),
        action: Action::from_str(action).unwrap(),
        resource: Resource::new("Photo", "bench").unwrap(),
    }
}

fn labeled_request(action: &str) -> Request {
    Request {
        principal: Principal::User(User::from_str("bench").unwrap()),
        action: Action::from_str(action).unwrap(),
        resource: Resource::new("Host", "web-01.example.com")
            .unwrap()
            .with_attr("name", AttrValue::String("web-01.example.com".to_owned())),
    }
}

fn workloads() -> Vec<Workload> {
    vec![
        Workload::get("livez", "/livez"),
        Workload::get("policies", "/api/v1/policies"),
        Workload::post(
            "authorize_simple",
            AuthorizeRequest::single(simple_request("bench_simple")),
            "Action::bench_simple",
        ),
        Workload::post(
            "authorize_labeled",
            AuthorizeRequest::single(labeled_request("bench_labeled")),
            "Action::bench_labeled",
        ),
        Workload::post(
            "authorize_batch_8",
            AuthorizeRequest::from_requests((0..8).map(|_| labeled_request("bench_batch_8"))),
            "Action::bench_batch_8",
        ),
        Workload::post(
            "authorize_batch_128",
            AuthorizeRequest::from_requests((0..128).map(|_| labeled_request("bench_batch_128"))),
            "Action::bench_batch_128",
        ),
    ]
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_optional_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
}

fn configured_concurrency(cpu_count: usize) -> Vec<usize> {
    let mut values = std::env::var("TREETOP_PERF_CONCURRENCIES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .filter_map(|value| value.trim().parse().ok())
                .filter(|value| *value > 0)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| vec![1, cpu_count.clamp(1, 8)]);
    values.sort_unstable();
    values.dedup();
    values
}

fn create_store() -> Arc<RwLock<PolicyStore>> {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(POLICIES, None, None).unwrap();
    store.set_labels(LABELS, None, None).unwrap();
    Arc::new(RwLock::new(store))
}

fn spawn_server() -> (String, ServerHandle, ParallelConfig) {
    let registry = treetop_rest::metrics::init_prometheus().unwrap();
    let store = create_store();
    let parallel = treetop_rest::parallel::init_parallelism(
        env_optional_usize("TREETOP_PERF_WORKERS"),
        env_optional_usize("TREETOP_PERF_RAYON_THREADS"),
        env_optional_usize("TREETOP_PERF_PAR_THRESHOLD"),
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

async fn send_requests(
    client: &reqwest::Client,
    base_url: &str,
    workload: &Workload,
    count: usize,
    concurrency: usize,
) -> Vec<Duration> {
    let url: Arc<str> = format!("{base_url}{}", workload.path).into();
    let results = stream::iter(0..count)
        .map(|_| {
            let client = client.clone();
            let url = url.clone();
            let body = workload.body.clone();
            async move {
                let started = Instant::now();
                let request = match body {
                    Some(body) => client
                        .post(url.as_ref())
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(body.to_string()),
                    None => client.get(url.as_ref()),
                };
                let response = request.send().await.map_err(|error| error.to_string())?;
                let status = response.status();
                response.bytes().await.map_err(|error| error.to_string())?;
                if !status.is_success() {
                    return Err(format!("request to {url} returned {status}"));
                }
                Ok(started.elapsed())
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<Result<Duration, String>>>()
        .await;

    results.into_iter().collect::<Result<Vec<_>, _>>().unwrap()
}

async fn run_workload(
    client: &reqwest::Client,
    base_url: &str,
    workload: &Workload,
    warmup: usize,
    samples: usize,
    concurrency: usize,
) -> RawRun {
    let _ = send_requests(client, base_url, workload, warmup, concurrency).await;
    let started = Instant::now();
    let durations = send_requests(client, base_url, workload, samples, concurrency).await;

    RawRun {
        workload: workload.name.to_owned(),
        concurrency,
        elapsed_ns: started.elapsed().as_nanos(),
        samples_ns: durations
            .into_iter()
            .map(|value| value.as_nanos())
            .collect(),
    }
}

fn metric_value(metrics: &str, name: &str, labels: &[(&str, &str)]) -> f64 {
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
        .unwrap_or(0.0)
}

fn anonymous_environment(parallel: ParallelConfig) -> AnonymousEnvironment {
    let build = treetop_rest::build_info::build_info();
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|line| line.split_once(':'))
                    .map(|(_, value)| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let governor = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let cpu_affinity = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("Cpus_allowed_list:")
                    .map(|value| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());

    AnonymousEnvironment {
        cpu_model: cpu,
        logical_cpus: std::thread::available_parallelism().unwrap().get(),
        cpu_affinity,
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        kernel,
        cpu_governor: governor,
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

fn print_environment(
    environment: &AnonymousEnvironment,
    samples: usize,
    warmup: usize,
    concurrencies: &[usize],
) {
    println!("CPU: {}", environment.cpu_model);
    println!("logical CPUs: {}", environment.logical_cpus);
    println!("CPU affinity: {}", environment.cpu_affinity);
    println!(
        "OS/kernel: {}/{} ({})",
        environment.os, environment.kernel, environment.architecture
    );
    println!("CPU governor: {}", environment.cpu_governor);
    println!("Rust: {}", environment.rust_version);
    println!("target: {}", environment.target);
    println!("profile: {}", environment.build_profile);
    println!(
        "versions: treetop-rest {} ({}; dirty: {}); treetop-core {} ({}; dirty: {}); Cedar {}",
        environment.treetop_rest_version,
        environment.treetop_rest_sha,
        environment.treetop_rest_dirty,
        environment.treetop_core_version,
        environment.treetop_core_sha,
        environment.treetop_core_dirty,
        environment.cedar_version
    );
    println!(
        "parallel: workers {}; Rayon threads {}; threshold {}",
        environment.parallel.workers,
        environment.parallel.rayon_threads,
        environment.parallel.par_threshold
    );
    println!("samples: {samples}; warm-up: {warmup}; concurrency: {concurrencies:?}");
}

fn print_latency_table(summaries: &[RunSummary]) {
    println!(
        "| workload | concurrency | requests/s | mean µs | p50 µs | p90 µs | p95 µs | p99 µs | max µs |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for summary in summaries {
        println!(
            "| {} | {} | {:.0} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |",
            summary.workload,
            summary.concurrency,
            summary.requests_per_second,
            summary.mean_us,
            summary.p50_us,
            summary.p90_us,
            summary.p95_us,
            summary.p99_us,
            summary.max_us,
        );
    }
}

fn phase_summaries(metrics: &str, workloads: &[Workload]) -> Vec<PhaseSummary> {
    workloads
        .iter()
        .filter_map(|workload| {
            let action = workload.metric_action?;
            let total_count = metric_value(
                metrics,
                "policy_eval_duration_seconds_count",
                &[("action", action)],
            );
            let total_sum = metric_value(
                metrics,
                "policy_eval_duration_seconds_sum",
                &[("action", action)],
            );
            let mean_phase = |phase| {
                let sum = metric_value(
                    metrics,
                    "policy_eval_phase_duration_seconds_sum",
                    &[("action", action), ("phase", phase)],
                );
                sum / total_count * 1_000_000.0
            };

            Some(PhaseSummary {
                workload: workload.name.to_owned(),
                evaluations: total_count as u64,
                total_mean_us: total_sum / total_count * 1_000_000.0,
                apply_labels_mean_us: mean_phase("apply_labels"),
                construct_entities_mean_us: mean_phase("construct_entities"),
                resolve_groups_mean_us: mean_phase("resolve_groups"),
                cedar_authorize_mean_us: mean_phase("cedar_authorize"),
                overhead_mean_us: mean_phase("overhead"),
            })
        })
        .collect()
}

fn print_phase_table(summaries: &[PhaseSummary]) {
    println!(
        "| action workload | evaluations | total mean µs | labels µs | entities µs | groups µs | Cedar µs | overhead µs |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");

    for summary in summaries {
        println!(
            "| {} | {:.0} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |",
            summary.workload,
            summary.evaluations,
            summary.total_mean_us,
            summary.apply_labels_mean_us,
            summary.construct_entities_mean_us,
            summary.resolve_groups_mean_us,
            summary.cedar_authorize_mean_us,
            summary.overhead_mean_us,
        );
    }
}

#[actix_web::test]
#[ignore = "machine-dependent characterization; run explicitly in release mode"]
async fn characterize_end_to_end_latency() {
    let samples = env_usize("TREETOP_PERF_SAMPLES", 5_000);
    let warmup = env_usize("TREETOP_PERF_WARMUP", 500);
    let cpu_count = std::thread::available_parallelism().unwrap().get();
    let concurrencies = configured_concurrency(cpu_count);
    let workloads = workloads();
    let (base_url, server, parallel) = spawn_server();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let mut raw_runs = Vec::new();
    for concurrency in concurrencies.iter().copied() {
        for workload in &workloads {
            raw_runs.push(
                run_workload(&client, &base_url, workload, warmup, samples, concurrency).await,
            );
        }
    }

    let metrics = client
        .get(format!("{base_url}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    server.stop(false).await;

    let environment = anonymous_environment(parallel);
    let http_summaries = raw_runs
        .iter()
        .map(RunSummary::from_run)
        .collect::<Vec<_>>();
    let policy_phase_summaries = phase_summaries(&metrics, &workloads);

    print_environment(&environment, samples, warmup, &concurrencies);
    print_latency_table(&http_summaries);
    print_phase_table(&policy_phase_summaries);

    if let Ok(path) = std::env::var("TREETOP_PERF_OUTPUT") {
        let report = AnonymousReport {
            schema_version: 1,
            privacy_notice: "Excludes hostname, username, network addresses, filesystem paths, and Git branch; includes source commit SHAs for reproducibility; review before sharing.",
            environment: &environment,
            configuration: CharacterizationConfig {
                samples_per_workload: samples,
                warmup_requests_per_workload: warmup,
                concurrencies: &concurrencies,
            },
            http_summaries: &http_summaries,
            policy_phase_summaries: &policy_phase_summaries,
            raw_http_runs: &raw_runs,
        };
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
}

#[test]
fn anonymous_report_schema_includes_source_provenance_without_host_identity() {
    let environment = AnonymousEnvironment {
        cpu_model: "example CPU".to_owned(),
        logical_cpus: 8,
        cpu_affinity: "0-7".to_owned(),
        os: "linux",
        architecture: "x86_64",
        kernel: "example kernel".to_owned(),
        cpu_governor: "performance".to_owned(),
        rust_version: "1.97.1".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        build_profile: "release".to_owned(),
        treetop_rest_version: "0.0.14",
        treetop_rest_sha: "rest-sha".to_owned(),
        treetop_rest_dirty: true,
        treetop_core_version: "0.0.22".to_owned(),
        treetop_core_sha: "core-sha".to_owned(),
        treetop_core_dirty: false,
        cedar_version: "4.12.0",
        parallel: ParallelConfig::new(8, 4, Some(16)),
    };
    let report = AnonymousReport {
        schema_version: 1,
        privacy_notice: "review before sharing",
        environment: &environment,
        configuration: CharacterizationConfig {
            samples_per_workload: 1,
            warmup_requests_per_workload: 1,
            concurrencies: &[1],
        },
        http_summaries: &[],
        policy_phase_summaries: &[],
        raw_http_runs: &[],
    };

    let json = serde_json::to_value(report).unwrap();
    assert_eq!(
        json.pointer("/environment/treetop_rest_sha"),
        Some(&serde_json::json!("rest-sha"))
    );
    assert_eq!(
        json.pointer("/environment/treetop_core_sha"),
        Some(&serde_json::json!("core-sha"))
    );
    assert_eq!(
        json.pointer("/environment/cpu_affinity"),
        Some(&serde_json::json!("0-7"))
    );
    for excluded in ["hostname", "username", "ip", "filesystem", "git_branch"] {
        assert!(!json.to_string().contains(excluded));
    }
}
