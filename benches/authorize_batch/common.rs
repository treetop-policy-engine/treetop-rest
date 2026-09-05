use std::hint::black_box;
use std::str::FromStr;
use std::sync::Arc;
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::handlers::evaluate_batch_requests_for_bench;
use treetop_rest::models::AuthRequest;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const DSL: &str = r#"
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

fn build_engine() -> Arc<treetop_bundle::PreparedEngine> {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL, None, None).unwrap();
    store.engine.clone()
}

fn build_requests(count: usize) -> Vec<AuthRequest> {
    let principal = Principal::User(User::from_str("alice").unwrap());
    let view_action = Action::from_str("view").unwrap();
    let edit_action = Action::from_str("edit").unwrap();

    (0..count)
        .map(|i| {
            let action = if i % 2 == 0 {
                view_action.clone()
            } else {
                edit_action.clone()
            };
            let request = Request {
                principal: principal.clone(),
                action,
                resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
            };
            AuthRequest::new(request)
        })
        .collect()
}

pub struct BatchContext {
    engine: Arc<treetop_bundle::PreparedEngine>,
    parallel: ParallelConfig,
    requests: Vec<AuthRequest>,
}

impl BatchContext {
    pub fn evaluate<T, F>(&self, map_fn: F)
    where
        T: Send,
        F: Fn(treetop_core::Decision) -> T + Send + Sync,
    {
        black_box(evaluate_batch_requests_for_bench(
            &self.requests,
            &self.engine,
            &self.parallel,
            map_fn,
        ));
    }
}

pub fn setup_batch(count: usize) -> BatchContext {
    BatchContext {
        engine: build_engine(),
        parallel: ParallelConfig::new(1, 1, Some(usize::MAX)),
        requests: build_requests(count),
    }
}

pub fn teardown_batch(_: BatchContext) {}
