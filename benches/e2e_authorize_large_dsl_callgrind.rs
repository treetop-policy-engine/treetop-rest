use actix_http::Request as HttpRequest;
use actix_service::boxed::{BoxService, service as box_service};
use actix_web::body::BoxBody;
use actix_web::dev::ServiceResponse;
use actix_web::{App, test, web};
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use std::sync::{Arc, Once, RwLock};
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::handlers;
use treetop_rest::middleware::TracingMiddleware;
use treetop_rest::models::AuthorizeRequest;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

fn init_metrics_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = treetop_rest::metrics::init_prometheus();
    });
}

fn build_large_dsl() -> String {
    let mut dsl = String::new();
    for idx in 0..75 {
        dsl.push_str(&format!(
            r#"
@id("bulk.policy.{idx}")
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"photo_{idx}.jpg"
);
"#
        ));
    }
    dsl
}

fn build_store() -> Arc<RwLock<PolicyStore>> {
    let mut store = PolicyStore::new().unwrap();
    let dsl = build_large_dsl();
    store.set_dsl(&dsl, None, None).unwrap();
    Arc::new(RwLock::new(store))
}

fn build_request() -> AuthorizeRequest {
    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "photo_42.jpg").unwrap(),
    };
    AuthorizeRequest::single(request)
}

type BoxedApp = BoxService<HttpRequest, ServiceResponse<BoxBody>, actix_web::Error>;
type BenchCtx = (BoxedApp, HttpRequest);
type BenchResult = (BoxedApp, ServiceResponse<BoxBody>);

fn setup_large() -> BenchCtx {
    init_metrics_once();
    let store = build_store();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let app = futures::executor::block_on(test::init_service(
        App::new()
            .wrap(TracingMiddleware::new())
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    ));
    let app = box_service(app);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .set_json(build_request())
        .to_request();

    (app, req)
}

fn teardown(_: BenchResult) {}

#[library_benchmark(setup = setup_large, teardown = teardown)]
fn e2e_authorize_large_dsl((app, req): BenchCtx) -> BenchResult {
    let response = futures::executor::block_on(test::call_service(&app, req));
    (app, response)
}

library_benchmark_group!(
    name = e2e_authorize_large_dsl_group;
    benchmarks = e2e_authorize_large_dsl
);

main!(library_benchmark_groups = e2e_authorize_large_dsl_group);
