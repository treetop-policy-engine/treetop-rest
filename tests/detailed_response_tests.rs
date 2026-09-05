use actix_web::{App, test, web};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::handlers;
use treetop_rest::models::{
    AuthorizeRequest, AuthorizeResponseVariant, BatchResult, DecisionBrief,
};
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

#[actix_web::test]
async fn detailed_response_serialization_uses_the_server_model() {
    let mut store = PolicyStore::new().unwrap();
    let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
    store.set_dsl(dsl, None, None).unwrap();
    let store = Arc::new(RwLock::new(store));
    let parallel = ParallelConfig::new(1, 1, None);

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

    let body = test::read_body(resp).await;
    let response: AuthorizeResponseVariant = serde_json::from_slice(&body).unwrap();
    let AuthorizeResponseVariant::Detailed(response) = response else {
        panic!("full detail request returned a brief response");
    };

    assert_eq!(response.successes(), 1);
    assert_eq!(response.failures(), 0);
    let result = response.find_by_id("check-1").unwrap();
    assert_eq!(result.index(), 0);
    match result.result() {
        BatchResult::Success { data } => {
            assert!(matches!(data.decision, DecisionBrief::Allow));
            assert_eq!(data.policy.len(), 1);
        }
        BatchResult::Failed { message } => panic!("authorization failed: {message}"),
    }
}
