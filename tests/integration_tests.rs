// Integration tests using the test data files
use rstest::rstest;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use treetop_core::{Action, AttrValue, Principal, Request, Resource, User};
use treetop_rest::state::PolicyStore;

const TEST_POLICIES: &str = include_str!("../testdata/default.cedar");
const TEST_LABELS: &str = include_str!("../testdata/labels.json");

fn create_store_with_test_data() -> Arc<RwLock<PolicyStore>> {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(TEST_POLICIES, None, None).unwrap();
    store.set_labels(TEST_LABELS, None, None).unwrap();
    Arc::new(RwLock::new(store))
}

enum ExpectedDecision {
    Allow,
    Deny,
}

#[test]
fn test_load_test_policies() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // Verify policies were loaded
    assert!(guard.policies.entries > 0);
    assert!(!guard.policies.content.is_empty());
}

#[test]
fn test_load_test_labels() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // Verify labels were loaded
    assert!(guard.labels.entries > 0);
    assert!(!guard.labels.content.is_empty());
}

#[rstest]
#[case(
    "alice",
    "view",
    "Photo",
    "VacationPhoto94.jpg",
    ExpectedDecision::Allow
)]
#[case(
    "alice",
    "edit",
    "Photo",
    "VacationPhoto94.jpg",
    ExpectedDecision::Deny
)]
#[case(
    "alice",
    "delete",
    "Photo",
    "VacationPhoto94.jpg",
    ExpectedDecision::Deny
)]
#[case(
    "bob",
    "delete",
    "Photo",
    "VacationPhoto94.jpg",
    ExpectedDecision::Deny
)]
#[case("alice", "only_here", "AnyType", "anyid", ExpectedDecision::Allow)]
#[case("bob", "only_here", "AnyType", "anyid", ExpectedDecision::Deny)]
fn test_basic_authorization(
    #[case] user: &str,
    #[case] action: &str,
    #[case] resource_type: &str,
    #[case] resource_id: &str,
    #[case] expected: ExpectedDecision,
) {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    let request = Request {
        principal: Principal::User(User::from_str(user).unwrap()),
        action: Action::from_str(action).unwrap(),
        resource: Resource::new(resource_type, resource_id).unwrap(),
    };

    let decision = guard.engine.evaluate(&request).unwrap();

    match expected {
        ExpectedDecision::Allow => assert!(decision.is_allowed()),
        ExpectedDecision::Deny => assert!(!decision.is_allowed()),
    }
}

#[rstest]
#[case("bob", "10.0.0.5", ExpectedDecision::Allow)]
#[case("bob", "10.0.0.1", ExpectedDecision::Allow)]
#[case("bob", "10.0.0.254", ExpectedDecision::Allow)]
#[case("bob", "192.168.1.5", ExpectedDecision::Deny)]
#[case("bob", "172.16.0.1", ExpectedDecision::Deny)]
fn test_ip_range_authorization(
    #[case] user: &str,
    #[case] ip: &str,
    #[case] expected: ExpectedDecision,
) {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    let resource = Resource::new("Host", "myhost.example.com")
        .unwrap()
        .with_attr("ip", AttrValue::ip(ip).unwrap());

    let request = Request {
        principal: Principal::User(User::from_str(user).unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    let decision = guard.engine.evaluate(&request).unwrap();

    match expected {
        ExpectedDecision::Allow => assert!(decision.is_allowed()),
        ExpectedDecision::Deny => assert!(!decision.is_allowed()),
    }
}

#[test]
fn test_alice_create_host_with_label() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // Create a host with a name that matches "in_domain" pattern
    let mut resource = Resource::new("Host", "web-server.example.com").unwrap();
    resource = resource.with_attr("name", AttrValue::String("server.example.com".to_string()));

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    // This should be allowed because alice can create hosts with in_domain label
    // Note: Label matching happens during evaluation, not in test setup
    let decision = guard.engine.evaluate(&request).unwrap();
    // The decision depends on whether labels are properly applied
    // This test verifies the evaluation runs without error
    assert!(decision.is_allowed());
}

#[test]
fn test_labels_json_structure() {
    // Verify the labels JSON has the expected structure
    let labels: serde_json::Value = serde_json::from_str(TEST_LABELS).unwrap();

    assert!(labels.is_array());
    let array = labels.as_array().unwrap();
    assert!(!array.is_empty());

    // Check first label has required fields
    let first_label = &array[0];
    assert!(first_label.get("kind").is_some());
    assert!(first_label.get("field").is_some());
    assert!(first_label.get("output").is_some());
    assert!(first_label.get("patterns").is_some());

    // Check patterns structure
    let patterns = first_label.get("patterns").unwrap().as_array().unwrap();
    assert!(!patterns.is_empty());

    let first_pattern = &patterns[0];
    assert!(first_pattern.get("name").is_some());
    assert!(first_pattern.get("regex").is_some());
}

#[test]
fn test_policies_count() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // Count permit and forbid statements in the test data
    let permit_count = TEST_POLICIES
        .lines()
        .filter(|line| line.trim().starts_with("permit ("))
        .count();
    let forbid_count = TEST_POLICIES
        .lines()
        .filter(|line| line.trim().starts_with("forbid ("))
        .count();

    let total = permit_count + forbid_count;
    assert_eq!(guard.policies.entries, total);
}

#[test]
fn test_policy_version_tracking() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    let version1 = guard.engine.current_version();
    drop(guard);

    // Update policies
    {
        let mut guard = store.write().unwrap();
        guard
            .set_dsl("permit (principal, action, resource);", None, None)
            .unwrap();
    }

    let guard = store.read().unwrap();
    let version2 = guard.engine.current_version();

    // Versions should be different after update
    assert_ne!(version1, version2);
}

#[test]
fn test_store_sha256_hash() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // SHA256 hash should be 64 hex characters
    assert_eq!(guard.policies.sha256.len(), 64);
    assert!(guard.policies.sha256.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_store_content_size() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    assert_eq!(guard.policies.size, TEST_POLICIES.len());
    assert_eq!(guard.labels.size, TEST_LABELS.len());
}

#[test]
fn test_batch_evaluation() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // Create a batch of requests
    let requests = [
        Request {
            principal: Principal::User(User::from_str("alice").unwrap()),
            action: Action::from_str("view").unwrap(),
            resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
        },
        Request {
            principal: Principal::User(User::from_str("alice").unwrap()),
            action: Action::from_str("edit").unwrap(),
            resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
        },
        Request {
            principal: Principal::User(User::from_str("alice").unwrap()),
            action: Action::from_str("delete").unwrap(),
            resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
        },
    ];

    // Evaluate all requests
    let results: Vec<_> = requests
        .iter()
        .map(|req| guard.engine.evaluate(req))
        .collect();

    // First should be Allow, others should be Deny
    assert!(results[0].as_ref().unwrap().is_allowed());
    assert!(!results[1].as_ref().unwrap().is_allowed());
    assert!(!results[2].as_ref().unwrap().is_allowed());
}

#[test]
fn test_batch_with_mixed_results() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // Create a batch with some valid and some potentially invalid requests
    let requests = [
        Request {
            principal: Principal::User(User::from_str("alice").unwrap()),
            action: Action::from_str("only_here").unwrap(),
            resource: Resource::new("AnyType", "anyid").unwrap(),
        },
        Request {
            principal: Principal::User(User::from_str("bob").unwrap()),
            action: Action::from_str("only_here").unwrap(),
            resource: Resource::new("AnyType", "anyid").unwrap(),
        },
        Request {
            principal: Principal::User(User::from_str("bob").unwrap()),
            action: Action::from_str("create_host").unwrap(),
            resource: Resource::new("Host", "myhost.example.com")
                .unwrap()
                .with_attr("ip", AttrValue::ip("10.0.0.5").unwrap()),
        },
    ];

    let results: Vec<_> = requests
        .iter()
        .map(|req| guard.engine.evaluate(req))
        .collect();

    // Verify all evaluations completed successfully
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.is_ok()));

    // Check expected outcomes
    assert!(results[0].as_ref().unwrap().is_allowed()); // alice only_here
    assert!(!results[1].as_ref().unwrap().is_allowed()); // bob only_here
    assert!(results[2].as_ref().unwrap().is_allowed()); // bob create_host with valid IP
}

#[test]
fn test_batch_consistency() {
    let store = create_store_with_test_data();
    let guard = store.read().unwrap();

    // Capture the policy version
    let version = guard.engine.current_version();

    // Create multiple identical requests
    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg").unwrap(),
    };

    // Evaluate the same request multiple times
    let results: Vec<_> = (0..5).map(|_| guard.engine.evaluate(&request)).collect();

    // All results should be identical and match the same version
    for result in &results {
        let decision = result.as_ref().unwrap();
        assert!(decision.is_allowed());
        assert_eq!(decision.version(), &version);
    }
}
