use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::PolicyStore;

const DSL: &str = r#"
permit (
    principal is User,
    action == Action::"view",
    resource is Host
) when {
    resource.nameLabels.contains("production")
};
"#;

const LABELS_JSON: &str = r#"[
  {
    "target": {"resource_type": "Host", "attribute": "nameLabels"}, "field": "name",
    "patterns": [{"name": "production", "regex": "^prod-"}]
  }
]"#;

const SCHEMA_JSON: &str = r#"{
  "": {
    "entityTypes": {
      "User": {},
      "Host": {
        "shape": {
          "type": "Record",
          "attributes": {
            "name": {"type": "String", "required": true},
            "nameLabels": {
              "type": "Set",
              "element": {"type": "String"},
              "required": false
            }
          },
          "additionalAttributes": false
        }
      }
    },
    "actions": {
      "view": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Host"],
          "context": {
            "type": "Record",
            "attributes": {},
            "additionalAttributes": false
          }
        }
      }
    }
  }
}"#;

fn setup_schema_backed_store() -> PolicyStore {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL, None, None).unwrap();
    store.set_labels(LABELS_JSON, None, None).unwrap();
    store.set_schema(SCHEMA_JSON, None, None).unwrap();
    store
}

fn teardown_store(_: PolicyStore) {}

#[library_benchmark(setup = setup_schema_backed_store, teardown = teardown_store)]
fn reload_compatible_schema(mut store: PolicyStore) -> PolicyStore {
    store.set_schema(SCHEMA_JSON, None, None).unwrap();
    store
}

library_benchmark_group!(
    name = policy_store_schema_reload;
    benchmarks = reload_compatible_schema
);

main!(library_benchmark_groups = policy_store_schema_reload);
