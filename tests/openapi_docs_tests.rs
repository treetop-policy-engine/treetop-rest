fn generated_spec() -> serde_json::Value {
    serde_json::to_value(treetop_rest::handlers::openapi_document())
        .expect("OpenAPI spec should serialize")
}

#[test]
fn docs_openapi_json_matches_generated_spec() {
    let generated = serde_json::to_string_pretty(treetop_rest::handlers::openapi_document())
        .expect("OpenAPI spec should serialize");
    let checked_in = include_str!("../docs/openapi.json").trim_end();

    assert_eq!(
        checked_in, generated,
        "docs/openapi.json is stale; run `cargo run --example openapi > docs/openapi.json`"
    );
}

#[test]
fn openapi_describes_admission_and_upload_security() {
    let spec = generated_spec();
    let access_token = &spec["components"]["securitySchemes"]["access_token"];
    assert_eq!(access_token["type"], "http");
    assert_eq!(access_token["scheme"], "bearer");
    assert!(
        access_token["description"]
            .as_str()
            .unwrap()
            .contains("only when TREETOP_ACCESS_TOKENS is configured")
    );

    let upload_token = &spec["components"]["securitySchemes"]["upload_token"];
    assert_eq!(upload_token["type"], "apiKey");
    assert_eq!(upload_token["in"], "header");
    assert_eq!(upload_token["name"], "X-Upload-Token");

    for path in ["/api/v1/policies", "/api/v1/schema", "/api/v1/bundle"] {
        let operation = &spec["paths"][path]["post"];
        assert_eq!(
            operation["security"][0]["upload_token"],
            serde_json::json!([])
        );
        assert_eq!(
            operation["security"][0]["access_token"],
            serde_json::json!([])
        );
        assert_eq!(
            operation["security"][1],
            serde_json::json!({"upload_token": []})
        );
        if path == "/api/v1/bundle" {
            assert!(operation["requestBody"]["content"]["application/gzip"].is_object());
            assert!(operation["requestBody"]["content"]["application/x-gzip"].is_object());
            assert!(operation["responses"]["413"].is_object());
            assert!(operation["responses"]["415"].is_object());
        } else {
            assert!(operation["requestBody"]["content"]["application/json"].is_object());
            assert!(operation["requestBody"]["content"]["text/plain"].is_object());
        }
        assert!(operation["responses"]["401"].is_object());
        assert!(operation["responses"]["403"].is_object());
        if path != "/api/v1/bundle" {
            assert!(operation["responses"]["409"].is_object());
        }
    }
}

#[test]
fn protected_operations_document_conditional_bearer_and_acl_failures() {
    let spec = generated_spec();
    for (path, path_item) in spec["paths"].as_object().unwrap() {
        for operation in path_item.as_object().unwrap().values() {
            if path == "/metrics" || path.starts_with("/api/v1/") {
                assert!(operation["responses"]["401"].is_object(), "{path}");
                assert!(operation["responses"]["403"].is_object(), "{path}");
                assert_eq!(
                    operation["responses"]["401"]["headers"]["WWW-Authenticate"]["description"],
                    "Bearer authentication challenge"
                );
                assert_eq!(
                    operation["responses"]["401"]["content"]["application/json"]["schema"]["$ref"],
                    "#/components/schemas/ErrorResponse"
                );
                if !matches!(
                    operation["operationId"].as_str(),
                    Some("upload_policies" | "upload_schema" | "upload_bundle")
                ) {
                    assert_eq!(
                        operation["security"],
                        serde_json::json!([{"access_token": []}, {}]),
                        "{path}"
                    );
                }
            } else {
                assert!(operation["security"].is_null(), "{path}");
            }
        }
    }
}

#[test]
fn openapi_describes_both_schema_json_forms() {
    let spec = generated_spec();
    assert_eq!(
        spec["paths"]["/api/v1/schema"]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/SchemaUpload"
    );
    let schema_upload = &spec["components"]["schemas"]["SchemaUpload"];
    let variants = schema_upload["anyOf"].as_array().unwrap();
    assert_eq!(variants.len(), 2);
    assert!(schema_upload["oneOf"].is_null());
    assert_eq!(variants[0]["required"], serde_json::json!(["schema"]));
    assert_eq!(variants[0]["properties"]["schema"]["type"], "string");
    assert_eq!(variants[1]["type"], "object");
}

#[test]
fn public_api_doc_entry_point_is_preserved() {
    use utoipa::OpenApi;

    let direct = treetop_rest::handlers::ApiDoc::openapi();
    assert_eq!(
        serde_json::to_value(direct).expect("ApiDoc should serialize"),
        generated_spec()
    );
}

#[test]
fn openapi_uses_the_wire_error_shape() {
    let spec = generated_spec();
    assert_eq!(
        spec["paths"]["/api/v1/authorize"]["post"]["responses"]["400"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/ErrorResponse"
    );
    let error_response = &spec["components"]["schemas"]["ErrorResponse"];
    assert_eq!(error_response["properties"]["error"]["type"], "string");
    assert_eq!(error_response["properties"]["code"]["type"], "string");
    assert!(spec["components"]["schemas"]["ServiceError"].is_null());
}

#[test]
fn openapi_describes_response_formats_and_operation_tags() {
    let spec = generated_spec();
    for path in [
        "/api/v1/policies",
        "/api/v1/schema",
        "/api/v1/policies/{user}",
    ] {
        let content = &spec["paths"][path]["get"]["responses"]["200"]["content"];
        assert!(content["application/json"].is_object());
        assert!(content["text/plain"].is_object());
    }

    for path_item in spec["paths"].as_object().unwrap().values() {
        for operation in path_item.as_object().unwrap().values() {
            assert_eq!(operation["tags"], serde_json::json!(["Treetop REST API"]));
        }
    }
    let metrics_content = &spec["paths"]["/metrics"]["get"]["responses"]["200"]["content"];
    assert!(metrics_content["application/openmetrics-text"].is_object());
    assert!(metrics_content["application/vnd.google.protobuf"].is_object());
}

#[test]
fn compact_permit_json_remains_an_unconstrained_wire_value() {
    let spec = generated_spec();
    let policy = &spec["components"]["schemas"]["PermitPolicy"];
    assert!(
        policy["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("json"))
    );
    let json = policy["properties"]["json"].as_object().unwrap();
    assert!(!json.contains_key("type"));
    assert!(!json.contains_key("$ref"));
    assert!(spec["components"]["schemas"]["PolicyJson"].is_null());
}
