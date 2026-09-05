use std::collections::HashMap;
use std::ops::Deref;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use treetop_core::{AttrValue, Decision, PermitPolicy, PolicyVersion, Request};
use url::Url;

use utoipa::ToSchema;

use crate::{
    parallel::ParallelConfig,
    state::{Metadata, OfLabels, OfPolicies, OfSchema, PolicyStore},
};

/// Network endpoint URL for policy or label service communication
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Endpoint {
    #[schema(value_type = String, example = "https://example.com/api")]
    url: Url,
}

impl Endpoint {
    /// Create a new endpoint from a URL
    pub fn new(url: Url) -> Self {
        Endpoint { url }
    }

    /// Get the endpoint URL as a string slice
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Get a reference to the underlying URL
    pub fn url(&self) -> &Url {
        &self.url
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl std::str::FromStr for Endpoint {
    type Err = url::ParseError;

    /// Parse an endpoint from a string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Url::parse(s) {
            Ok(url) => Ok(Endpoint { url }),
            Err(e) => Err(e),
        }
    }
}

/// Detailed authorization decision including the matching policy
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct AuthorizeDecisionDetailed {
    pub policy: Vec<PermitPolicy>,
    pub decision: DecisionBrief,
    pub version: PolicyVersion,
}

impl From<Decision> for AuthorizeDecisionDetailed {
    /// Convert a core Decision into a detailed AuthorizeDecisionDetailed
    fn from(decision: Decision) -> Self {
        AuthorizeDecisionDetailed {
            policy: decision
                .permit_policies()
                .map(|policies| policies.clone().into_inner())
                .unwrap_or_default(),
            decision: if decision.is_allowed() {
                DecisionBrief::Allow
            } else {
                DecisionBrief::Deny
            },
            version: decision.version().clone(),
        }
    }
}

/// Brief authorization decision without policy details
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub enum DecisionBrief {
    Allow,
    Deny,
}

/// Brief authorization decision response with minimal information
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct AuthorizeDecisionBrief {
    pub decision: DecisionBrief,
    pub version: PolicyVersion,
    pub policy_id: String,
}

impl From<Decision> for AuthorizeDecisionBrief {
    /// Convert a core Decision into a brief AuthorizeDecisionBrief
    fn from(decision: Decision) -> Self {
        AuthorizeDecisionBrief {
            policy_id: decision
                .permit_policies()
                .map(|policies| policies.ids().join("; "))
                .unwrap_or_default(),
            decision: if decision.is_allowed() {
                DecisionBrief::Allow
            } else {
                DecisionBrief::Deny
            },
            version: decision.version().clone(),
        }
    }
}

#[derive(Serialize, ToSchema, Deserialize)]
pub struct StatusResponse {
    pub policy_configuration: PoliciesMetadata,
    pub parallel_configuration: ParallelConfig,
    #[serde(default)]
    pub request_limits: RequestLimits,
    #[serde(default)]
    pub request_context: RequestContextStatus,
}

#[derive(Serialize, ToSchema, Deserialize, Clone, Copy)]
pub struct RequestLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_batch_size: Option<usize>,
    pub max_context_bytes: usize,
    pub max_context_depth: usize,
    pub max_context_keys: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_batch_size: None,
            max_context_bytes: 16 * 1024,
            max_context_depth: 8,
            max_context_keys: 64,
        }
    }
}

#[derive(Serialize, ToSchema, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestContextFallbackReason {
    NoSchema,
    SchemaIncompatible,
}

impl std::fmt::Display for RequestContextFallbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestContextFallbackReason::NoSchema => write!(f, "no_schema"),
            RequestContextFallbackReason::SchemaIncompatible => {
                write!(f, "schema_incompatible")
            }
        }
    }
}

#[derive(Serialize, ToSchema, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestContextStatus {
    pub supported: bool,
    pub schema_backed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<RequestContextFallbackReason>,
}

impl RequestContextStatus {
    pub fn no_schema() -> Self {
        Self {
            supported: true,
            schema_backed: false,
            fallback_reason: Some(RequestContextFallbackReason::NoSchema),
        }
    }

    pub fn schema_backed() -> Self {
        Self {
            supported: true,
            schema_backed: true,
            fallback_reason: None,
        }
    }

    pub fn schema_incompatible() -> Self {
        Self {
            supported: true,
            schema_backed: false,
            fallback_reason: Some(RequestContextFallbackReason::SchemaIncompatible),
        }
    }
}

impl Default for RequestContextStatus {
    fn default() -> Self {
        Self::no_schema()
    }
}

/// Metadata about the policies and labels in the policy store
#[derive(Serialize, Deserialize, ToSchema)]
pub struct PoliciesMetadata {
    pub allow_upload: bool,
    pub schema_validation_mode: String,

    pub policies: Metadata<OfPolicies>,
    pub labels: Metadata<OfLabels>,
    pub schema: Metadata<OfSchema>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<BundleMetadata>,
}

/// Metadata for the complete bundle that produced the active policy state.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BundleMetadata {
    pub format_version: u32,
    pub bundle_id: String,
    pub archive_sha256: String,
    pub compressed_size: usize,
    pub module_count: usize,
    pub signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_frequency: Option<u32>,
    pub loaded_at: DateTime<Utc>,
}

impl<T> From<T> for PoliciesMetadata
where
    T: Deref<Target = PolicyStore>,
{
    /// Convert a PolicyStore into metadata
    fn from(store: T) -> Self {
        PoliciesMetadata {
            allow_upload: store.allow_upload,
            schema_validation_mode: store.schema_validation_mode.to_string(),
            policies: store.policies.clone(),
            labels: store.labels.clone(),
            schema: store.schema.clone(),
            bundle: store.bundle.clone(),
        }
    }
}

/// Policy data for download
#[derive(Serialize, Deserialize, ToSchema)]
pub struct PoliciesDownload {
    pub policies: Metadata<OfPolicies>,
}

/// Schema data for download
#[derive(Serialize, Deserialize, ToSchema)]
pub struct SchemaDownload {
    pub schema: Metadata<OfSchema>,
}

/// Why a policy was selected by list policies APIs.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub enum PolicyMatchReason {
    PrincipalEq,
    PrincipalIn,
    PrincipalAny,
    PrincipalIs,
    PrincipalIsIn,
    ActionEq,
    ActionIn,
    ActionAny,
    ResourceEq,
    ResourceIn,
    ResourceAny,
    ResourceIs,
    ResourceIsIn,
}

impl From<treetop_core::PolicyMatchReason> for PolicyMatchReason {
    fn from(reason: treetop_core::PolicyMatchReason) -> Self {
        match reason {
            treetop_core::PolicyMatchReason::PrincipalEq => PolicyMatchReason::PrincipalEq,
            treetop_core::PolicyMatchReason::PrincipalIn => PolicyMatchReason::PrincipalIn,
            treetop_core::PolicyMatchReason::PrincipalAny => PolicyMatchReason::PrincipalAny,
            treetop_core::PolicyMatchReason::PrincipalIs => PolicyMatchReason::PrincipalIs,
            treetop_core::PolicyMatchReason::PrincipalIsIn => PolicyMatchReason::PrincipalIsIn,
            treetop_core::PolicyMatchReason::ActionEq => PolicyMatchReason::ActionEq,
            treetop_core::PolicyMatchReason::ActionIn => PolicyMatchReason::ActionIn,
            treetop_core::PolicyMatchReason::ActionAny => PolicyMatchReason::ActionAny,
            treetop_core::PolicyMatchReason::ResourceEq => PolicyMatchReason::ResourceEq,
            treetop_core::PolicyMatchReason::ResourceIn => PolicyMatchReason::ResourceIn,
            treetop_core::PolicyMatchReason::ResourceAny => PolicyMatchReason::ResourceAny,
            treetop_core::PolicyMatchReason::ResourceIs => PolicyMatchReason::ResourceIs,
            treetop_core::PolicyMatchReason::ResourceIsIn => PolicyMatchReason::ResourceIsIn,
        }
    }
}

/// Match metadata for one listed policy.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyMatch {
    pub cedar_id: String,
    pub reasons: Vec<PolicyMatchReason>,
}

impl From<&treetop_core::PolicyMatch> for PolicyMatch {
    fn from(policy_match: &treetop_core::PolicyMatch) -> Self {
        Self {
            cedar_id: policy_match.cedar_id.clone(),
            reasons: policy_match
                .reasons
                .iter()
                .cloned()
                .map(PolicyMatchReason::from)
                .collect(),
        }
    }
}

/// Policies associated with a specific user
#[derive(Clone, Serialize, ToSchema)]
pub struct UserPolicies {
    pub user: String,
    pub policies: Vec<Value>,
    pub matches: Vec<PolicyMatch>,
}

impl TryFrom<treetop_core::PolicyCandidates> for UserPolicies {
    type Error = crate::errors::ServiceError;

    /// Convert core UserPolicies into a serializable UserPolicies
    fn try_from(user_policies: treetop_core::PolicyCandidates) -> Result<Self, Self::Error> {
        let policies = user_policies
            .policies()
            .iter()
            .map(|policy| {
                policy.to_json().map_err(|err| {
                    crate::errors::ServiceError::ListPoliciesError(format!(
                        "failed to serialize policy to JSON: {err}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(UserPolicies {
            user: user_policies.user().to_string(),
            policies,
            matches: user_policies
                .matches()
                .iter()
                .map(PolicyMatch::from)
                .collect(),
        })
    }
}

/// Single authorization request with optional client-provided ID
#[derive(Deserialize, Serialize, ToSchema)]
pub struct AuthRequest {
    /// Optional client-provided identifier for this request
    pub id: Option<String>,
    /// Optional request-scoped context values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, AttrValue>>,
    /// The actual authorization request
    #[serde(flatten)]
    pub request: Request,
}

impl AuthRequest {
    /// Create a new authorization request without a client ID
    pub fn new(request: Request) -> Self {
        Self {
            id: None,
            context: None,
            request,
        }
    }

    /// Create a new authorization request with a client-provided ID
    ///
    /// The ID will be returned in the response for request correlation.
    pub fn with_id<I>(id: I, request: Request) -> Self
    where
        I: Into<String>,
    {
        Self {
            id: Some(id.into()),
            context: None,
            request,
        }
    }

    /// Create a new authorization request with context values.
    pub fn with_context(mut self, context: HashMap<String, AttrValue>) -> Self {
        if !context.is_empty() {
            self.context = Some(context);
        }
        self
    }
}

impl From<Request> for AuthRequest {
    /// Convert a Request into an AuthRequest without ID
    fn from(request: Request) -> Self {
        Self::new(request)
    }
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct AuthorizeRequest {
    /// List of authorization requests to evaluate, subject to the server's configured batch limit.
    pub requests: Vec<AuthRequest>,
}

impl AuthorizeRequest {
    /// Create a new empty builder for constructing an authorize request
    ///
    /// # Example
    /// ```
    /// let auth_req = treetop_rest::models::AuthorizeRequest::new();
    /// assert_eq!(auth_req.requests.len(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
        }
    }

    /// Add a request without a client-provided ID, using the fluent builder pattern
    ///
    /// # Example
    /// ```
    /// use treetop_core::{Action, Principal, Request, Resource, User};
    /// let request = Request {
    ///     principal: Principal::User(User::new("alice", None, None).unwrap()),
    ///     action: Action::new("view", None).unwrap(),
    ///     resource: Resource::new("Photo", "photo.jpg").unwrap(),
    /// };
    /// let auth_req = treetop_rest::models::AuthorizeRequest::new().add_request(request);
    /// assert_eq!(auth_req.requests.len(), 1);
    /// ```
    pub fn add_request(mut self, request: Request) -> Self {
        self.requests.push(AuthRequest::new(request));
        self
    }

    /// Add a request with a client-provided ID, using the fluent builder pattern
    ///
    /// The ID is returned in the response for request correlation.
    ///
    /// # Example
    /// ```
    /// use treetop_core::{Action, Principal, Request, Resource, User};
    /// let request = Request {
    ///     principal: Principal::User(User::new("alice", None, None).unwrap()),
    ///     action: Action::new("view", None).unwrap(),
    ///     resource: Resource::new("Photo", "photo.jpg").unwrap(),
    /// };
    /// let auth_req = treetop_rest::models::AuthorizeRequest::new()
    ///     .add_with_id("req-1", request);
    /// assert_eq!(auth_req.requests.len(), 1);
    /// assert_eq!(auth_req.requests[0].id, Some("req-1".to_string()));
    /// ```
    pub fn add_with_id<I>(mut self, id: I, request: Request) -> Self
    where
        I: Into<String>,
    {
        self.requests.push(AuthRequest::with_id(id, request));
        self
    }

    /// Create a request with a single authorization check (convenience method)
    pub fn single(request: Request) -> Self {
        Self {
            requests: vec![AuthRequest::new(request)],
        }
    }

    /// Create a request from multiple authorization checks without IDs (convenience method)
    pub fn from_requests<I>(requests: I) -> Self
    where
        I: IntoIterator<Item = Request>,
    {
        Self {
            requests: requests.into_iter().map(AuthRequest::from).collect(),
        }
    }

    /// Create a request from multiple authorization checks with IDs (convenience method)
    pub fn with_ids<I, Id>(requests: I) -> Self
    where
        I: IntoIterator<Item = (Id, Request)>,
        Id: Into<String>,
    {
        Self {
            requests: requests
                .into_iter()
                .map(|(id, request)| AuthRequest::with_id(id, request))
                .collect(),
        }
    }
}

impl Default for AuthorizeRequest {
    /// Create a default empty AuthorizeRequest
    fn default() -> Self {
        Self::new()
    }
}

/// Batch authorization check request with multiple requests
#[derive(Deserialize, ToSchema)]
pub struct BatchCheckRequest {
    /// List of authorization requests to evaluate
    pub requests: Vec<Request>,
}

/// Result of a single batch evaluation - either success or failure
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum BatchResult<T> {
    Success {
        #[serde(rename = "result")]
        data: T,
    },
    Failed {
        #[serde(rename = "error")]
        message: String,
    },
}

/// A single result from a batch operation with its original index and optional client ID
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IndexedResult<T> {
    /// Index of the request in the original batch
    index: usize,
    /// Client-provided identifier for this request (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    /// Result of the evaluation (success or error)
    #[serde(flatten)]
    result: BatchResult<T>,
}

impl<T> IndexedResult<T> {
    /// Create a new indexed result
    ///
    /// # Arguments
    /// * `index` - Position of this result in the original batch
    /// * `id` - Optional client-provided identifier for this request
    /// * `result` - The evaluation result (success or failure)
    pub fn new(index: usize, id: Option<String>, result: BatchResult<T>) -> Self {
        Self { index, id, result }
    }

    /// Get the index of this result in the original batch
    pub fn index(&self) -> usize {
        self.index
    }

    /// Get the result for this entry
    pub fn result(&self) -> &BatchResult<T> {
        &self.result
    }

    /// Get the client-provided identifier (if any)
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// Container for authorization response results with metadata
///
/// Generic over the decision type to support both brief and detailed responses.
/// All fields are private; use accessor methods to retrieve data.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct AuthorizeResponse<T> {
    /// Results for each request with optional client IDs
    results: Vec<IndexedResult<T>>,
    /// Policy version used for all evaluations
    version: PolicyVersion,
    /// Number of successful evaluations
    successful: usize,
    /// Number of failed evaluations
    failed: usize,
}

impl<T> AuthorizeResponse<T> {
    /// Create a new authorize response
    ///
    /// # Arguments
    /// * `results` - Vector of indexed results from the authorization evaluations
    /// * `version` - Policy version used for all evaluations
    /// * `successful` - Count of successful evaluations
    /// * `failed` - Count of failed evaluations
    pub fn new(
        results: Vec<IndexedResult<T>>,
        version: PolicyVersion,
        successful: usize,
        failed: usize,
    ) -> Self {
        Self {
            results,
            version,
            successful,
            failed,
        }
    }

    /// Get the number of successful evaluations
    pub fn successes(&self) -> usize {
        self.successful
    }

    /// Get the number of failed evaluations
    pub fn failures(&self) -> usize {
        self.failed
    }

    /// Get the policy version used for evaluations
    pub fn version(&self) -> &PolicyVersion {
        &self.version
    }

    /// Get the total number of results
    pub fn total(&self) -> usize {
        self.results.len()
    }

    /// Get a slice of all results
    pub fn results(&self) -> &[IndexedResult<T>] {
        &self.results
    }

    /// Find a result by client-provided ID
    ///
    /// Returns the first matching result if multiple results have the same ID.
    ///
    /// # Arguments
    /// * `id` - The client-provided identifier to search for
    ///
    /// # Returns
    /// A reference to the matching result, or None if not found
    pub fn find_by_id(&self, id: &str) -> Option<&IndexedResult<T>> {
        self.results.iter().find(|r| r.id.as_deref() == Some(id))
    }

    /// Get a result by its index in the batch
    ///
    /// # Arguments
    /// * `index` - The index position in the results vector
    ///
    /// # Returns
    /// A reference to the result at that index, or None if out of bounds
    pub fn get_at(&self, index: usize) -> Option<&IndexedResult<T>> {
        self.results.get(index)
    }

    /// Iterate over results
    pub fn iter(&self) -> impl Iterator<Item = &IndexedResult<T>> {
        self.results.iter()
    }
}

impl<'a, T> IntoIterator for &'a AuthorizeResponse<T> {
    type Item = &'a IndexedResult<T>;
    type IntoIter = std::slice::Iter<'a, IndexedResult<T>>;

    /// Create an iterator over results by reference
    fn into_iter(self) -> Self::IntoIter {
        self.results.iter()
    }
}

/// Type alias for brief authorization response variant
pub type AuthorizeBriefResponse = AuthorizeResponse<AuthorizeDecisionBrief>;
/// Type alias for detailed authorization response variant
pub type AuthorizeDetailedResponse = AuthorizeResponse<AuthorizeDecisionDetailed>;

/// Response from the authorize endpoint - either brief or detailed based on query parameter
///
/// Uses tagged serde enum to deserialize into the correct variant.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum AuthorizeResponseVariant {
    /// Brief response with minimal decision information
    Brief(AuthorizeBriefResponse),
    /// Detailed response with full decision reasoning
    Detailed(AuthorizeDetailedResponse),
}

/// Deserializable result type for authorize endpoint responses
pub type AuthorizedResult = AuthorizeResponseVariant;

/// Type alias for brief batch check response variant
pub type BatchCheckResponse = AuthorizeResponse<AuthorizeDecisionBrief>;

/// Type alias for detailed batch check response variant
pub type BatchCheckDetailedResponse = AuthorizeResponse<AuthorizeDecisionDetailed>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_request_limits_deserialize_legacy_shape() {
        let limits: RequestLimits = serde_json::from_str(
            r#"{
                "max_context_bytes": 8192,
                "max_context_depth": 4,
                "max_context_keys": 32
            }"#,
        )
        .unwrap();

        assert_eq!(limits.max_batch_size, None);
        assert_eq!(limits.max_context_bytes, 8192);
        assert_eq!(limits.max_context_depth, 4);
        assert_eq!(limits.max_context_keys, 32);
    }

    #[test]
    fn test_endpoint_new() {
        let url = Url::parse("https://example.com/api").unwrap();
        let endpoint = Endpoint::new(url.clone());
        assert_eq!(endpoint.as_str(), "https://example.com/api");
        assert_eq!(endpoint.url(), &url);
    }

    #[test]
    fn test_endpoint_from_str() {
        let endpoint = Endpoint::from_str("https://example.com/api").unwrap();
        assert_eq!(endpoint.as_str(), "https://example.com/api");
    }

    #[test]
    fn test_endpoint_from_str_invalid() {
        let result = Endpoint::from_str("not a valid url");
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoint_display() {
        let endpoint = Endpoint::from_str("https://example.com/api").unwrap();
        assert_eq!(format!("{}", endpoint), "https://example.com/api");
    }

    #[test]
    fn test_indexed_result_accessors() {
        // Test that IndexedResult accessors work correctly
        let result = IndexedResult::new(
            5,
            Some("test-id".to_string()),
            BatchResult::Success {
                data: "success".to_string(),
            },
        );

        assert_eq!(result.index(), 5);
        assert_eq!(result.id(), Some("test-id"));
        assert!(matches!(result.result(), BatchResult::Success { .. }));
    }

    #[test]
    fn test_indexed_result_without_id() {
        // Test IndexedResult with no client ID
        let result: IndexedResult<String> = IndexedResult::new(
            0,
            None,
            BatchResult::Failed {
                message: "error".to_string(),
            },
        );

        assert_eq!(result.index(), 0);
        assert_eq!(result.id(), None);
        assert!(matches!(result.result(), BatchResult::Failed { .. }));
    }

    #[test]
    fn test_authorize_response_accessors() {
        // Test AuthorizeResponse accessor methods
        let results = vec![
            IndexedResult::new(
                0,
                Some("req-1".to_string()),
                BatchResult::Success {
                    data: "success1".to_string(),
                },
            ),
            IndexedResult::new(
                1,
                None,
                BatchResult::Failed {
                    message: "error".to_string(),
                },
            ),
        ];

        // Create a minimal PolicyVersion by deserializing from JSON (the only way to construct it)
        let version_json =
            r#"{"hash": "test-hash", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();

        let response = AuthorizeResponse::new(results, version, 1, 1);

        assert_eq!(response.successes(), 1);
        assert_eq!(response.failures(), 1);
        assert_eq!(response.total(), 2);
        assert_eq!(response.version().hash.as_ref(), "test-hash");
    }

    #[test]
    fn test_find_by_id_existing() {
        // Test finding a result by an existing ID
        let results = vec![
            IndexedResult::new(
                0,
                Some("req-1".to_string()),
                BatchResult::Success {
                    data: "success1".to_string(),
                },
            ),
            IndexedResult::new(
                1,
                Some("req-2".to_string()),
                BatchResult::Success {
                    data: "success2".to_string(),
                },
            ),
        ];
        let version_json = r#"{"hash": "v1", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();
        let response = AuthorizeResponse::new(results, version, 2, 0);

        let found = response.find_by_id("req-2");
        assert!(found.is_some());
        assert_eq!(found.unwrap().index(), 1);
        assert_eq!(found.unwrap().id(), Some("req-2"));
    }

    #[test]
    fn test_find_by_id_not_found() {
        // Test that find_by_id returns None for non-existent ID
        let results = vec![IndexedResult::new(
            0,
            Some("req-1".to_string()),
            BatchResult::Success {
                data: "success1".to_string(),
            },
        )];
        let version_json = r#"{"hash": "v1", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();
        let response = AuthorizeResponse::new(results, version, 1, 0);

        let found = response.find_by_id("req-nonexistent");
        assert!(found.is_none());
    }

    #[test]
    fn test_find_by_id_with_none_ids() {
        // Test find_by_id when some results have no ID
        let results = vec![
            IndexedResult::new(
                0,
                None,
                BatchResult::Success {
                    data: "success1".to_string(),
                },
            ),
            IndexedResult::new(
                1,
                Some("req-2".to_string()),
                BatchResult::Success {
                    data: "success2".to_string(),
                },
            ),
            IndexedResult::new(
                2,
                None,
                BatchResult::Success {
                    data: "success3".to_string(),
                },
            ),
        ];
        let version_json = r#"{"hash": "v1", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();
        let response = AuthorizeResponse::new(results, version, 3, 0);

        // Should find the one with ID
        let found = response.find_by_id("req-2");
        assert!(found.is_some());
        assert_eq!(found.unwrap().index(), 1);

        // Should not match None entries
        let not_found = response.find_by_id("none");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_find_by_id_first_match() {
        // Test that find_by_id returns the first matching result
        let results = vec![
            IndexedResult::new(
                0,
                Some("req-1".to_string()),
                BatchResult::Success {
                    data: "success1".to_string(),
                },
            ),
            IndexedResult::new(
                1,
                Some("req-1".to_string()),
                BatchResult::Success {
                    data: "success2".to_string(),
                },
            ),
        ];
        let version_json = r#"{"hash": "v1", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();
        let response = AuthorizeResponse::new(results, version, 2, 0);

        let found = response.find_by_id("req-1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().index(), 0); // Should return the first match
    }

    #[test]
    fn test_find_by_id_empty_response() {
        // Test find_by_id on an empty response
        let results: Vec<IndexedResult<String>> = vec![];
        let version_json = r#"{"hash": "v1", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();
        let response = AuthorizeResponse::new(results, version, 0, 0);

        let found = response.find_by_id("any-id");
        assert!(found.is_none());
    }

    #[test]
    fn test_authorize_response_iteration() {
        // Test iterating over response results
        let results = vec![
            IndexedResult::new(
                0,
                Some("req-1".to_string()),
                BatchResult::Success {
                    data: "success1".to_string(),
                },
            ),
            IndexedResult::new(
                1,
                Some("req-2".to_string()),
                BatchResult::Success {
                    data: "success2".to_string(),
                },
            ),
        ];
        let version_json = r#"{"hash": "v1", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();
        let response = AuthorizeResponse::new(results, version, 2, 0);

        let ids: Vec<_> = response.iter().filter_map(|r| r.id()).collect();

        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"req-1"));
        assert!(ids.contains(&"req-2"));
    }

    #[test]
    fn test_authorize_response_get_at() {
        // Test getting result by index
        let results = vec![
            IndexedResult::new(
                0,
                Some("req-1".to_string()),
                BatchResult::Success {
                    data: "success1".to_string(),
                },
            ),
            IndexedResult::new(
                1,
                Some("req-2".to_string()),
                BatchResult::Success {
                    data: "success2".to_string(),
                },
            ),
        ];
        let version_json = r#"{"hash": "v1", "serial": 1, "loaded_at": "2024-01-01T00:00:00Z"}"#;
        let version: PolicyVersion = serde_json::from_str(version_json).unwrap();
        let response = AuthorizeResponse::new(results, version, 2, 0);

        let first = response.get_at(0);
        assert!(first.is_some());
        assert_eq!(first.unwrap().index(), 0);

        let second = response.get_at(1);
        assert!(second.is_some());
        assert_eq!(second.unwrap().index(), 1);

        let out_of_bounds = response.get_at(2);
        assert!(out_of_bounds.is_none());
    }
}
