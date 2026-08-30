use cedar_policy::{
    PolicySet as CedarPolicySet, Schema as CedarSchema, ValidationMode as CedarValidationMode,
    Validator as CedarValidator,
};
use chrono::{DateTime, Utc};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter, Result as FmtResult, Write};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, RwLock};
use tracing::{debug, warn};
use treetop_bundle::{LabelSet, ValidatedBundle};
use treetop_core::{LabelRegistryBuilder, Labeler, PolicyEngine};
use utoipa::ToSchema;

use crate::{
    config::{BundleEngineMode, SchemaValidationMode},
    errors::ServiceError,
    metrics,
    models::{BundleMetadata, Endpoint, PoliciesMetadata, RequestContextStatus, UserPolicies},
};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OfPolicies;
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OfLabels;
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OfSchema;

pub trait MetadataParser {
    /// Count the number of entries in the content.
    fn count_entries(content: &str) -> Result<usize, ServiceError>;

    /// Return the size of the content in bytes.
    fn content_size(content: &str) -> usize {
        content.len()
    }

    /// Validate the content, by default does nothing.
    fn validate_content(_: &str) -> Result<(), ServiceError> {
        Ok(())
    }

    /// Make a sha256 hash of the content.
    fn make_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hasher
            .finalize()
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Process the content after parsing, by default does nothing.
    fn process_content(_: &str) -> Result<(), ServiceError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Metadata<T> {
    pub timestamp: DateTime<Utc>,
    pub sha256: String,
    pub size: usize,
    pub source: Option<Endpoint>,
    pub refresh_frequency: Option<u32>,
    pub entries: usize,
    pub content: String,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> Display for Metadata<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let source = match &self.source {
            Some(s) => s.as_str(),
            None => "None",
        };

        let refresh = match self.refresh_frequency {
            Some(freq) => freq.to_string(),
            None => "None".into(),
        };

        write!(
            f,
            "   source: {}
   timestamp: {}
   sha256: {}
   size: {}
   refresh_frequency: {}
   entries: {}",
            source, self.timestamp, self.sha256, self.size, refresh, self.entries,
        )
    }
}

impl<T: MetadataParser> Metadata<T> {
    pub fn new(
        content: String,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
    ) -> Result<Self, ServiceError> {
        if content.is_empty() && source.is_none() && refresh_frequency.is_none() {
            return Ok(Metadata {
                timestamp: Utc::now(),
                sha256: String::new(),
                size: 0,
                source,
                refresh_frequency,
                entries: 0,
                content: String::new(),
                _marker: PhantomData,
            });
        }

        T::validate_content(&content)?;

        let sha256 = T::make_hash(&content);
        let size = T::content_size(&content);
        let entries = T::count_entries(&content)?;

        T::process_content(&content)?;

        if let Some(source) = source.clone() {
            debug!(
                update = "Metadata",
                source = source.to_string(),
                sha256 = sha256,
                size = size,
                entries = entries
            );
        }

        Ok(Metadata {
            timestamp: Utc::now(),
            sha256,
            size,
            source,
            refresh_frequency,
            entries,
            content,
            _marker: PhantomData,
        })
    }

    /// Construct metadata for content already validated by the caller.
    fn from_validated_content(
        content: String,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
        entries: usize,
    ) -> Self {
        let sha256 = T::make_hash(&content);
        let size = T::content_size(&content);
        if let Some(source) = source.as_ref() {
            debug!(
                update = "Metadata",
                source = source.to_string(),
                sha256 = sha256,
                size = size,
                entries = entries
            );
        }
        Self {
            timestamp: Utc::now(),
            sha256,
            size,
            source,
            refresh_frequency,
            entries,
            content,
            _marker: PhantomData,
        }
    }
}

/// Parse labels from JSON and return them as a vector of labelers.
///
/// The format of the JSON is expected to be an array of objects, each with a "kind", "field", "output" and "patterns" field.
pub fn parse_labels(content: &str) -> Result<Vec<Arc<dyn Labeler>>, ServiceError> {
    Ok(LabelSet::from_json_str(content)?.to_labelers())
}

/// Count the number of policy entries in the content.
///
/// The content is expected to be in the policy DSL format.
impl MetadataParser for OfPolicies {
    fn count_entries(content: &str) -> Result<usize, ServiceError> {
        Ok(content
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                line.starts_with("permit (") || line.starts_with("forbid (")
            })
            .count())
    }
}

/// Count the number of host labels in the content.
///
/// The format of the JSON is expected to be an array of objects, each with a "name" and "regex" field.
/// Example:
/// ```json
/// [
///     { "name": "example.com", "regex": "^example\\.com$" },
///     { "name": "test.com", "regex": "^test\\.com$" }
/// ]
/// ```
impl MetadataParser for OfLabels {
    fn count_entries(content: &str) -> Result<usize, ServiceError> {
        Ok(LabelSet::from_json_str(content)?.rules().len())
    }

    fn process_content(content: &str) -> Result<(), ServiceError> {
        // Validate that the labels can be parsed
        parse_labels(content)?;
        Ok(())
    }
}

impl MetadataParser for OfSchema {
    fn count_entries(content: &str) -> Result<usize, ServiceError> {
        let schema_json: serde_json::Value = serde_json::from_str(content)?;
        match schema_json {
            serde_json::Value::Object(obj) => Ok(obj.len()),
            _ => Ok(1),
        }
    }

    fn validate_content(content: &str) -> Result<(), ServiceError> {
        CedarSchema::from_json_str(content)
            .map(|_| ())
            .map_err(|e| ServiceError::SchemaValidationError(e.to_string()))
    }
}

pub struct PolicyStore {
    pub engine: Arc<PolicyEngine>,
    pub allow_upload: bool,
    pub upload_token: Option<String>,
    pub schema_validation_mode: SchemaValidationMode,
    pub request_context_status: RequestContextStatus,

    pub policies: Metadata<OfPolicies>,
    pub labels: Metadata<OfLabels>,
    pub schema: Metadata<OfSchema>,
    pub bundle: Option<BundleMetadata>,
    pub bundle_url_mode: bool,
    pub label_registry_labelers: Vec<Arc<dyn Labeler>>,
    remote_loads: RemoteLoadStatus,
    list_policies_raw_cache: Mutex<LruCache<ListPoliciesCacheKey, Arc<String>>>,
    list_policies_json_cache: Mutex<LruCache<ListPoliciesCacheKey, Arc<UserPolicies>>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RemoteSourceKind {
    Policies,
    Labels,
    Schema,
    Bundle,
}

#[derive(Debug, Default, Clone)]
struct RemoteLoadStatus {
    policies: RemoteSourceStatus,
    labels: RemoteSourceStatus,
    schema: RemoteSourceStatus,
    bundle: RemoteSourceStatus,
}

#[derive(Debug, Default, Clone)]
struct RemoteSourceStatus {
    configuration: Option<(Endpoint, u32)>,
    loaded: bool,
}

impl RemoteSourceStatus {
    fn configure(&mut self, source: Endpoint, refresh_frequency: u32) {
        self.configuration = Some((source, refresh_frequency));
        self.loaded = false;
    }

    fn mark_loaded(&mut self) -> Option<(Endpoint, u32)> {
        self.loaded = true;
        self.configuration.clone()
    }

    fn ready(&self, metadata_has_source: bool) -> bool {
        !(self.configuration.is_some() || metadata_has_source) || self.loaded
    }
}

pub struct PreparedBundle {
    engine: Arc<PolicyEngine>,
    policies: Metadata<OfPolicies>,
    labels: Metadata<OfLabels>,
    schema: Metadata<OfSchema>,
    labelers: Vec<Arc<dyn Labeler>>,
    request_context_status: RequestContextStatus,
    bundle: BundleMetadata,
}

impl PreparedBundle {
    /// Build the upload response outside the store write lock.
    pub(crate) fn metadata(
        &self,
        allow_upload: bool,
        schema_validation_mode: SchemaValidationMode,
    ) -> PoliciesMetadata {
        PoliciesMetadata {
            allow_upload,
            schema_validation_mode: schema_validation_mode.to_string(),
            policies: self.policies.clone(),
            labels: self.labels.clone(),
            schema: self.schema.clone(),
            bundle: Some(self.bundle.clone()),
        }
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self {
            engine: Arc::new(
                PolicyEngine::new_from_str("").expect("Failed to initialize policy engine"),
            ),
            allow_upload: false,
            upload_token: None,
            schema_validation_mode: SchemaValidationMode::Permissive,
            request_context_status: RequestContextStatus::default(),
            policies: Metadata::<OfPolicies>::new(String::new(), None, None).unwrap(),
            labels: Metadata::<OfLabels>::new(String::new(), None, None).unwrap(),
            schema: Metadata::<OfSchema>::new(String::new(), None, None).unwrap(),
            bundle: None,
            bundle_url_mode: false,
            label_registry_labelers: Vec::new(),
            remote_loads: RemoteLoadStatus::default(),
            list_policies_raw_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(LIST_POLICIES_CACHE_LIMIT).unwrap(),
            )),
            list_policies_json_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(LIST_POLICIES_CACHE_LIMIT).unwrap(),
            )),
        }
    }
}

impl PolicyStore {
    /// Create a new PolicyStore initialized with the given DSL string.
    pub fn new() -> Result<Self, ServiceError> {
        Ok(Self {
            engine: Arc::new(
                PolicyEngine::new_from_str("").expect("Failed to initialize policy engine"),
            ),
            allow_upload: false,
            upload_token: None,
            schema_validation_mode: SchemaValidationMode::Permissive,
            request_context_status: RequestContextStatus::default(),
            policies: Metadata::<OfPolicies>::new(String::new(), None, None)?,
            labels: Metadata::<OfLabels>::new(String::new(), None, None)?,
            schema: Metadata::<OfSchema>::new(String::new(), None, None)?,
            bundle: None,
            bundle_url_mode: false,
            label_registry_labelers: Vec::new(),
            remote_loads: RemoteLoadStatus::default(),
            list_policies_raw_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(LIST_POLICIES_CACHE_LIMIT).unwrap(),
            )),
            list_policies_json_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(LIST_POLICIES_CACHE_LIMIT).unwrap(),
            )),
        })
    }

    pub fn set_schema_validation_mode(&mut self, mode: SchemaValidationMode) {
        self.schema_validation_mode = mode;
    }

    /// Configure a remote source and require a fresh confirmed load for readiness.
    pub(crate) fn configure_remote_source(
        &mut self,
        kind: RemoteSourceKind,
        source: Endpoint,
        refresh_frequency: u32,
    ) {
        match kind {
            RemoteSourceKind::Policies => {
                self.policies.source = Some(source.clone());
                self.policies.refresh_frequency = Some(refresh_frequency);
                self.remote_loads
                    .policies
                    .configure(source, refresh_frequency);
            }
            RemoteSourceKind::Labels => {
                self.labels.source = Some(source.clone());
                self.labels.refresh_frequency = Some(refresh_frequency);
                self.remote_loads
                    .labels
                    .configure(source, refresh_frequency);
            }
            RemoteSourceKind::Schema => {
                self.schema.source = Some(source.clone());
                self.schema.refresh_frequency = Some(refresh_frequency);
                self.remote_loads
                    .schema
                    .configure(source, refresh_frequency);
            }
            RemoteSourceKind::Bundle => {
                self.bundle_url_mode = true;
                self.remote_loads
                    .bundle
                    .configure(source, refresh_frequency);
            }
        }
    }

    /// Record a remote response that was successful, validated, and applied.
    pub(crate) fn mark_remote_source_loaded(&mut self, kind: RemoteSourceKind) {
        match kind {
            RemoteSourceKind::Policies => {
                if let Some((source, refresh_frequency)) = self.remote_loads.policies.mark_loaded()
                {
                    self.policies.source = Some(source);
                    self.policies.refresh_frequency = Some(refresh_frequency);
                }
            }
            RemoteSourceKind::Labels => {
                if let Some((source, refresh_frequency)) = self.remote_loads.labels.mark_loaded() {
                    self.labels.source = Some(source);
                    self.labels.refresh_frequency = Some(refresh_frequency);
                }
            }
            RemoteSourceKind::Schema => {
                if let Some((source, refresh_frequency)) = self.remote_loads.schema.mark_loaded() {
                    self.schema.source = Some(source);
                    self.schema.refresh_frequency = Some(refresh_frequency);
                }
            }
            RemoteSourceKind::Bundle => {
                let _ = self.remote_loads.bundle.mark_loaded();
            }
        }
    }

    /// Whether every configured remote source has completed a confirmed valid load.
    ///
    /// A source remains ready after its first successful load because the store keeps
    /// serving the last-known-good value when a later refresh fails.
    pub(crate) fn configured_sources_loaded(&self) -> bool {
        if self.bundle_url_mode {
            self.remote_loads.bundle.ready(true)
        } else {
            self.remote_loads
                .policies
                .ready(self.policies.source.is_some())
                && self.remote_loads.labels.ready(self.labels.source.is_some())
                && self.remote_loads.schema.ready(self.schema.source.is_some())
        }
    }

    fn current_schema(&self) -> Result<Option<CedarSchema>, ServiceError> {
        if self.schema.content.is_empty() {
            return Ok(None);
        }
        CedarSchema::from_json_str(&self.schema.content)
            .map(Some)
            .map_err(|e| ServiceError::SchemaValidationError(e.to_string()))
    }

    fn validate_policies_with_schema(
        &self,
        dsl: &str,
        schema: &CedarSchema,
    ) -> Result<(), ServiceError> {
        let policy_set: CedarPolicySet = dsl
            .parse::<CedarPolicySet>()
            .map_err(|e| ServiceError::CompileError(e.to_string()))?;

        let validator = CedarValidator::new(schema.clone());
        let result = validator.validate(&policy_set, CedarValidationMode::Strict);

        if result.validation_passed() {
            return Ok(());
        }

        let reasons = result
            .validation_errors()
            .take(5)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let detail = if reasons.is_empty() {
            "schema validation failed".to_string()
        } else {
            reasons.join("; ")
        };
        Err(ServiceError::SchemaValidationError(detail))
    }

    fn ensure_schema_present_for_policy_reload(&self) -> Result<(), ServiceError> {
        if self.schema_validation_mode == SchemaValidationMode::Strict
            && self.schema.content.is_empty()
        {
            return Err(ServiceError::SchemaValidationError(
                "strict schema validation requires an uploaded schema before policy reload"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_bundle_schema_present(
        schema_validation_mode: SchemaValidationMode,
        schema_present: bool,
    ) -> Result<(), ServiceError> {
        if schema_validation_mode == SchemaValidationMode::Strict && !schema_present {
            return Err(ServiceError::SchemaValidationError(
                "strict schema validation requires every bundle to include a schema".to_string(),
            ));
        }
        Ok(())
    }

    fn runtime_schema_for_dsl(
        &self,
        dsl: &str,
        schema: Option<CedarSchema>,
    ) -> Result<(Option<CedarSchema>, RequestContextStatus), ServiceError> {
        let Some(schema) = schema else {
            return Ok((None, RequestContextStatus::no_schema()));
        };

        match self.validate_policies_with_schema(dsl, &schema) {
            Ok(()) => Ok((Some(schema), RequestContextStatus::schema_backed())),
            Err(e) if self.schema_validation_mode == SchemaValidationMode::Permissive => {
                warn!(message = "Policy/schema mismatch in permissive mode", error = %e);
                metrics::record_schema_validation_failure("policy_schema_mismatch");
                Ok((None, RequestContextStatus::schema_incompatible()))
            }
            Err(e) => {
                metrics::record_schema_validation_failure("policy_schema_mismatch");
                Err(e)
            }
        }
    }

    fn build_engine_from_parts(
        dsl: &str,
        schema: Option<CedarSchema>,
        labelers: &[Arc<dyn Labeler>],
    ) -> Result<PolicyEngine, ServiceError> {
        let mut engine = match schema {
            Some(schema) => PolicyEngine::new_from_str_with_schema(dsl, schema)?,
            None => PolicyEngine::new_from_str(dsl)?,
        };

        if !labelers.is_empty() {
            let mut builder = LabelRegistryBuilder::new();
            for labeler in labelers {
                builder = builder.add_labeler(Arc::clone(labeler));
            }
            engine = engine.with_label_registry(builder.build());
        }

        Ok(engine)
    }

    fn rebuild_engine_for_dsl_with_parts(
        &mut self,
        dsl: &str,
        schema: Option<CedarSchema>,
        labelers: &[Arc<dyn Labeler>],
    ) -> Result<(), ServiceError> {
        let (runtime_schema, request_context_status) = self.runtime_schema_for_dsl(dsl, schema)?;
        let engine = Self::build_engine_from_parts(dsl, runtime_schema, labelers)?;
        self.engine = Arc::new(engine);
        self.request_context_status = request_context_status;
        Ok(())
    }

    pub fn set_dsl(
        &mut self,
        dsl: &str,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
    ) -> Result<(), ServiceError> {
        self.ensure_schema_present_for_policy_reload()?;

        let old_metadata = self.policies.clone();
        let source = source.or(old_metadata.source);
        let refresh_frequency = refresh_frequency.or(old_metadata.refresh_frequency);

        let metadata = Metadata::<OfPolicies>::new(dsl.to_string(), source, refresh_frequency)?;
        let schema = self.current_schema()?;
        let labelers = self.label_registry_labelers.clone();
        self.rebuild_engine_for_dsl_with_parts(dsl, schema, &labelers)?;
        self.policies = metadata;
        self.bundle = None;
        self.clear_list_policies_cache()?;
        Ok(())
    }

    pub fn set_schema(
        &mut self,
        schema: &str,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
    ) -> Result<(), ServiceError> {
        let old_metadata = self.schema.clone();
        let source = source.or(old_metadata.source);
        let refresh_frequency = refresh_frequency.or(old_metadata.refresh_frequency);

        let metadata =
            match Metadata::<OfSchema>::new(schema.to_string(), source, refresh_frequency) {
                Ok(metadata) => metadata,
                Err(e) => {
                    metrics::record_schema_validation_failure("schema_parse");
                    return Err(e);
                }
            };
        let parsed_schema = match CedarSchema::from_json_str(schema) {
            Ok(schema) => schema,
            Err(e) => {
                metrics::record_schema_validation_failure("schema_parse");
                return Err(ServiceError::SchemaValidationError(e.to_string()));
            }
        };
        if !self.labels.content.is_empty() {
            LabelSet::from_json_str(&self.labels.content)?.validate_schema_json_str(schema)?;
        }
        let dsl = self.policies.content.clone();
        let labelers = self.label_registry_labelers.clone();
        self.rebuild_engine_for_dsl_with_parts(&dsl, Some(parsed_schema), &labelers)?;

        self.schema = metadata;
        self.bundle = None;
        metrics::record_schema_reload();
        Ok(())
    }

    pub fn set_labels(
        &mut self,
        labels: &str,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
    ) -> Result<(), ServiceError> {
        let old_metadata = self.labels.clone();
        let source = source.or(old_metadata.source);
        let refresh_frequency = refresh_frequency.or(old_metadata.refresh_frequency);

        let label_set = LabelSet::from_json_str(labels)?;
        if !self.schema.content.is_empty() {
            label_set.validate_schema_json_str(&self.schema.content)?;
        }
        let metadata = Metadata::<OfLabels>::from_validated_content(
            labels.to_string(),
            source,
            refresh_frequency,
            label_set.rules().len(),
        );
        let labelers = label_set.to_labelers();
        let dsl = self.policies.content.clone();
        let schema = self.current_schema()?;
        self.rebuild_engine_for_dsl_with_parts(&dsl, schema, &labelers)?;

        self.label_registry_labelers = labelers;
        self.labels = metadata;
        self.bundle = None;
        self.clear_list_policies_cache()?;
        Ok(())
    }

    /// Prepare a complete bundle replacement without holding the store write lock.
    pub fn prepare_bundle(
        validated: &ValidatedBundle,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
        schema_validation_mode: SchemaValidationMode,
    ) -> Result<PreparedBundle, ServiceError> {
        Self::prepare_bundle_with_engine_mode(
            validated,
            source,
            refresh_frequency,
            schema_validation_mode,
            BundleEngineMode::Monolithic,
        )
    }

    /// Prepare a complete bundle replacement using the selected engine layout.
    pub fn prepare_bundle_with_engine_mode(
        validated: &ValidatedBundle,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
        schema_validation_mode: SchemaValidationMode,
        engine_mode: BundleEngineMode,
    ) -> Result<PreparedBundle, ServiceError> {
        Self::ensure_bundle_schema_present(
            schema_validation_mode,
            validated.schema_json().is_some(),
        )?;
        let engine = Arc::new(match engine_mode {
            BundleEngineMode::Monolithic => validated.prepare_engine()?,
            BundleEngineMode::BundleModules => validated.prepare_engine_with_policy_stores()?,
        });
        let policies = Metadata::<OfPolicies>::from_validated_content(
            validated.policies().to_string(),
            source.clone(),
            refresh_frequency,
            validated.policy_ids().len(),
        );
        let labels_json = validated.labels_json()?;
        let labels = Metadata::<OfLabels>::from_validated_content(
            labels_json,
            source.clone(),
            refresh_frequency,
            validated.labels().rules().len(),
        );
        let schema = match validated.schema_json_string()? {
            Some(schema_json) => {
                let entries = validated.schema_json().map_or(0, |schema| match schema {
                    serde_json::Value::Object(namespaces) => namespaces.len(),
                    _ => 1,
                });
                Metadata::<OfSchema>::from_validated_content(
                    schema_json,
                    source.clone(),
                    refresh_frequency,
                    entries,
                )
            }
            None => Metadata::<OfSchema>::from_validated_content(
                String::new(),
                source.clone(),
                refresh_frequency,
                0,
            ),
        };
        let signature = validated.verified_signature();
        Ok(PreparedBundle {
            engine,
            policies,
            labels,
            schema,
            labelers: validated.labels().to_labelers(),
            request_context_status: if validated.schema_json().is_some() {
                RequestContextStatus::schema_backed()
            } else {
                RequestContextStatus::no_schema()
            },
            bundle: BundleMetadata {
                format_version: validated.format_version(),
                bundle_id: validated.bundle_id().to_string(),
                archive_sha256: validated.archive_sha256().to_string(),
                compressed_size: validated.compressed_size(),
                module_count: validated.module_count(),
                signed: signature.is_signed(),
                signing_key_id: signature.key_id().map(ToString::to_string),
                source,
                refresh_frequency,
                loaded_at: Utc::now(),
            },
        })
    }

    /// Atomically publish a previously prepared bundle candidate.
    pub fn apply_prepared_bundle(&mut self, prepared: PreparedBundle) -> Result<(), ServiceError> {
        Self::ensure_bundle_schema_present(
            self.schema_validation_mode,
            !prepared.schema.content.is_empty(),
        )?;
        self.clear_list_policies_cache()?;
        self.engine = prepared.engine;
        self.policies = prepared.policies;
        self.labels = prepared.labels;
        self.schema = prepared.schema;
        self.label_registry_labelers = prepared.labelers;
        self.request_context_status = prepared.request_context_status;
        self.bundle = Some(prepared.bundle);
        Ok(())
    }

    pub fn list_policies_raw(
        &self,
        user: String,
        mut groups: Vec<String>,
        mut namespaces: Vec<String>,
    ) -> Result<Arc<String>, ServiceError> {
        normalize_list_filters(&mut groups, &mut namespaces);
        let key = ListPoliciesCacheKey::new(user, groups, namespaces);
        let mut cache = self.list_policies_raw_cache.lock().map_err(|e| {
            ServiceError::ListPoliciesError(format!("list policies raw cache lock poisoned: {e}"))
        })?;
        if let Some(cached) = cache.get(&key) {
            return Ok(Arc::clone(cached));
        }
        drop(cache);

        let policies = self.list_policies_for_key(&key)?;
        let content = Arc::new(format_policies_raw(&policies));
        let mut cache = self.list_policies_raw_cache.lock().map_err(|e| {
            ServiceError::ListPoliciesError(format!("list policies raw cache lock poisoned: {e}"))
        })?;
        cache.put(key, Arc::clone(&content));
        Ok(content)
    }

    pub fn list_policies_json(
        &self,
        user: String,
        mut groups: Vec<String>,
        mut namespaces: Vec<String>,
    ) -> Result<Arc<UserPolicies>, ServiceError> {
        normalize_list_filters(&mut groups, &mut namespaces);
        let key = ListPoliciesCacheKey::new(user, groups, namespaces);
        let mut cache = self.list_policies_json_cache.lock().map_err(|e| {
            ServiceError::ListPoliciesError(format!("list policies json cache lock poisoned: {e}"))
        })?;
        if let Some(cached) = cache.get(&key) {
            return Ok(Arc::clone(cached));
        }
        drop(cache);

        let policies = self.list_policies_for_key(&key)?;
        let response = Arc::new(UserPolicies::try_from(policies)?);
        let mut cache = self.list_policies_json_cache.lock().map_err(|e| {
            ServiceError::ListPoliciesError(format!("list policies json cache lock poisoned: {e}"))
        })?;
        cache.put(key, Arc::clone(&response));
        Ok(response)
    }

    fn list_policies_for_key(
        &self,
        key: &ListPoliciesCacheKey,
    ) -> Result<treetop_core::UserPolicies, ServiceError> {
        let namespace: Vec<&str> = key.namespaces.iter().map(|s| s.as_str()).collect();
        let group_refs: Vec<&str> = key.groups.iter().map(|s| s.as_str()).collect();
        Ok(self
            .engine
            .list_policies_for_user(&key.user, &group_refs, &namespace)?)
    }

    fn clear_list_policies_cache(&self) -> Result<(), ServiceError> {
        self.list_policies_raw_cache
            .lock()
            .map_err(|e| {
                ServiceError::ListPoliciesError(format!(
                    "list policies raw cache lock poisoned: {e}"
                ))
            })?
            .clear();
        self.list_policies_json_cache
            .lock()
            .map_err(|e| {
                ServiceError::ListPoliciesError(format!(
                    "list policies json cache lock poisoned: {e}"
                ))
            })?
            .clear();
        Ok(())
    }
}

pub type SharedPolicyStore = Arc<RwLock<PolicyStore>>;

const LIST_POLICIES_CACHE_LIMIT: usize = 128;

#[derive(Clone, Hash, Eq, PartialEq)]
struct ListPoliciesCacheKey {
    user: String,
    groups: Vec<String>,
    namespaces: Vec<String>,
}

impl ListPoliciesCacheKey {
    fn new(user: String, groups: Vec<String>, namespaces: Vec<String>) -> Self {
        Self {
            user,
            groups,
            namespaces,
        }
    }
}

fn format_policies_raw(policies: &treetop_core::UserPolicies) -> String {
    let mut content = String::new();
    for (index, policy) in policies.policies().iter().enumerate() {
        if index > 0 {
            content.push('\n');
        }
        let _ = write!(content, "{policy}");
    }
    content
}

fn normalize_list_filters(groups: &mut Vec<String>, namespaces: &mut Vec<String>) {
    groups.sort_unstable();
    groups.dedup();
    namespaces.sort_unstable();
    namespaces.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Endpoint;
    use serde_json::Value;
    use std::str::FromStr;

    fn schema_free_prepared_bundle() -> PreparedBundle {
        let policies = "permit (principal, action, resource);";
        PreparedBundle {
            engine: Arc::new(PolicyEngine::new_from_str(policies).unwrap()),
            policies: Metadata::<OfPolicies>::new(policies.to_string(), None, None).unwrap(),
            labels: Metadata::<OfLabels>::new(String::new(), None, None).unwrap(),
            schema: Metadata::<OfSchema>::new(String::new(), None, None).unwrap(),
            labelers: Vec::new(),
            request_context_status: RequestContextStatus::no_schema(),
            bundle: BundleMetadata {
                format_version: 1,
                bundle_id: "bundle-id".to_string(),
                archive_sha256: "archive-sha256".to_string(),
                compressed_size: 1,
                module_count: 1,
                signed: false,
                signing_key_id: None,
                source: None,
                refresh_frequency: None,
                loaded_at: Utc::now(),
            },
        }
    }

    const CONTEXT_POLICY_DSL: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    context.env == "prod"
};
"#;

    const CONTEXT_SCHEMA_JSON: &str = r#"{
  "": {
    "entityTypes": {
      "User": {},
      "Photo": {
        "shape": {
          "type": "Record",
          "attributes": {
            "name": {
              "type": "String",
              "required": true
            },
            "nameLabels": {
              "type": "Set",
              "element": {
                "type": "String"
              },
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
          "resourceTypes": ["Photo"],
          "context": {
            "type": "Record",
            "attributes": {
              "env": {
                "type": "String",
                "required": true
              }
            },
            "additionalAttributes": false
          }
        }
      }
    }
  }
}"#;

    const INCOMPATIBLE_POLICY_DSL: &str = r#"
permit (
    principal == Group::"ops",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const LABELS_JSON: &str = r#"[
  {
    "kind": "Photo",
    "field": "name",
    "output": "nameLabels",
    "patterns": [
      {
        "name": "vacation",
        "regex": "^Vacation.*"
      }
    ]
  }
]"#;

    #[test]
    fn test_metadata_empty() {
        let metadata = Metadata::<OfPolicies>::new(String::new(), None, None).unwrap();
        assert_eq!(metadata.size, 0);
        assert_eq!(metadata.entries, 0);
        assert!(metadata.content.is_empty());
        assert!(metadata.sha256.is_empty());
    }

    #[test]
    fn test_metadata_policies_count() {
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"photo.jpg"
);

forbid (
    principal == User::"bob",
    action == Action::"delete",
    resource == Photo::"photo.jpg"
);
"#;
        let metadata = Metadata::<OfPolicies>::new(dsl.to_string(), None, None).unwrap();
        assert_eq!(metadata.entries, 2);
        assert_eq!(metadata.size, dsl.len());
        assert!(!metadata.sha256.is_empty());
    }

    #[test]
    fn test_metadata_with_source() {
        let dsl = "permit (principal, action, resource);";
        let endpoint = Endpoint::from_str("https://example.com/policies").unwrap();
        let metadata =
            Metadata::<OfPolicies>::new(dsl.to_string(), Some(endpoint.clone()), Some(60)).unwrap();

        assert_eq!(metadata.entries, 1);
        assert_eq!(
            metadata.source.unwrap().as_str(),
            "https://example.com/policies"
        );
        assert_eq!(metadata.refresh_frequency, Some(60));
    }

    #[test]
    fn test_metadata_labels_valid() {
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "example_domain",
                "regex": "example\\.com$"
            }
        ]
    }
]"#;
        let metadata = Metadata::<OfLabels>::new(labels_json.to_string(), None, None).unwrap();
        assert_eq!(metadata.entries, 1);
        assert!(!metadata.sha256.is_empty());
    }

    #[test]
    fn test_metadata_labels_invalid_json() {
        let invalid_json = "{ not valid json }";
        let result = Metadata::<OfLabels>::new(invalid_json.to_string(), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_labels_empty_pattern() {
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "",
                "regex": "test"
            }
        ]
    }
]"#;
        let result = Metadata::<OfLabels>::new(labels_json.to_string(), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_labels_invalid_regex() {
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "bad_pattern",
                "regex": "[invalid(regex"
            }
        ]
    }
]"#;
        let result = Metadata::<OfLabels>::new(labels_json.to_string(), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_store_default() {
        let store = PolicyStore::default();
        assert!(!store.allow_upload);
        assert!(store.upload_token.is_none());
        assert_eq!(store.policies.entries, 0);
        assert_eq!(store.labels.entries, 0);
        assert!(store.label_registry_labelers.is_empty());
    }

    #[test]
    fn test_policy_store_new() {
        let store = PolicyStore::new().unwrap();
        assert!(!store.allow_upload);
        assert!(store.upload_token.is_none());
        assert_eq!(store.policies.entries, 0);
        assert_eq!(
            store.request_context_status,
            RequestContextStatus::no_schema()
        );
    }

    #[test]
    fn test_remote_readiness_requires_confirmed_load_for_each_source() {
        let mut store = PolicyStore::new().unwrap();
        let endpoint = Endpoint::from_str("https://example.com/config").unwrap();
        assert!(store.configured_sources_loaded());

        store.configure_remote_source(RemoteSourceKind::Policies, endpoint.clone(), 60);
        store.set_dsl("", None, None).unwrap();
        assert!(!store.policies.sha256.is_empty());
        assert!(!store.configured_sources_loaded());
        store.mark_remote_source_loaded(RemoteSourceKind::Policies);
        assert!(store.configured_sources_loaded());

        store.configure_remote_source(RemoteSourceKind::Labels, endpoint.clone(), 60);
        assert!(!store.configured_sources_loaded());
        store.mark_remote_source_loaded(RemoteSourceKind::Labels);
        assert!(store.configured_sources_loaded());

        store.configure_remote_source(RemoteSourceKind::Schema, endpoint.clone(), 60);
        assert!(!store.configured_sources_loaded());
        store.mark_remote_source_loaded(RemoteSourceKind::Schema);
        assert!(store.configured_sources_loaded());

        store.configure_remote_source(RemoteSourceKind::Policies, endpoint, 120);
        assert!(!store.configured_sources_loaded());
    }

    #[test]
    fn bundle_upload_does_not_erase_configured_remote_readiness() {
        let mut store = PolicyStore::new().unwrap();
        let endpoint = Endpoint::from_str("https://example.com/policies").unwrap();
        store.configure_remote_source(RemoteSourceKind::Policies, endpoint, 60);

        store
            .apply_prepared_bundle(schema_free_prepared_bundle())
            .unwrap();

        assert!(store.policies.source.is_none());
        assert!(!store.configured_sources_loaded());
        store.mark_remote_source_loaded(RemoteSourceKind::Policies);
        assert!(store.configured_sources_loaded());
        assert_eq!(
            store.policies.source.as_ref().map(Endpoint::as_str),
            Some("https://example.com/policies")
        );
        assert_eq!(store.policies.refresh_frequency, Some(60));
    }

    #[test]
    fn strict_mode_rejects_schema_free_prepared_bundle_without_replacing_state() {
        let mut store = PolicyStore::new().unwrap();
        store.set_schema_validation_mode(SchemaValidationMode::Strict);
        let previous_engine = Arc::clone(&store.engine);

        let error = store
            .apply_prepared_bundle(schema_free_prepared_bundle())
            .unwrap_err();

        assert!(matches!(error, ServiceError::SchemaValidationError(_)));
        assert!(Arc::ptr_eq(&store.engine, &previous_engine));
        assert!(store.policies.content.is_empty());
        assert!(store.bundle.is_none());
    }

    #[test]
    fn test_policy_store_set_dsl() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"photo.jpg"
);
"#;
        let result = store.set_dsl(dsl, None, None);
        assert!(result.is_ok());
        assert_eq!(store.policies.entries, 1);
        assert_eq!(store.policies.content, dsl);
    }

    #[test]
    fn test_policy_store_set_dsl_invalid() {
        let mut store = PolicyStore::new().unwrap();
        let invalid_dsl = "this is not valid Cedar DSL";
        let result = store.set_dsl(invalid_dsl, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_store_set_labels() {
        let mut store = PolicyStore::new().unwrap();
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "example",
                "regex": "example\\.com$"
            }
        ]
    }
]"#;
        let result = store.set_labels(labels_json, None, None);
        assert!(result.is_ok());
        assert_eq!(store.labels.entries, 1);
    }

    #[test]
    fn test_policy_store_preserves_source() {
        let mut store = PolicyStore::new().unwrap();
        let endpoint = Endpoint::from_str("https://example.com/policies").unwrap();

        // Set initial DSL with source
        let dsl1 = "permit (principal, action, resource);";
        store
            .set_dsl(dsl1, Some(endpoint.clone()), Some(60))
            .unwrap();

        assert_eq!(
            store.policies.source.as_ref().unwrap().as_str(),
            "https://example.com/policies"
        );
        assert_eq!(store.policies.refresh_frequency, Some(60));

        // Update DSL without providing source - should preserve it
        let dsl2 = "forbid (principal, action, resource);";
        store.set_dsl(dsl2, None, None).unwrap();

        assert_eq!(
            store.policies.source.as_ref().unwrap().as_str(),
            "https://example.com/policies"
        );
        assert_eq!(store.policies.refresh_frequency, Some(60));
    }

    #[test]
    fn test_metadata_display() {
        let dsl = "permit (principal, action, resource);";
        let endpoint = Endpoint::from_str("https://example.com/api").unwrap();
        let metadata =
            Metadata::<OfPolicies>::new(dsl.to_string(), Some(endpoint), Some(120)).unwrap();

        let display = format!("{}", metadata);
        assert!(display.contains("https://example.com/api"));
        assert!(display.contains("120"));
        assert!(display.contains(&metadata.sha256));
    }

    #[test]
    fn test_list_policies_raw_matches_engine() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();

        let expected = store
            .engine
            .list_policies_for_user("alice", &[], &[])
            .unwrap();
        let expected_raw = format_policies_raw(&expected);
        let raw = store
            .list_policies_raw("alice".to_string(), vec![], vec![])
            .unwrap();

        assert_eq!(*raw, expected_raw);
    }

    #[test]
    fn test_list_policies_json_matches_engine() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();

        let expected = store
            .engine
            .list_policies_for_user("alice", &[], &[])
            .unwrap();
        let expected_json = UserPolicies::try_from(expected).unwrap();
        let response = store
            .list_policies_json("alice".to_string(), vec![], vec![])
            .unwrap();

        let expected_value = serde_json::to_value(expected_json).unwrap_or(Value::Null);
        let response_value = serde_json::to_value(response.as_ref()).unwrap_or(Value::Null);
        assert_eq!(response_value, expected_value);
    }

    #[test]
    fn test_list_policies_cache_cleared_on_set_dsl() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();
        let _ = store
            .list_policies_raw("alice".to_string(), vec![], vec![])
            .unwrap();
        let _ = store
            .list_policies_json("alice".to_string(), vec![], vec![])
            .unwrap();

        assert_eq!(store.list_policies_raw_cache.lock().unwrap().len(), 1);
        assert_eq!(store.list_policies_json_cache.lock().unwrap().len(), 1);

        let updated = r#"
permit (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(updated, None, None).unwrap();

        assert!(store.list_policies_raw_cache.lock().unwrap().is_empty());
        assert!(store.list_policies_json_cache.lock().unwrap().is_empty());
    }

    #[test]
    fn test_list_policies_cache_normalizes_groups_and_namespaces() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();

        let _ = store
            .list_policies_raw(
                "alice".to_string(),
                vec!["admins".to_string(), "users".to_string()],
                vec!["Team".to_string(), "Org".to_string()],
            )
            .unwrap();

        let _ = store
            .list_policies_raw(
                "alice".to_string(),
                vec![
                    "users".to_string(),
                    "admins".to_string(),
                    "admins".to_string(),
                ],
                vec!["Org".to_string(), "Org".to_string(), "Team".to_string()],
            )
            .unwrap();

        assert_eq!(store.list_policies_raw_cache.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_policy_store_schema_backed_runtime_state() {
        let mut store = PolicyStore::new().unwrap();
        store.set_schema(CONTEXT_SCHEMA_JSON, None, None).unwrap();
        store.set_dsl(CONTEXT_POLICY_DSL, None, None).unwrap();

        assert_eq!(
            store.request_context_status,
            RequestContextStatus::schema_backed()
        );
    }

    #[test]
    fn test_policy_store_permissive_schema_mismatch_falls_back() {
        let mut store = PolicyStore::new().unwrap();
        store.set_dsl(INCOMPATIBLE_POLICY_DSL, None, None).unwrap();
        store.set_schema(CONTEXT_SCHEMA_JSON, None, None).unwrap();

        assert_eq!(
            store.request_context_status,
            RequestContextStatus::schema_incompatible()
        );
    }

    #[test]
    fn test_policy_store_set_labels_preserves_schema_backed_runtime() {
        let mut store = PolicyStore::new().unwrap();
        store.set_schema(CONTEXT_SCHEMA_JSON, None, None).unwrap();
        store.set_dsl(CONTEXT_POLICY_DSL, None, None).unwrap();
        store.set_labels(LABELS_JSON, None, None).unwrap();

        assert_eq!(
            store.request_context_status,
            RequestContextStatus::schema_backed()
        );
    }

    #[test]
    fn test_policy_store_rejects_labels_incompatible_with_schema() {
        let mut store = PolicyStore::new().unwrap();
        store.set_schema(CONTEXT_SCHEMA_JSON, None, None).unwrap();
        let incompatible = LABELS_JSON.replace("nameLabels", "missingLabels");

        let error = store.set_labels(&incompatible, None, None).unwrap_err();

        assert!(error.to_string().contains("missingLabels is not declared"));
        assert!(store.labels.content.is_empty());
    }
}
