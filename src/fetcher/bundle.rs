use futures_util::StreamExt;
use reqwest::{Client, StatusCode, header};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, error, info};
use treetop_bundle::{ArchiveLimits, BundleArchive, BundleError, SignaturePolicy, TrustStore};

use crate::config::BundleEngineMode;
use crate::errors::ServiceError;
use crate::metrics::{self, BundleFailureReason};
use crate::models::Endpoint;
use crate::state::{PolicyStore, RemoteSourceKind};

/// Conditional, bounded fetcher for complete policy bundles.
pub struct BundleFetcher {
    client: Client,
    store: Arc<RwLock<PolicyStore>>,
    url: Endpoint,
    refresh_secs: u32,
    limits: ArchiveLimits,
    signature_policy: SignaturePolicy,
    trust_store: Arc<TrustStore>,
    engine_mode: BundleEngineMode,
    etag: Option<String>,
    last_modified: Option<String>,
    archive_sha256: Option<String>,
}

impl BundleFetcher {
    pub fn new(
        store: Arc<RwLock<PolicyStore>>,
        url: Endpoint,
        refresh_secs: u32,
        limits: ArchiveLimits,
        signature_policy: SignaturePolicy,
        trust_store: Arc<TrustStore>,
    ) -> Result<Self, ServiceError> {
        Self::new_with_engine_mode(
            store,
            url,
            refresh_secs,
            limits,
            signature_policy,
            trust_store,
            BundleEngineMode::Monolithic,
        )
    }

    pub fn new_with_engine_mode(
        store: Arc<RwLock<PolicyStore>>,
        url: Endpoint,
        refresh_secs: u32,
        limits: ArchiveLimits,
        signature_policy: SignaturePolicy,
        trust_store: Arc<TrustStore>,
        engine_mode: BundleEngineMode,
    ) -> Result<Self, ServiceError> {
        if refresh_secs == 0 {
            return Err(ServiceError::ValidationError(
                "bundle refresh frequency must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            client: Client::new(),
            store,
            url,
            refresh_secs,
            limits,
            signature_policy,
            trust_store,
            engine_mode,
            etag: None,
            last_modified: None,
            archive_sha256: None,
        })
    }

    pub fn spawn(mut self) {
        {
            let mut store = self.store.write().expect("policy store lock poisoned");
            store.configure_remote_source(
                RemoteSourceKind::Bundle,
                self.url.clone(),
                self.refresh_secs,
            );
        }
        tokio::spawn(async move {
            loop {
                if let Err(error) = self.check_and_update().await {
                    error!(
                        message = "bundle fetch loop error",
                        url = self.url.as_str(),
                        error = %error
                    );
                }
                tokio::time::sleep(Duration::from_secs(u64::from(self.refresh_secs))).await;
            }
        });
    }

    pub(crate) async fn check_and_update(&mut self) -> Result<(), Box<dyn Error>> {
        let mut request = self.client.get(self.url.as_str());
        if let Some(etag) = &self.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &self.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, last_modified);
        }
        let response = request.send().await.inspect_err(|_| {
            metrics::record_bundle_failure(BundleFailureReason::Fetch);
        })?;
        if response.status() == StatusCode::NOT_MODIFIED {
            debug!(message = "bundle not modified", url = self.url.as_str());
            return Ok(());
        }
        if !response.status().is_success() {
            metrics::record_bundle_failure(BundleFailureReason::Fetch);
            return Err(io::Error::other(format!(
                "GET {} returned HTTP {}",
                self.url.as_str(),
                response.status()
            ))
            .into());
        }
        let content_length = response.content_length();
        if content_length.is_some_and(|length| length > self.limits.max_compressed_bytes() as u64) {
            metrics::record_bundle_failure(BundleFailureReason::SizeLimit);
            return Err(BundleError::SizeLimit {
                kind: "compressed",
                limit: self.limits.max_compressed_bytes(),
            }
            .into());
        }

        let response_etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let response_last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::with_capacity(content_length.unwrap_or_default() as usize);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.inspect_err(|_| {
                metrics::record_bundle_failure(BundleFailureReason::Fetch);
            })?;
            if bytes.len().saturating_add(chunk.len()) > self.limits.max_compressed_bytes() {
                metrics::record_bundle_failure(BundleFailureReason::SizeLimit);
                return Err(BundleError::SizeLimit {
                    kind: "compressed",
                    limit: self.limits.max_compressed_bytes(),
                }
                .into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let archive_sha256 = hex_sha256(&bytes);
        if self.archive_sha256.as_deref() == Some(&archive_sha256) {
            // Adopt rotated validators even when the representation is unchanged;
            // otherwise every refresh could redownload the same archive.
            self.etag = response_etag;
            self.last_modified = response_last_modified;
            debug!(message = "bundle body unchanged", url = self.url.as_str());
            return Ok(());
        }

        let signature_policy = self.signature_policy;
        let trust_store = self.trust_store.clone();
        let limits = self.limits;
        let source = self.url.clone();
        let refresh_frequency = self.refresh_secs;
        let schema_validation_mode = {
            let store = self.store.read().map_err(|error| {
                metrics::record_bundle_failure(BundleFailureReason::Store);
                format!("policy store lock poisoned: {error}")
            })?;
            store.schema_validation_mode
        };
        let engine_mode = self.engine_mode;
        let (prepared, bundle_id, signing_key_id) = tokio::task::spawn_blocking(move || {
            let archive = BundleArchive::from_bytes(bytes);
            let validated = archive
                .validate(signature_policy, &trust_store, limits)
                .inspect_err(|error| {
                    metrics::record_bundle_failure(reason_for_bundle_error(error));
                })?;
            let bundle_id = validated.bundle_id().to_owned();
            let signing_key_id = validated
                .verified_signature()
                .key_id()
                .map(ToOwned::to_owned);
            let prepared = PolicyStore::prepare_bundle_with_engine_mode(
                &validated,
                Some(source),
                Some(refresh_frequency),
                schema_validation_mode,
                engine_mode,
            )
            .inspect_err(|_| {
                metrics::record_bundle_failure(BundleFailureReason::Validation);
            })?;
            Ok::<_, ServiceError>((prepared, bundle_id, signing_key_id))
        })
        .await
        .map_err(|error| io::Error::other(format!("bundle preparation task failed: {error}")))??;
        {
            let mut store = self.store.write().map_err(|error| {
                metrics::record_bundle_failure(BundleFailureReason::Store);
                format!("policy store lock poisoned: {error}")
            })?;
            store.apply_prepared_bundle(prepared).inspect_err(|error| {
                let reason = if matches!(error, ServiceError::SchemaValidationError(_)) {
                    BundleFailureReason::Validation
                } else {
                    BundleFailureReason::Store
                };
                metrics::record_bundle_failure(reason);
            })?;
            store.mark_remote_source_loaded(RemoteSourceKind::Bundle);
        }
        self.etag = response_etag;
        self.last_modified = response_last_modified;
        self.archive_sha256 = Some(archive_sha256);
        metrics::record_bundle_reload();
        info!(
            message = "verified bundle applied",
            bundle_id,
            engine_mode = %self.engine_mode,
            key_id = signing_key_id.as_deref()
        );
        Ok(())
    }
}

pub(crate) fn reason_for_bundle_error(error: &BundleError) -> BundleFailureReason {
    match error {
        BundleError::SizeLimit { .. } => BundleFailureReason::SizeLimit,
        BundleError::Archive(message) if message == "signature_missing" => {
            BundleFailureReason::SignatureMissing
        }
        BundleError::Archive(message) if message == "untrusted_key" => {
            BundleFailureReason::UntrustedKey
        }
        BundleError::Archive(message) if message == "invalid_signature" => {
            BundleFailureReason::InvalidSignature
        }
        BundleError::Archive(_) => BundleFailureReason::Archive,
        BundleError::Validation(_) => BundleFailureReason::Validation,
        _ => BundleFailureReason::Archive,
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{RemoteSourceKind, SharedPolicyStore};
    use actix_web::{App, HttpRequest, HttpResponse, HttpServer, dev::ServerHandle, web};
    use std::fs;
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::Mutex;
    use treetop_bundle::BundleBuilder;

    struct ResponseState {
        body: Vec<u8>,
        etag: String,
    }

    fn bundle_bytes() -> Vec<u8> {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        write(
            root.join("policy.cedar"),
            r#"
@id("dns.read")
permit(principal, action == ExampleCo::DNS::Action::"read", resource);
"#,
        );
        write(
            root.join("treetop-module.toml"),
            r#"
format_version = 2
name = "dns"
namespace = "ExampleCo::DNS"
policies = ["policy.cedar"]
"#,
        );
        let manifest = root.join("treetop-bundle.toml");
        write(
            &manifest,
            r#"
format_version = 2
name = "fetch-test"

[[modules]]
manifest = "treetop-module.toml"
role = "ordinary"
"#,
        );
        BundleBuilder::from_manifest(manifest)
            .unwrap()
            .build(None)
            .unwrap()
            .into_bytes()
    }

    fn spawn_bundle_server(
        state: Arc<RwLock<ResponseState>>,
        request_etags: Arc<Mutex<Vec<Option<String>>>>,
    ) -> (Endpoint, ServerHandle) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = HttpServer::new(move || {
            let state = state.clone();
            let request_etags = request_etags.clone();
            App::new().default_service(web::to(move |request: HttpRequest| {
                let state = state.clone();
                let request_etags = request_etags.clone();
                async move {
                    let request_etag = request
                        .headers()
                        .get(header::IF_NONE_MATCH.as_str())
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string);
                    request_etags.lock().unwrap().push(request_etag.clone());
                    let state = state.read().unwrap();
                    if request_etag.as_deref() == Some(state.etag.as_str()) {
                        HttpResponse::NotModified().finish()
                    } else {
                        HttpResponse::Ok()
                            .insert_header((header::ETAG.as_str(), state.etag.clone()))
                            .content_type("application/gzip")
                            .body(state.body.clone())
                    }
                }
            }))
        })
        .listen(listener)
        .unwrap()
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        (
            format!("http://{address}/bundle.tar.gz").parse().unwrap(),
            handle,
        )
    }

    fn fetcher(store: SharedPolicyStore, url: Endpoint, limits: ArchiveLimits) -> BundleFetcher {
        store
            .write()
            .unwrap()
            .configure_remote_source(RemoteSourceKind::Bundle, url.clone(), 60);
        BundleFetcher::new(
            store,
            url,
            60,
            limits,
            SignaturePolicy::AllowUnsigned,
            Arc::new(TrustStore::new()),
        )
        .unwrap()
    }

    #[test]
    fn rejects_zero_refresh_frequency() {
        let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
        let url = "https://example.com/bundle.tar.gz".parse().unwrap();

        let error = BundleFetcher::new(
            store,
            url,
            0,
            ArchiveLimits::default(),
            SignaturePolicy::AllowUnsigned,
            Arc::new(TrustStore::new()),
        )
        .err()
        .unwrap();

        assert!(error.to_string().contains("greater than zero"));
    }

    #[actix_web::test]
    async fn successful_fetch_applies_bundle_and_uses_conditional_get() {
        let state = Arc::new(RwLock::new(ResponseState {
            body: bundle_bytes(),
            etag: "\"bundle-v1\"".to_string(),
        }));
        let request_etags = Arc::new(Mutex::new(Vec::new()));
        let (url, server) = spawn_bundle_server(state.clone(), request_etags.clone());
        let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
        let mut fetcher = fetcher(store.clone(), url, ArchiveLimits::default());

        fetcher.check_and_update().await.unwrap();
        state.write().unwrap().etag = "\"bundle-v1-rotated\"".to_string();
        fetcher.check_and_update().await.unwrap();
        fetcher.check_and_update().await.unwrap();

        {
            let store = store.read().unwrap();
            assert_eq!(store.bundle.as_ref().unwrap().bundle_id.len(), 64);
            assert!(store.configured_sources_loaded());
        }
        assert_eq!(
            request_etags.lock().unwrap().as_slice(),
            &[
                None,
                Some("\"bundle-v1\"".to_string()),
                Some("\"bundle-v1-rotated\"".to_string())
            ]
        );
        server.stop(false).await;
    }

    #[actix_web::test]
    async fn failed_refresh_preserves_last_known_good_bundle_and_readiness() {
        let state = Arc::new(RwLock::new(ResponseState {
            body: bundle_bytes(),
            etag: "\"bundle-v1\"".to_string(),
        }));
        let (url, server) = spawn_bundle_server(state.clone(), Arc::new(Mutex::new(Vec::new())));
        let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
        let mut fetcher = fetcher(store.clone(), url, ArchiveLimits::default());
        fetcher.check_and_update().await.unwrap();
        let original_id = store
            .read()
            .unwrap()
            .bundle
            .as_ref()
            .unwrap()
            .bundle_id
            .clone();
        {
            let mut state = state.write().unwrap();
            state.body = b"not a bundle".to_vec();
            state.etag = "\"bundle-v2\"".to_string();
        }

        assert!(fetcher.check_and_update().await.is_err());

        {
            let store = store.read().unwrap();
            assert_eq!(store.bundle.as_ref().unwrap().bundle_id, original_id);
            assert!(store.configured_sources_loaded());
        }
        server.stop(false).await;
    }

    #[actix_web::test]
    async fn strict_mode_rejects_schema_free_remote_bundle() {
        let state = Arc::new(RwLock::new(ResponseState {
            body: bundle_bytes(),
            etag: "\"schema-free\"".to_string(),
        }));
        let (url, server) = spawn_bundle_server(state, Arc::new(Mutex::new(Vec::new())));
        let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
        store
            .write()
            .unwrap()
            .set_schema_validation_mode(crate::config::SchemaValidationMode::Strict);
        let mut fetcher = fetcher(store.clone(), url, ArchiveLimits::default());

        let error = fetcher.check_and_update().await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("every bundle to include a schema")
        );
        {
            let store = store.read().unwrap();
            assert!(store.bundle.is_none());
            assert!(!store.configured_sources_loaded());
        }
        server.stop(false).await;
    }

    #[actix_web::test]
    async fn declared_compressed_size_limit_prevents_initial_readiness() {
        let state = Arc::new(RwLock::new(ResponseState {
            body: vec![0; 32],
            etag: "\"oversized\"".to_string(),
        }));
        let (url, server) = spawn_bundle_server(state, Arc::new(Mutex::new(Vec::new())));
        let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
        let mut fetcher = fetcher(store.clone(), url, ArchiveLimits::new(16, 1024).unwrap());

        assert!(fetcher.check_and_update().await.is_err());

        {
            let store = store.read().unwrap();
            assert!(store.bundle.is_none());
            assert!(!store.configured_sources_loaded());
        }
        server.stop(false).await;
    }

    fn write(path: impl AsRef<Path>, contents: &str) {
        fs::write(path, contents).unwrap();
    }
}
