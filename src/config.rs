use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use subtle::{Choice, ConstantTimeEq};
use treetop_bundle::{SignaturePolicy, TrustStore, TrustedKey};

use crate::errors::ServiceError;

use crate::models::Endpoint;

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchemaValidationMode {
    #[default]
    Permissive,
    Strict,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BundleSignaturePolicy {
    #[default]
    AllowUnsigned,
    Required,
}

/// How validated bundles are compiled into the policy engine.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BundleEngineMode {
    /// Compile every module into one Cedar policy set.
    #[default]
    Monolithic,
    /// Compile each ordinary module as an independent namespace store.
    BundleModules,
}

impl fmt::Display for BundleEngineMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Monolithic => write!(f, "monolithic"),
            Self::BundleModules => write!(f, "bundle-modules"),
        }
    }
}

impl From<BundleSignaturePolicy> for SignaturePolicy {
    fn from(value: BundleSignaturePolicy) -> Self {
        match value {
            BundleSignaturePolicy::AllowUnsigned => Self::AllowUnsigned,
            BundleSignaturePolicy::Required => Self::Required,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BundleRuntimeConfig {
    pub signature_policy: SignaturePolicy,
    pub trust_store: Arc<TrustStore>,
    pub max_request_bytes: usize,
    pub max_compressed_bytes: usize,
    pub max_uncompressed_bytes: usize,
}

impl std::fmt::Display for SchemaValidationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaValidationMode::Permissive => write!(f, "permissive"),
            SchemaValidationMode::Strict => write!(f, "strict"),
        }
    }
}

/// Application configuration (host and port).
#[derive(Parser, Debug, Clone)]
pub struct Config {
    /// IP address to bind to
    #[clap(long, default_value = "127.0.0.1", env = "TREETOP_LISTEN")]
    pub host: String,

    /// Port to listen on
    #[clap(long, default_value = "9999", env = "TREETOP_PORT")]
    pub port: u16,

    /// Number of Actix worker threads (default: auto based on available CPU)
    #[clap(long, env = "TREETOP_WORKERS")]
    pub workers: Option<usize>,

    /// Number of Rayon worker threads used for batch evaluation (default: auto based on available CPU)
    #[clap(long, env = "TREETOP_RAYON_THREADS")]
    pub rayon_threads: Option<usize>,

    /// Batch parallel threshold: minimum number of authorization queries in a batch to enable parallel processing.
    /// On single-core systems, parallelism is disabled regardless of this setting.
    #[clap(long, env = "TREETOP_PAR_THRESHOLD", default_value = "8")]
    pub par_threshold: Option<usize>,

    /// Allow upload of policy (otherwise only support of fetching from a URL)
    #[clap(long, default_value = "false", env = "TREETOP_ALLOW_UPLOAD")]
    pub allow_upload: bool,

    /// URL to fetch policies from
    #[clap(long, default_value = None, env = "TREETOP_POLICY_URL")]
    pub policy_url: Option<Endpoint>,

    /// Update frequency in seconds for fetching TREETOP_POLICY_URL (default is 60 seconds)
    #[clap(long, default_value = None, env = "TREETOP_POLICY_UPDATE_FREQUENCY")]
    pub update_frequency: Option<u32>,

    /// Optional URL to fetch host labels from
    #[clap(long, default_value = None, env = "TREETOP_LABELS_URL")]
    pub labels_url: Option<Endpoint>,

    /// Update frequency in seconds for fetching host labels (default is 60 seconds)
    #[clap(long, default_value = None, env = "TREETOP_LABELS_UPDATE_FREQUENCY")]
    pub labels_refresh: Option<u32>,

    /// Optional URL to fetch Cedar schema from
    #[clap(long, default_value = None, env = "TREETOP_SCHEMA_URL")]
    pub schema_url: Option<Endpoint>,

    /// Update frequency in seconds for fetching Cedar schema (default is 60 seconds)
    #[clap(long, default_value = None, env = "TREETOP_SCHEMA_UPDATE_FREQUENCY")]
    pub schema_refresh: Option<u32>,

    /// Schema validation mode for policy/schema reloads.
    #[clap(
        long,
        env = "TREETOP_SCHEMA_VALIDATION_MODE",
        value_enum,
        default_value = "permissive"
    )]
    pub schema_validation_mode: SchemaValidationMode,

    /// URL to fetch a complete Treetop policy bundle from.
    #[clap(
        long,
        env = "TREETOP_BUNDLE_URL",
        conflicts_with_all = ["policy_url", "labels_url", "schema_url"]
    )]
    pub bundle_url: Option<Endpoint>,

    /// Bundle refresh frequency in seconds.
    #[clap(long, env = "TREETOP_BUNDLE_UPDATE_FREQUENCY", default_value = "60")]
    pub bundle_refresh: u32,

    /// Policy-engine layout used when loading validated bundles.
    #[clap(
        long,
        env = "TREETOP_BUNDLE_ENGINE_MODE",
        value_enum,
        default_value = "monolithic"
    )]
    pub bundle_engine_mode: BundleEngineMode,

    /// Maximum compressed bundle size in bytes.
    #[clap(
        long,
        env = "TREETOP_MAX_BUNDLE_COMPRESSED_BYTES",
        default_value = "10485760"
    )]
    pub max_bundle_compressed_bytes: usize,

    /// Maximum uncompressed bundle size in bytes.
    #[clap(
        long,
        env = "TREETOP_MAX_BUNDLE_UNCOMPRESSED_BYTES",
        default_value = "52428800"
    )]
    pub max_bundle_uncompressed_bytes: usize,

    /// Trusted Ed25519 SPKI public key. Repeat the flag or use a comma-separated environment value.
    #[clap(
        long = "bundle-trusted-key",
        env = "TREETOP_BUNDLE_TRUSTED_KEYS",
        value_delimiter = ','
    )]
    pub bundle_trusted_keys: Vec<PathBuf>,

    /// Whether a bundle signature is optional or required.
    #[clap(
        long,
        env = "TREETOP_BUNDLE_SIGNATURE_POLICY",
        value_enum,
        default_value = "allow-unsigned"
    )]
    pub bundle_signature_policy: BundleSignaturePolicy,

    /// Maximum JSON size of per-request context payload in bytes.
    #[clap(long, env = "TREETOP_MAX_CONTEXT_BYTES", default_value = "16384")]
    pub max_context_bytes: usize,

    /// Maximum nesting depth allowed in per-request context payload.
    #[clap(long, env = "TREETOP_MAX_CONTEXT_DEPTH", default_value = "8")]
    pub max_context_depth: usize,

    /// Maximum number of top-level keys allowed in per-request context payload.
    #[clap(long, env = "TREETOP_MAX_CONTEXT_KEYS", default_value = "64")]
    pub max_context_keys: usize,

    /// Maximum number of authorization checks accepted in one batch.
    #[clap(long, env = "TREETOP_MAX_BATCH_SIZE", default_value = "1024")]
    pub max_batch_size: usize,

    /// Maximum request body size in bytes (default: 10485760 = 10 MB)
    #[clap(long, default_value = "10485760", env = "TREETOP_MAX_REQUEST_SIZE")]
    pub max_request_size: usize,

    #[clap(long)]
    /// Print version information and exit
    pub version: bool,
}

impl Config {
    pub fn bundle_runtime_config(&self) -> Result<BundleRuntimeConfig, ServiceError> {
        if self.bundle_url.is_some()
            && (self.policy_url.is_some() || self.labels_url.is_some() || self.schema_url.is_some())
        {
            return Err(ServiceError::ValidationError(
                "TREETOP_BUNDLE_URL is mutually exclusive with policy, labels, and schema URLs"
                    .to_string(),
            ));
        }
        if self.max_bundle_compressed_bytes == 0 || self.max_bundle_uncompressed_bytes == 0 {
            return Err(ServiceError::ValidationError(
                "bundle size limits must be greater than zero".to_string(),
            ));
        }
        if self.bundle_url.is_some() && self.bundle_refresh == 0 {
            return Err(ServiceError::ValidationError(
                "bundle refresh frequency must be greater than zero".to_string(),
            ));
        }
        let keys = self
            .bundle_trusted_keys
            .iter()
            .map(TrustedKey::from_spki_pem_file)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServiceError::ValidationError(error.to_string()))?;
        let trust_store = TrustStore::from_keys(keys)
            .map_err(|error| ServiceError::ValidationError(error.to_string()))?;
        if self.bundle_signature_policy == BundleSignaturePolicy::Required && trust_store.is_empty()
        {
            return Err(ServiceError::ValidationError(
                "required bundle signatures need at least one trusted key".to_string(),
            ));
        }
        Ok(BundleRuntimeConfig {
            signature_policy: self.bundle_signature_policy.into(),
            trust_store: Arc::new(trust_store),
            max_request_bytes: self.max_request_size,
            max_compressed_bytes: self.max_bundle_compressed_bytes,
            max_uncompressed_bytes: self.max_bundle_uncompressed_bytes,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClientAllowlist {
    #[default]
    Any,
    Nets(Arc<[IpNet]>),
}

impl ClientAllowlist {
    /// Parse the environment value. Unset, blank, and `*` all mean open access.
    pub fn parse_env(input: Option<&str>) -> Result<Self, ServiceError> {
        let Some(input) = input else {
            return Ok(Self::Any);
        };
        let trimmed = input.trim();

        if trimmed.is_empty() || trimmed == "*" {
            return Ok(Self::Any);
        }

        let mut nets = Vec::with_capacity(trimmed.bytes().filter(|byte| *byte == b',').count() + 1);
        for entry in trimmed.split(',').map(str::trim) {
            if entry.is_empty() {
                return Err(ServiceError::ValidationError(
                    "TREETOP_CLIENT_ALLOWLIST contains an empty entry".into(),
                ));
            }
            if entry == "*" {
                return Err(ServiceError::ValidationError(
                    "TREETOP_CLIENT_ALLOWLIST cannot mix '*' with addresses or networks".into(),
                ));
            }
            nets.push(Self::parse_net(entry)?);
        }

        Ok(Self::Nets(nets.into()))
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        match self {
            ClientAllowlist::Any => true,
            ClientAllowlist::Nets(nets) => nets.iter().any(|net| match (net, ip) {
                (IpNet::V4(net), IpAddr::V4(addr)) => net.contains(&addr),
                (IpNet::V6(net), IpAddr::V6(addr)) => net.contains(&addr),
                _ => false,
            }),
        }
    }

    fn parse_net(raw: &str) -> Result<IpNet, ServiceError> {
        IpNet::from_str(raw)
            .or_else(|_| Self::ip_to_host_net(raw))
            .map_err(|_| ServiceError::InvalidIp)
    }

    fn ip_to_host_net(raw: &str) -> Result<IpNet, ()> {
        let ip: IpAddr = raw.parse().map_err(|_| ())?;
        match ip {
            IpAddr::V4(addr) => Ipv4Net::new(addr, 32).map(IpNet::from).map_err(|_| ()),
            IpAddr::V6(addr) => Ipv6Net::new(addr, 128).map(IpNet::from).map_err(|_| ()),
        }
    }
}

impl FromStr for ClientAllowlist {
    type Err = ServiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_env(Some(s))
    }
}

#[derive(Clone, Default)]
pub struct AccessTokens {
    digests: Arc<[[u8; 32]]>,
}

impl fmt::Debug for AccessTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokens")
            .field("count", &self.digests.len())
            .finish()
    }
}

impl AccessTokens {
    fn parse_env(input: Option<&str>) -> Result<Self, ServiceError> {
        let Some(input) = input else {
            return Ok(Self::default());
        };
        if input.trim().is_empty() {
            return Ok(Self::default());
        }

        let entries: Vec<_> = input.split(',').map(str::trim).collect();
        if entries.iter().any(|entry| entry.is_empty()) {
            return Err(ServiceError::ValidationError(
                "TREETOP_ACCESS_TOKENS contains an empty entry".into(),
            ));
        }
        if entries.iter().any(|token| !valid_bearer_token(token)) {
            return Err(ServiceError::ValidationError(
                "TREETOP_ACCESS_TOKENS contains an invalid Bearer token".into(),
            ));
        }

        let unique = entries
            .into_iter()
            .map(hash_token)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(Self {
            digests: unique.into(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn matches(&self, token: &str) -> bool {
        // Configured tokens and Authorization header values are validated at their
        // respective boundaries. Hash only once on the request hot path.
        let candidate = hash_token(token);
        let mut matched = Choice::from(0);
        for configured in self.digests.iter() {
            matched |= configured.ct_eq(&candidate);
        }
        bool::from(matched)
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn valid_bearer_token(token: &str) -> bool {
    let mut body_bytes = 0;
    let mut padding_started = false;
    for byte in token.bytes() {
        if byte == b'=' {
            padding_started = true;
        } else if padding_started
            || !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
        {
            return false;
        } else {
            body_bytes += 1;
        }
    }
    body_bytes > 0
}

#[derive(Clone, Default)]
pub struct AdmissionConfig {
    pub client_allowlist: ClientAllowlist,
    pub trusted_proxies: Arc<[IpNet]>,
    pub access_tokens: AccessTokens,
}

impl fmt::Debug for AdmissionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionConfig")
            .field("client_allowlist", &self.client_allowlist)
            .field("trusted_proxy_count", &self.trusted_proxies.len())
            .field("access_token_count", &self.access_tokens.len())
            .finish()
    }
}

impl AdmissionConfig {
    pub fn from_env() -> Result<Self, ServiceError> {
        let client_allowlist = env_value("TREETOP_CLIENT_ALLOWLIST")?;
        let access_tokens = env_value("TREETOP_ACCESS_TOKENS")?;
        let trusted_proxies = env_value("TREETOP_TRUSTED_PROXIES")?;
        Self::parse(
            client_allowlist.as_deref(),
            access_tokens.as_deref(),
            trusted_proxies.as_deref(),
        )
    }

    pub fn parse(
        client_allowlist: Option<&str>,
        access_tokens: Option<&str>,
        trusted_proxies: Option<&str>,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            client_allowlist: ClientAllowlist::parse_env(client_allowlist)?,
            trusted_proxies: parse_network_list(trusted_proxies, "TREETOP_TRUSTED_PROXIES")?.into(),
            access_tokens: AccessTokens::parse_env(access_tokens)?,
        })
    }

    pub fn enabled(&self) -> bool {
        self.has_acl() || !self.access_tokens.is_empty()
    }

    pub fn has_acl(&self) -> bool {
        matches!(self.client_allowlist, ClientAllowlist::Nets(_))
    }
}

fn env_value(name: &'static str) -> Result<Option<String>, ServiceError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ServiceError::ValidationError(format!(
            "{name} is not valid Unicode"
        ))),
    }
}

fn parse_network_list(
    input: Option<&str>,
    variable: &'static str,
) -> Result<Vec<IpNet>, ServiceError> {
    let Some(input) = input else {
        return Ok(Vec::new());
    };
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }

    input
        .split(',')
        .map(str::trim)
        .map(|entry| {
            if entry.is_empty() {
                return Err(ServiceError::ValidationError(format!(
                    "{variable} contains an empty entry"
                )));
            }
            if entry == "*" {
                return Err(ServiceError::ValidationError(format!(
                    "{variable} does not accept a wildcard"
                )));
            }
            ClientAllowlist::parse_net(entry).map_err(|_| {
                ServiceError::ValidationError(format!(
                    "{variable} contains an invalid address or network"
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn parses_any() {
        let allowlist = ClientAllowlist::from_str("*").unwrap();
        assert!(allowlist.allows(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn parses_default_hosts() {
        let allowlist = ClientAllowlist::from_str("127.0.0.1,::1").unwrap();
        assert!(allowlist.allows(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(allowlist.allows(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_outside_network() {
        let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
        assert!(!allowlist.allows(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn errors_on_empty() {
        assert!(matches!(
            ClientAllowlist::from_str(""),
            Ok(ClientAllowlist::Any)
        ));
        assert!(matches!(
            ClientAllowlist::from_str(",,,"),
            Err(ServiceError::ValidationError(_))
        ));
    }

    #[test]
    fn errors_on_invalid_ip() {
        assert!(matches!(
            ClientAllowlist::from_str("not-an-ip"),
            Err(ServiceError::InvalidIp)
        ));
    }

    #[test]
    fn rejects_mixed_wildcard_and_empty_allowlist_entries() {
        for value in ["*,127.0.0.1", "127.0.0.1,", ",127.0.0.1"] {
            assert!(ClientAllowlist::from_str(value).is_err(), "{value}");
        }
    }

    #[test]
    fn parses_all_admission_modes() {
        let open = AdmissionConfig::parse(None, None, None).unwrap();
        assert!(!open.enabled());

        let acl = AdmissionConfig::parse(Some("10.0.0.0/8"), None, None).unwrap();
        assert!(acl.has_acl());
        assert!(acl.access_tokens.is_empty());

        let token = AdmissionConfig::parse(None, Some("one"), None).unwrap();
        assert!(!token.has_acl());
        assert!(token.access_tokens.matches("one"));

        let both =
            AdmissionConfig::parse(Some("2001:db8::/32"), Some("one,two"), Some("::1")).unwrap();
        assert!(both.has_acl());
        assert_eq!(both.access_tokens.len(), 2);
        assert_eq!(both.trusted_proxies.len(), 1);
    }

    #[test]
    fn access_tokens_are_validated_deduplicated_and_redacted() {
        let config = AdmissionConfig::parse(None, Some("abc-._~+/,abc-._~+/"), None).unwrap();
        assert_eq!(config.access_tokens.len(), 1);
        assert!(config.access_tokens.matches("abc-._~+/"));
        assert!(!config.access_tokens.matches("different"));
        assert!(!format!("{config:?}").contains("abc-._~+/"));
        assert!(AdmissionConfig::parse(None, Some("padded=="), None).is_ok());

        for value in [
            "first,",
            ",first",
            "has space",
            "has:colon",
            "=padding",
            "padding=inside",
        ] {
            assert!(
                AdmissionConfig::parse(None, Some(value), None).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_invalid_trusted_proxy_lists_without_echoing_values() {
        for value in ["*", "10.0.0.0/8,", "not-a-network"] {
            let error = AdmissionConfig::parse(None, None, Some(value)).unwrap_err();
            assert!(!error.to_string().contains(value));
        }
    }

    #[test]
    fn rejects_zero_bundle_refresh_when_remote_bundle_mode_is_enabled() {
        let config = Config::try_parse_from([
            "treetop-server",
            "--bundle-url",
            "https://example.com/bundle.tar.gz",
            "--bundle-refresh",
            "0",
        ])
        .unwrap();

        let error = config.bundle_runtime_config().unwrap_err();
        assert!(error.to_string().contains("greater than zero"));
    }

    #[test]
    fn bundle_engine_mode_is_an_explicit_opt_in() {
        let default = Config::try_parse_from(["treetop-server"]).unwrap();
        assert_eq!(default.bundle_engine_mode, BundleEngineMode::Monolithic);

        let configured =
            Config::try_parse_from(["treetop-server", "--bundle-engine-mode", "bundle-modules"])
                .unwrap();
        assert_eq!(
            configured.bundle_engine_mode,
            BundleEngineMode::BundleModules
        );
    }

    #[test]
    fn removed_admission_flags_are_rejected() {
        assert!(Config::try_parse_from(["treetop-server", "--client-allowlist", "*"]).is_err());
        assert!(Config::try_parse_from(["treetop-server", "--trust-ip-headers"]).is_err());
    }
}
