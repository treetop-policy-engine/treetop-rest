# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Refresh Rust dependencies in both committed lockfiles and pin GitHub Actions to
  their latest stable releases before publication; preserve compatibility requirements.

- Adopt Core 0.0.25 and Bundle's explicit `PreparedEngine` schema modes. Strict and permissive policy loading
  retain their existing behavior, and each authorization batch captures one frozen evaluation session.
- Authorization and version responses now include nullable `label_set` and unsigned `generation` metadata.
  Label identifiers use the SHA-256 digest of the loaded label document (canonical JSON for bundles) and survive
  engine replacement. Generation is local to one engine instance and can restart when an engine is replaced.
- Label rules for different resource kinds can share one output owner; invalid or reserved outputs reject the
  replacement before publication. Failed label reloads leave the active engine and metadata intact.
- **Breaking:** malformed identities and IP values now fail during JSON deserialization with HTTP 400, rejecting
  the whole batch. Callers must validate/fix those inputs rather than expecting a per-item evaluation failure.
- Rust callers must handle fallible request constructors, use `AttrValue::ip`, and adopt `PreparedEngine` for
  store engines. REST decision field names and Allow/Deny values remain stable; conversion uses Core accessors.

## [0.0.15] - 2026-08-30

### Added

- Added the opt-in `--bundle-engine-mode=bundle-modules` /
  `TREETOP_BUNDLE_ENGINE_MODE=bundle-modules` loading path. It derives namespace-partitioned Core policy stores from
  validated ordinary bundle modules, replicates global-module policies into every store, logs the active mode on
  successful bundle application, and fails closed when module boundaries are not independent.

### Changed

- Updated `treetop-core` to 0.0.23 and `treetop-bundle` to 0.0.6. Existing deployments remain on the `monolithic`
  bundle engine mode by default, raw Cedar loading remains monolithic, and the bundle archive format remains version
  1.
- Refreshed Actix Web/runtime, LRU, UUID, build-metadata dependencies, and the pinned benchmark workflow to their
  latest compatible stable releases.

## [0.0.14] - 2026-08-18

### Added

- Added deterministic large-policy REST characterization using Treetop Core's shared corpus, covering authorization,
  policy listing, reload and rollback, process memory, and administrator-visible OpenMetrics across 1,000-, 10,000-,
  and 100,000-policy weekly runs, with manual 250,000-policy and sustained reload-soak modes.
- Added a fixed 1,000-policy Callgrind target for store reload, allow and forbid authorization, mixed batches, and
  cached policy listing.

### Changed

- Updated `treetop-core` to 0.0.22 and `treetop-bundle` to 0.0.5. The REST API, configuration, and production metric
  surface are unchanged.

### Security

- Updated the HTTP client stack to patched `h2` 0.4.16 and stopped compiling Actix's vulnerable `h2` 0.3 line by
  disabling the unused server HTTP/2 feature. The server continues to expose the same plaintext HTTP/1.x listener.

## [0.0.13] - 2026-08-16

### Added

- Added optional polling and authenticated upload of deterministic `.tar.gz` Treetop policy bundles, with bounded
  streaming, conditional requests, atomic policy/schema/label replacement, last-known-good readiness behavior, and
  bundle identity and signature details in status metadata.
- Added Ed25519 bundle trust configuration, optional or required signature policies, multi-key rotation support, and
  bounded bundle reload success and failure metrics.
- Added independent environment-only IP/CIDR and opaque Bearer-token admission controls for `/api/v1/**` and
  `/metrics`, explicit trusted-proxy chain walking for `X-Forwarded-For`, fixed-reason rejection metrics, and OpenAPI
  Bearer security metadata.
- Added an operator security guide covering network and proxy trust, access and upload credentials, remote sources,
  signed bundles, resource limits, information exposure, hardened deployment, rotation, and compromise response.

### Changed

- Updated `treetop-bundle` to 0.0.4 and refreshed every outdated direct Rust dependency (`uuid`, `base64`, and
  `ed25519-dalek`) to its latest stable release. REST disables the bundle crate's encrypted-private-key feature because
  the service verifies bundles with public keys and never loads signing keys.
- Reduced admission hot-path work by hashing Bearer candidates once, parsing trusted forwarding chains without a
  temporary address allocation, and isolating allowlist parsing from request-path benchmarks. Legacy label updates now
  parse once and reuse compiled regex programs. Bundle loads reuse validated artifact counts, preallocate bounded
  compressed bodies, adopt rotated HTTP validators for unchanged archives, and run archive verification, engine
  construction, and upload-response preparation outside async workers and the policy-store write lock. Bundle URL
  mode now rejects a zero-second polling interval instead of starting a tight fetch loop.
- Expanded deterministic performance gates for signed and unsigned bundle validation, atomic bundle application,
  schema reloads, and policy-list cache hits and misses. Benchmark fixtures and heavyweight teardown now run outside
  authorization, bundle, schema, cache, and client-IP measurement regions, and an integration test enforces automatic
  Callgrind target discovery.
- Legacy label loading now uses the shared `treetop-bundle` parser and intentionally rejects unknown fields, empty
  values or pattern lists, duplicate names or destinations, invalid Cedar entity types, and invalid regular
  expressions. Labels must also match an active schema's entity and attribute types. Bundle loads always apply strict
  aggregate schema validation when a schema is present.
- **Breaking security change:** The client allowlist now defaults to open instead of loopback-only. Deployments that
  relied on the old default must set `TREETOP_CLIENT_ALLOWLIST=127.0.0.1,::1` before upgrading. Allowlist and trusted
  proxy settings are now environment-only, and configured ACL and Bearer controls must both pass.

### Fixed

- Protected routes are classified by Actix's routing-normalized path, preventing percent-encoded `/api/v1/**` and
  `/metrics` paths from bypassing admission controls.
- Bundle uploads no longer erase configured remote-source readiness state, schema-free bundles are rejected before
  Cedar engine construction in strict schema mode, and upload bodies obey the lower of the global request limit and
  compressed-bundle limit.
- Admission benchmarks now cover canonical and percent-encoded protected routes. Trusted-proxy and direct-peer
  request construction run in setup rather than contaminating the measured client-IP resolution paths.

### Removed

- Removed `--client-allowlist`, `--trust-ip-headers`, and `TREETOP_TRUST_IP_HEADERS`. Use
  `TREETOP_CLIENT_ALLOWLIST` and explicit `TREETOP_TRUSTED_PROXIES` networks instead.

### Security

- Signed bundles are accepted only when their Ed25519 signature matches a configured SPKI public key; malformed,
  invalid, or untrusted signatures are never downgraded to unsigned content. Private signing material is not loaded by
  the REST service.
- Access tokens are validated at startup, retained only as unique SHA-256 digests, compared without early-exit digest
  equality, never logged, and rejected through a credential-independent `401` response. Operators must use TLS outside
  loopback and may rotate tokens by overlapping old and new values across restarts.

## [0.0.12] - 2026-08-14

### Added

- Added `authorization_batch_size` and bounded `batch_size_class` labels on a dedicated authorization latency histogram
  so operators can correlate slow REST authorization requests with their batch sizes and calculate amortized server
  time per authorization check.
- Added adaptive native histograms for HTTP and policy-evaluation latency through negotiated Prometheus protobuf
  exposition, while retaining classic histogram output.
- Added `policy_eval_phase_duration_seconds` for the label, entity-construction, group-resolution, Cedar authorization,
  and residual phases already measured by Treetop Core.
- Added an opt-in end-to-end latency characterization with representative single and batch workloads, CPU/runtime/build
  provenance, documented example results, and a reviewable machine-anonymous JSON export. A Linux runner generates
  scaling matrices across arbitrary counts or exact CPU-affinity sets and production or controlled Actix/Rayon layouts.
  A k6 2.2.0 scenario adds fixed-sample, sustained, and constant-arrival-rate load from the same or a remote node.

### Changed

- Updated `treetop-core` to 0.0.21 for the borrowed evaluation-observation API used by the detailed authorization
  timing metrics and the authorization hot-path optimizations.
- Move the canonical source repository and container distribution to the
  `treetop-policy-engine` organization. New server images are published only to
  `ghcr.io/treetop-policy-engine/treetop-rest`; personal GHCR and Docker Hub paths are no longer
  updated.
- **Breaking metrics exposition change:** Migrated `/metrics` text output from Prometheus 0.0.4 to OpenMetrics 1.0,
  canonicalized action label values from `Action::\"id\"` to `Action::id`, and replaced raw HTTP paths with route
  templates (`unmatched` for unknown routes). Metric sample names and label keys remain stable. Update direct text
  parsers and label/path selectors during rollout; Prometheus scrapers continue to negotiate a supported format.
- Expanded both latency histograms from the 11 Prometheus default boundaries to a strict 19-boundary superset spanning
  10 microseconds through 10 seconds. Existing boundaries retain their time series, but wait one full query window
  before evaluating classic quantiles across the rollout.
- Replaced the `prometheus` client with `prometheus-client` 0.25.0, refreshed all compatible Rust lockfile dependencies,
  updated `futures` to 0.3.34, updated `actions/upload-artifact` to v7.0.1, pinned all GitHub Actions to full commit SHAs,
  and pinned the container builder to Rust 1.97.1 on Alpine 3.24.
- Emit the full Treetop REST commit SHA and packaged Treetop Core source SHA in build metadata so performance reports
  identify the exact source revisions.

### Fixed

- Cache canonical action labels and resolved Prometheus metric handles, and recognize Core's unambiguous canonical
  action form without a general Cedar parse, so policy evaluations avoid unnecessary parser and metric-family work on
  the authorization hot path.

## [0.0.11] - 2026-08-13

### Removed

- **Breaking packaging change:** Removed the bundled `treetop-cli` binary, public `treetop_rest::cli`
  module, CLI-only dependencies, matrix benchmarks, tests, and documentation. Users of the v0.0.10
  bridge binary should install
  [treetop-cli v0.0.1](https://github.com/treetop-policy-engine/treetop-cli/releases/tag/v0.0.1),
  which preserves
  the CLI/REPL configuration and history locations and uses `treetop-client` 0.0.2.

### Changed

- Describe the package and generated OpenAPI document as a server-only release.
- Package only the x86_64 and ARM64 Linux musl server binaries in GitHub releases. Container images
  and runtime behavior are unchanged.

## [0.0.10] - 2026-08-12

### Added

- Added a canonical generated OpenAPI document at `/openapi.json`, a checked-in
  `docs/openapi.json` copy with stale-document checks, and documented regeneration.

### Changed

- Configured Swagger UI to load `/openapi.json` while preserving
  `/api-docs/openapi.json` as a compatibility alias.
- Documented operation tags, upload-token security, supported JSON and plain-text
  representations, and the actual structured error response in the generated spec.
- Marked v0.0.10 as the final bridge release that includes the bundled
  `treetop-cli`. Future CLI releases are available from the standalone
  [treetop-cli repository](https://github.com/treetop-policy-engine/treetop-cli).

### Fixed

- Made the generated schema-upload alternatives valid for standard OpenAPI
  validators while preserving the public Rust `handlers::ApiDoc` entry point.

## [0.0.9] - 2026-08-12

### Fixed

- Isolated each Linux release target's cross-compilation artifacts so host build scripts are not reused across
  incompatible container glibc versions.

## [0.0.8] - 2026-08-12

### Added

- Added continuous fuzz testing for authorization request handling and atomic policy, schema, and label reloads.
- Added `/livez` and `/readyz` operational probes, including readiness tracking for the initial successful load of
  every configured remote policy, label, and schema source.

### Changed

- Updated `treetop-core` to version `0.0.19`.
- Migrated performance benchmarks from `iai-callgrind` to Gungraun 0.19.4 and upgraded the reusable benchmark
  workflow from v1 to v3.
- Updated the Cargo dependency graph to current Rust 1.97-compatible releases, including Actix Web 4.14.1 and Cedar
  Policy 4.12.0.
- Upgraded GitHub Actions dependencies, pinned the release and cross-compilation tools, and added Dependabot coverage
  for GitHub Actions and container images.
- Updated the build and runtime containers to Rust 1.97, Alpine 3.24, and miniserve 0.35.0.
- Disabled crates.io publishing for the server package; supported release artifacts remain container images and
  prebuilt binaries.

### Security

- Added a configurable authorization batch limit to bound evaluation work per request.
- Authenticate policy and schema uploads before parsing their bodies, while retaining a second authorization check
  before applying an update.

## [0.0.7] - 2026-07-04

### Changed

- Updated direct dependencies to current compatible releases, including `lru` 0.18, `tabled` 0.21, and the
  `vergen` 10 build metadata toolchain.
- Updated `treetop-core` to version `0.0.18`.
- Refreshed the full Cargo lockfile to the latest Rust 1.96-compatible dependency graph.

### Fixed

- Migrated the build script to the `vergen` 10 API so release build metadata continues to include Cargo, Rust, build,
  and Git information.

## [0.0.6] - 2026-04-04

### Added

- Request context evaluation support on `POST /api/v1/authorize`.
- Runtime context status on `GET /api/v1/status` via `request_context.{supported,schema_backed,fallback_reason}`.

### Changed

- Updated `treetop-core` to version `0.0.17`.
- Updated direct Cedar dependencies to the `4.9` line used by the new core release.
- Uploaded schemas now participate in live runtime evaluation when compatible with the active policies.
- In permissive schema mode, incompatible schema uploads are retained as metadata while evaluation falls back to a
  schema-free engine.
- CLI `status` output now shows whether request-context evaluation is schema-backed or running in fallback mode.

### Fixed

- Evaluate authorize requests with supplied `context` instead of validating and then ignoring it.
- Preserve schema-backed runtime behavior when labels are reloaded.
- Map `treetop-core` request, context, and evaluation errors to the correct REST error categories.
- Refresh API and README documentation for context support, `/status`, and current release behavior.

## [0.0.5] - 2026-04-04

### Added

- Cedar schema management support, including `GET /api/v1/schema` and `POST /api/v1/schema`.
- CLI support for downloading and uploading schemas, including `upload --schema`.
- Schema validation and schema-fetch configuration for policy/schema reloads.
- Match reasons in user policy responses via `matches[].reasons`.
- Configurable request body size limit via `TREETOP_MAX_REQUEST_SIZE`.

### Changed

- Improved shared policy store concurrency and robustness under poisoned-lock scenarios.
- Split and renamed benchmark targets with `_callgrind` suffix for better perf workflow discovery.
- Updated API and configuration documentation to cover schema support and current server behavior.

### Fixed

- Send `X-Upload-Token` correctly on JSON upload paths.
- Correct Docker healthcheck path to `/api/v1/health`.
- Ensure generic fetcher updates hashes and metadata correctly to avoid unnecessary reloads.
- Correct OpenAPI annotations for GET endpoints such as health and version.
- Refresh README and API examples to use current endpoint paths and upload behavior.

## [0.0.4] - 2026-02-09

### Added

- Group membership support for policy retrieval via `groups` query parameter on `/api/v1/policies/{user}` endpoint
- Test suite for group membership filtering functionality
- Performance tracking via `iai-callgrind` action
- Dependabot support

### Changed

- Updated `treetop-core` to version 0.0.16.
- **CLI**: Consolidated `get-policies` and `list-policies` commands into single `policies` command
- **CLI**: Added `--user` flag to `policies` command for retrieving user-specific policies
- **CLI**: Added support for group membership syntax using bracket notation (e.g., `DNS::User::alice[admins,developers]`)

### Fixed

- **CLI**: Extract entity ID from namespaced principals (e.g., `DNS::User::alice` → `alice`) before making API requests,
as the API expects just the entity ID

## [0.0.3] - 2026-02-01

### Changed

- Updates `treetop-core` to version 0.0.14.
- **BREAKING** Brief authorization responses now include the policy identifier in the `policy_id` field

## [0.0.2] - 2026-01-31

### Changed

- Migrate to single authorize endpoint, `/api/v1/authorize`, which handles both single and batch requests.
- Update CLI to use the new unified authorize endpoint for all permission checks.
- Remove all other authorize endpoints.
- Remove principal from metrics labels to reduce cardinality.
