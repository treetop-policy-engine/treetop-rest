# Treetop REST API

This document describes the HTTP interface exposed by the Treetop REST server for
policy management and evaluation.

See the [security guide](security.md) for deployment trust boundaries and production hardening.

## Base URL and formats

- Default base URL: `http://localhost:9999`
- All requests and responses use JSON unless noted.
- Policy upload requests accept either `application/json` with a `policies` string
  field or `text/plain` containing Cedar policy DSL.
- Schema upload requests accept `application/json` containing either a `schema`
  string field or a raw Cedar schema document, or `text/plain` containing Cedar
  schema JSON.
- Bundle uploads accept `application/gzip` or `application/x-gzip`.

## Authentication

- `/api/v1/**` and `/metrics` require `Authorization: Bearer <token>` when the server has
  `TREETOP_ACCESS_TOKENS` configured. Missing and rejected credentials receive the same `401 Unauthorized` JSON error
  and `WWW-Authenticate: Bearer` response header.
- A configured client allowlist applies independently to the same routes. A disallowed or unresolved client address
  receives `403 Forbidden`. When both controls are configured, the ACL is evaluated first and both controls must pass.
- `/livez`, `/readyz`, `/openapi.json`, `/api-docs/openapi.json`, and `/swagger-ui/**` are public.
- Uploads to `/api/v1/policies`, `/api/v1/schema`, and `/api/v1/bundle` additionally require
  `TREETOP_ALLOW_UPLOAD=true` and the
  `X-Upload-Token: <token>` header matching the server-generated upload token. When Bearer admission is enabled, uploads
  require both credentials.
- Send Bearer credentials only over HTTPS outside loopback. Access tokens are static operator-provided credentials;
  they have no identity, scope, expiry, or management API.

## Errors

Fallible endpoints return a JSON object with an `error` message and stable `code`.
Parse and schema errors may also include `details` containing `line` and `column`
numbers when the underlying parser reports them.

## Endpoints

### GET /livez

- Purpose: Kubernetes-style liveness probe. A successful response means the HTTP
  worker is alive; the probe deliberately does not depend on remote configuration.
- Response: `ok` as plain text with HTTP 200.
- This operational endpoint bypasses all admission controls.

### GET /readyz

- Purpose: Kubernetes-style readiness probe. A successful response means the policy
  store is available and every configured remote policy, labels, schema, or bundle
  source has completed at least one valid load.
- Response: `ok` as plain text with HTTP 200 when ready, or `not ready` with HTTP 503.
- The check does not make network requests. After an initial successful load, a later
  remote fetch failure continues serving the last-known-good configuration and does
  not make the service unready.
- This operational endpoint bypasses all admission controls.

### GET /openapi.json

- Purpose: machine-readable OpenAPI specification generated from the server route
  definitions.
- Response: OpenAPI JSON document for the Treetop REST API.
- Interactive documentation: Swagger UI is available at `/swagger-ui/` and loads
  this canonical document.
- Compatibility: `/api-docs/openapi.json` serves the same document for clients of
  earlier releases.
- Static copy: [`docs/openapi.json`](openapi.json). Regenerate it with
  `cargo run --example openapi > docs/openapi.json`.

### GET /metrics

- Purpose: Prometheus/OpenMetrics counters, gauges, and latency histograms.
- Default response: OpenMetrics 1.0 text with
  `Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8`.
- Native histogram response: length-delimited Prometheus `MetricFamily` protobuf when the `Accept` header requests
  `application/vnd.google.protobuf`, `proto=io.prometheus.client.MetricFamily`, and `encoding=delimited`.
- This operational endpoint is subject to the configured client allowlist and Bearer-token controls.

The server exposes classic and native representations of its latency histograms. The metric sample names and label keys
used before this migration are retained:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `http_requests_total` | `method`, `path`, `status_code`, `client_ip` | Completed HTTP requests. |
| `http_request_duration_seconds` | `method`, `path`, `status_code` | Server-side HTTP handling time. |
| `authorization_batch_size` | none | Authorization checks per completed, accepted authorization request. |
| `authorization_request_duration_seconds` | `batch_size_class` | Server-side authorization-request latency by bounded batch-size class. |
| `policy_evals_total` | `action` | Core policy decisions. |
| `policy_evals_allowed_total` | `action` | Allowed Core decisions. |
| `policy_evals_denied_total` | `action` | Denied Core decisions. |
| `policy_eval_duration_seconds` | `action` | Total Treetop Core evaluation time per decision. |
| `policy_eval_phase_duration_seconds` | `action`, `phase` | One Core phase per decision. |
| `bundle_reloads_total` | none | Successfully verified and atomically applied bundles. |
| `bundle_reload_failures_total` | `reason` | Failed bundle loads using a bounded reason set. |
| `policy_reloads_total` | none | Successful Core policy reloads. |
| `schema_reloads_total` | none | Successful schema reloads. |
| `schema_validation_failures_total` | `reason` | Schema validation failures. |
| `context_validation_failures_total` | `reason` | Request-context validation failures. |
| `admission_rejections_total` | `reason` | Admission-control rejections from a fixed, bounded reason set. |
| `treetop_build_info` | `app_version`, `core_version`, `cedar_version` | Build identity gauge fixed at 1. |

HTTP `path` uses the registered route template, such as `/api/v1/policies/{user}`, rather than the raw user value.
Requests that do not match a registered route use `path="unmatched"`. This bounds path cardinality. `client_ip` remains
on the request counter for compatibility but is deliberately absent from the duration histogram.

`authorization_batch_size` records one observation after a `POST /api/v1/authorize` request has passed admission,
payload and JSON extraction, and the configured maximum-batch check and has produced a response. Its `_sum` is the
number of accepted authorization checks and its `_count` is the number of accepted HTTP batches. The fixed classic
boundaries are `0`, `1`, `4`, `8`, `32`, `128`, and `512`, plus `+Inf`.

`authorization_request_duration_seconds` uses the same server-side timer as `http_request_duration_seconds` and labels
each accepted batch as `0`, `1`, `2-4`, `5-8`, `9-32`, `33-128`, `129-512`, or `513+`. These values remain fixed when
instances configure different `TREETOP_MAX_BATCH_SIZE` values, so fleet aggregation stays safe. Empty batches retain
their existing accepted behavior and use class `0`. Admission failures, payload or JSON extraction failures, and
over-limit batches are absent from both authorization metrics; an accepted batch that later returns an application
error remains included.

The action label is the Cedar entity UID without representation quotes, for example `Action::view`. Treat the action
vocabulary as a controlled, bounded set. Percent, quote, backslash, and control characters inside unusual action IDs
use uppercase percent encoding to keep text and protobuf labels identical and collision-safe. Dynamic per-request action
IDs would create high-cardinality metrics.

#### Policy phase semantics

`policy_eval_phase_duration_seconds` builds directly on the phase timings exported by Treetop Core 0.0.19:

| `phase` | Timing boundary |
| --- | --- |
| `apply_labels` | Apply configured labels to the request resource. |
| `construct_entities` | Build Cedar entities used for evaluation. |
| `resolve_groups` | Resolve principal group entities. |
| `cedar_authorize` | Call Cedar's `Authorizer::is_authorized`. |
| `overhead` | Non-negative residual of Core total minus the four named phases. |

The residual currently includes Cedar request construction, result and diagnostic materialization, other unpartitioned
Core work, and timer precision. If a future optimization requires another internal boundary, add it to Treetop Core's
`EvaluationPhases` first and then expose it here; the REST server does not duplicate Core timers.

One HTTP authorization batch produces one HTTP observation and one total plus five phase observations per decision.
Batch decisions can execute concurrently. Consequently, the HTTP duration is not the sum of policy durations, and the
sum of phase percentiles is not a total percentile. Compare sums or means when estimating phase contribution.

The opt-in [performance characterization](performance.md) reports the wider client-observed HTTP round trip alongside
these server and Core layers.

#### Histogram layout

OpenMetrics text exposes these 19 finite classic boundaries, in seconds:

```text
0.000010, 0.000025, 0.000050, 0.000100, 0.000250, 0.000500,
0.001, 0.0025, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250,
0.500, 1, 2.5, 5, 10
```

The layout is a strict superset of the former Prometheus client defaults. It preserves every old boundary while adding
10, 25, 50, 100, 250, and 500 microsecond buckets plus 1 and 2.5 millisecond buckets. This resolves the normal
Treetop distribution without sacrificing the previous long-tail coverage.

Each populated classic label set costs 20 bucket series including `+Inf`, plus `_sum` and `_count`: 22 series instead
of the previous 14, a 57% increase. The phase metric can populate five label sets per observed action, or 110 classic
series per action. Authorization latency can populate eight fixed batch classes, or 176 classic series, and its batch
size histogram costs ten series. HTTP series scale with observed `method`/route-template/`status_code` combinations.
Native ingestion uses one sparse histogram series per label set and is the preferred long-term representation for
varied workloads.

The protobuf response also contains a standard exponential native histogram with a maximum bucket growth factor of
1.1 and an instrumentation-side best-effort limit of 160 populated sparse buckets. Native buckets adapt to distributions
outside the classic range without a server configuration matrix. The fixed classic layout remains fleet-wide so
classic histograms are aggregatable during migration.

#### Enable native histogram scraping

[Prometheus 3.8 and newer](https://prometheus.io/docs/specs/native_histograms/) support native histograms as a stable
feature, but Prometheus 3.x still requires explicit scrape configuration. During migration, ingest both forms so
existing classic queries continue working:

```yaml
scrape_configs:
  - job_name: treetop-rest
    scrape_native_histograms: true
    always_scrape_classic_histograms: true
    static_configs:
      - targets: ["treetop-rest:9999"]
```

After dashboards, alerts, recording rules, and the longest relevant query window use native histograms, set
`always_scrape_classic_histograms: false` to avoid storing the classic bucket series. Prometheus then negotiates the
protobuf response and retains the native part. If remote write is used, configure its native-histogram support as well.
See the [Prometheus native histogram specification](https://prometheus.io/docs/specs/native_histograms/) for versioned
scrape and remote-write requirements.

No Treetop server flag selects the exposition: ordinary text scrapers receive the compatibility form, while Prometheus
content negotiation selects protobuf. A direct protobuf request is:

```bash
curl -H 'Accept: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited' \
  -H "Authorization: Bearer <access-token>" \
  http://localhost:9999/metrics --output metrics.pb
```

#### PromQL examples

Native histogram p95 authorization latency by batch-size class:

```promql
histogram_quantile(
  0.95,
  sum by (batch_size_class) (rate(authorization_request_duration_seconds[5m]))
)
```

Native histogram mean authorization latency by batch-size class:

```promql
sum by (batch_size_class) (
  histogram_sum(rate(authorization_request_duration_seconds[5m]))
)
/
sum by (batch_size_class) (
  histogram_count(rate(authorization_request_duration_seconds[5m]))
)
```

With classic histograms retained, amortized server time per accepted authorization check is total batch wall time
divided by the exact number of checks:

```promql
sum(rate(authorization_request_duration_seconds_sum[5m]))
/
sum(rate(authorization_batch_size_sum[5m]))
```

When authorization latency is ingested only as a native histogram, use its native sum with the classic batch-size sum:

```promql
sum(histogram_sum(rate(authorization_request_duration_seconds[5m])))
/
sum(rate(authorization_batch_size_sum[5m]))
```

This ratio measures batching efficiency in server wall-clock seconds per check. It is not individual evaluation
latency: decisions in a batch can run concurrently. Use `policy_eval_duration_seconds` for Core time per decision.

Native histogram p95 HTTP latency by route:

```promql
histogram_quantile(
  0.95,
  sum by (path) (rate(http_request_duration_seconds[5m]))
)
```

Native histogram p95 Core phase latency:

```promql
histogram_quantile(
  0.95,
  sum by (action, phase) (rate(policy_eval_phase_duration_seconds[5m]))
)
```

Native histogram mean phase time uses `histogram_sum` and `histogram_count`:

```promql
sum by (action, phase) (
  histogram_sum(rate(policy_eval_phase_duration_seconds[5m]))
)
/
sum by (action, phase) (
  histogram_count(rate(policy_eval_phase_duration_seconds[5m]))
)
```

The equivalent classic p95 query keeps the `le` dimension:

```promql
histogram_quantile(
  0.95,
  sum by (le, path) (rate(http_request_duration_seconds_bucket[5m]))
)
```

#### Migration notes

- Metric sample names and label keys are unchanged. Existing exact queries for old classic boundaries continue to use
  the same time series.
- `/metrics` text changes from Prometheus 0.0.4 to OpenMetrics 1.0 and ends with `# EOF`. Counter `TYPE` metadata uses
  the OpenMetrics family name without `_total`; counter sample names still end in `_total`.
- Action label values change from Cedar's quoted display form, such as `Action::\"view\"`, to `Action::view`.
- Raw HTTP paths change to route templates, and unmatched requests collapse to `unmatched`. Update dashboards that
  selected a concrete `/api/v1/policies/<user>` path.
- Newly added classic buckets and all native histogram series have no pre-deployment history. Avoid aggregating classic
  quantiles across mixed old/new instances or a range spanning the rollout; wait at least one full query window after
  every target uses the new layout.
- Native and classic histogram samples are different Prometheus data types. During dual ingestion, keep their queries
  separate; do not add them together.

### GET /api/v1/health

- Purpose: legacy liveness probe retained for compatibility. New deployments should
  use `/livez` and `/readyz`.
- Response: `{}` with HTTP 200.

### Authorization state metadata

Policy versions include `hash`, `loaded_at`, nullable `label_set`, and unsigned `generation`.
Each authorization batch and every successful item use the same complete state version. `label_set`
identifies the installed label configuration using the SHA-256 digest of its document; bundle documents
use canonical JSON. `generation` is local to an engine instance and can restart when REST replaces it.
Consumers comparing versions must include all four fields.

Malformed principal/action/resource identities and IP attributes cause HTTP 400 during deserialization,
rejecting the entire batch before evaluation. Evaluation-time failures still use failed per-item results.

### GET /api/v1/version

- Purpose: version metadata for the server and policy engine.
- Response shape:
  - `version`: server version string.
  - `core`: `{ version, cedar }` identifying treetop-core and Cedar versions.
  - `policies`: `{ hash, loaded_at }` identifying the currently loaded policy set.
     The hash is a SHA-256 of the policy content, and `loaded_at` is an RFC 3339
     timestamp of when the policies were loaded.
  - `schema` (optional): `{ hash, loaded_at }` identifying the currently loaded schema.

Example response:

```json
{
  "version": "0.1.0",
  "core": {
    "version": "0.3.0",
    "cedar": "0.11.0"
  },
  "policies": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  }
}
```

### GET /api/v1/status

- Purpose: server status plus metadata for currently loaded policies, labels, and schema.
- Response shape:
  - `policy_configuration`: policy, label, schema, and optional bundle metadata, including:
    - `allow_upload`
    - `schema_validation_mode`
    - `policies`
    - `labels`
    - `schema`
    - `bundle`: format and bundle IDs, archive hash and size, module/signature details, source, refresh interval, and
      load timestamp. Its presence means the active policy state was loaded atomically from a bundle; `signed` reports
      whether that bundle carried a verified signature, and `signing_key_id` identifies the trusted verification key.
      This field is absent after an independent component update.
  - `parallel_configuration`: current Actix/Rayon worker settings.
  - `request_limits`: currently enforced context limits.
  - `request_context`: runtime context mode:
    - `supported`: request context is supported by the bundled core.
    - `schema_backed`: request/context evaluation is currently using a schema-backed engine.
    - `fallback_reason`: `no_schema` or `schema_incompatible` when runtime is not schema-backed.

Example response:

```json
{
  "policy_configuration": {
    "allow_upload": false,
    "schema_validation_mode": "permissive",
    "policies": {
      "timestamp": "2025-12-19T00:14:38.577289000Z",
      "sha256": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
      "size": 2049,
      "source": { "url": "https://example.com/production.tar.gz" },
      "refresh_frequency": 300,
      "entries": 42,
      "content": "...DSL content..."
    },
    "labels": {
      "timestamp": "2025-12-19T00:14:38.577289000Z",
      "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
      "size": 512,
      "source": { "url": "https://example.com/production.tar.gz" },
      "refresh_frequency": 300,
      "entries": 10,
      "content": "...JSON content..."
    },
    "schema": {
      "timestamp": "2025-12-19T00:14:38.577289000Z",
      "sha256": "bbf3d4d65ab0c11f8fa73f8cf54eb7bbd7d8bfcc8ca0d26f5cab098507ad6f6d",
      "size": 411,
      "source": { "url": "https://example.com/production.tar.gz" },
      "refresh_frequency": 300,
      "entries": 1,
      "content": "{...schema json...}"
    },
    "bundle": {
      "format_version": 1,
      "bundle_id": "9dca3dfe1c7e976b9a5c713a7f82529c78d92691a4e419142fdde92f50f033f4",
      "archive_sha256": "d88ccdddbca3e4d305f705348e80b0de3c326c9384b9a7c25942f0254f54342a",
      "compressed_size": 16384,
      "module_count": 3,
      "signed": true,
      "signing_key_id": "f62d00af62c26edc920ddf22c11f57f84e511490d8d753cebfccbd5215956124",
      "source": { "url": "https://example.com/production.tar.gz" },
      "refresh_frequency": 300,
      "loaded_at": "2025-12-19T00:14:38.577289000Z"
    }
  },
  "parallel_configuration": {
    "cpu_count": 8,
    "workers": 8,
    "rayon_threads": 8,
    "par_threshold": 8,
    "allow_parallel": true
  },
  "request_limits": {
    "max_batch_size": 1024,
    "max_context_bytes": 16384,
    "max_context_depth": 8,
    "max_context_keys": 64
  },
  "request_context": {
    "supported": true,
    "schema_backed": false,
    "fallback_reason": "no_schema"
  }
}
```

### GET /api/v1/policies

- Purpose: download the current policy set.
- Query: `format=raw` (or `text`) to receive plain DSL content; otherwise
  JSON.
- Responses:
  - JSON: `{ "policies": Metadata }` with `content` containing the DSL string.
  - Raw: `text/plain` body with the DSL.

### POST /api/v1/policies

- Purpose: upload or replace the policy set (if allowed).
- Headers: `Authorization: Bearer <access-token>` when global token admission is configured,
  `X-Upload-Token: <upload-token>`, and `Content-Type` as described above.

#### Upload examples

JSON:

```bash
curl -X POST http://localhost:9999/api/v1/policies \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -H "X-Upload-Token: <upload-token>" \
  --data-binary @policies.json
```

See the [cedar JSON documentation](https://docs.cedarpolicy.com/policies/json-format.html) for details.

Cedar DSL:

```bash
curl -X POST http://localhost:9999/api/v1/policies \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: text/plain" \
  -H "X-Upload-Token: <upload-token>" \
  --data-binary @policies.cedar
```

See the [Cedar policy language documentation](https://docs.cedarpolicy.com/policies/syntax-policy.html) for details.

- Response: `PoliciesMetadata` reflecting the newly loaded policies and labels. As per the
  status endpoint (minus `allow_upload`).

When remote bundle mode is active, independent policy and schema uploads return `409 Conflict` because they would
break the bundle's atomic policy/schema/label state.

### POST /api/v1/bundle

- Purpose: verify and atomically replace the complete policy, schema, and label state from a Treetop `.tar.gz` bundle.
- Creation: use the
  [`treetop-bundle` CLI](https://github.com/treetop-policy-engine/treetop-bundle/blob/v0.0.6/README.md#commands) to validate,
  build, and optionally sign compatible archives:

  ```bash
  treetop-bundle build --manifest treetop-bundle.toml --output bundle.tar.gz
  treetop-bundle build --manifest treetop-bundle.toml --output signed-bundle.tar.gz \
    --signing-key private.pem
  ```

  Private signing keys are build-time material: keep them and their passphrases on the system running
  `treetop-bundle`, and never upload or configure them in Treetop REST. The REST service loads only trusted Ed25519 SPKI
  public keys for verification. `treetop-bundle` 0.0.6 supports password-encrypted PKCS#8 private keys through
  `--signing-key-password-file` or `TREETOP_BUNDLE_SIGNING_KEY_PASSWORD`; see its
  [signing-key documentation](https://github.com/treetop-policy-engine/treetop-bundle/blob/v0.0.6/README.md#signing-keys).
  REST does not enable encrypted-private-key loading because it never handles private keys; this does not affect its
  ability to verify bundles produced with encrypted signing keys.

- Headers: `Authorization: Bearer <access-token>` when global token admission is configured,
  `X-Upload-Token: <upload-token>`, and `Content-Type: application/gzip` or `application/x-gzip`.
- Signature behavior: the configured bundle signature policy is applied identically to fetched and uploaded bundles.
  Under `allow-unsigned`, unsigned bundles are accepted but any signature present must be trusted and valid. Under
  `required`, unsigned bundles are rejected.
- Atomicity: archive decoding, signature verification, policy/schema/label validation, and engine construction occur
  before the active store is replaced. Strict schema mode checks that the bundle includes a schema before constructing
  a Cedar engine. A rejected bundle leaves the last-known-good state unchanged.
- Responses: `200` with updated `PoliciesMetadata`; `400` for invalid content or signatures; `413` for the compressed
  bundle or global request-size limit, whichever is lower; `415` for unsupported media types; and the existing `403`
  response for admission or upload failures.

```bash
curl -X POST http://localhost:9999/api/v1/bundle \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/gzip" \
  -H "X-Upload-Token: <upload-token>" \
  --data-binary @bundle.tar.gz
```

### GET /api/v1/schema

- Purpose: download the current Cedar schema.
- Query: `format=raw` (or `text`) to receive raw schema JSON; otherwise JSON.
- Responses:
  - JSON: `{ "schema": Metadata }` with `content` containing schema JSON.
  - Raw: `text/plain` body with schema JSON.

### POST /api/v1/schema

- Purpose: upload or replace the Cedar schema (if allowed).
- Headers: `Authorization: Bearer <access-token>` when global token admission is configured,
  `X-Upload-Token: <upload-token>`, and `Content-Type` as described above.
- Request body: a JSON object with a `schema` string, a raw Cedar schema JSON
  document, or the Cedar schema JSON as `text/plain`.
- Response: `PoliciesMetadata` with updated schema metadata.

### GET /api/v1/policies/{user}

- Purpose: list policies that apply to a user.
- Response: `{ "user": "<user>", "policies": [<policy_json_objects>], "matches": [<match_metadata>] }`.
  - `matches[].cedar_id`: Cedar policy identifier.
  - `matches[].reasons`: Why each policy matched (for example `PrincipalEq`, `ActionEq`, `ResourceIs`).

### POST /api/v1/authorize (Unified Authorization Endpoint)

- Purpose: evaluate one or more authorization requests with optional client-provided identifiers.
- Query parameters:
  - `detail`: Response detail level. `brief` (default) returns only decision and version; `full` (or `detailed`)
  includes matching policy information.
- Request body (JSON):
  - `requests`: Array of authorization requests. The server rejects arrays larger than its configured
    `TREETOP_MAX_BATCH_SIZE` before evaluation. Each entry contains:
    - `id` (optional): Client-provided identifier for correlating responses
    - `context` (optional): request-scoped Cedar attributes passed as `context.<field>`
    - `principal`: Principal object
    - `action`: Action identifier
    - `resource`: Resource object with `kind`, `id`, and optional `attrs`
- Context behavior:
  - `context` is fully evaluated when supplied.
  - In `strict` schema mode, sending `context` without an uploaded schema fails that request.
  - In `permissive` mode, context can still be evaluated when runtime has fallen back to a schema-free engine, but
    `/api/v1/status.request_context` will report the fallback state.
  - Context object values use the same `AttrValue` encoding as resource attributes. Flat strings, booleans,
    numbers, and arrays are accepted directly by the API model.

**Example request:**

```bash
curl -X POST http://localhost:9999/api/v1/authorize \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "id": "check-1",
        "context": {
          "env": { "type": "String", "value": "prod" }
        },
        "principal": { "User": { "id": "alice", "namespace": ["DNS"], "groups": [{ "id": "admins", "namespace": ["DNS"] }] } },
        "action": { "id": "create_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "hostname.example.com",
          "attrs": {
            "ip":   { "type": "Ip", "value": "10.0.0.1" },
            "name": { "type": "String", "value": "hostname.example.com" }
          }
        }
      },
      {
        "id": "check-2",
        "principal": { "User": { "id": "bob", "namespace": ["Service"], "groups": [] } },
        "action": { "id": "view", "namespace": ["Service"] },
        "resource": {
          "kind": "Photo",
          "id": "photo.jpg",
          "attrs": {
            "owner": { "type": "String", "value": "alice" }
          }
        }
      }
    ]
  }'
```

**Response (brief, default):**

```json
{
  "results": [
    {
      "index": 0,
      "id": "check-1",
      "status": "success",
      "result": {
        "decision": "Allow",
        "policy_id": "default",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 1,
      "id": "check-2",
      "status": "success",
      "result": {
        "decision": "Deny",
        "policy_id": "",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 2,
      "id": "check-3",
      "status": "failed",
      "error": "Evaluation failed: invalid resource"
    }
  ],
  "version": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 2,
  "failed": 1
}
```

**Response (detailed, ?detail=full):**

```json
{
  "results": [
    {
      "index": 0,
      "id": "check-1",
      "status": "success",
      "result": {
        "policy": [
          {
            "literal": "permit (...)",
            "json": {...}
          }
        ],
        "decision": "Allow",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 1,
      "id": "check-2",
      "status": "success",
      "result": {
        "policy": [],
        "decision": "Deny",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    }
  ],
  "version": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 2,
  "failed": 0
}
```

### Features

- **Single or Multiple Requests**: Handle one or many authorization requests in a single call
- **Client Identifiers**: Optional `id` field on each request for easy correlation of responses
- **Parallel Processing**: All requests evaluated in parallel using Rayon
- **Consistent Snapshot**: All requests evaluated against the same policy version
- **Detailed or Brief Results**: Control response verbosity with the `?detail` query parameter
- **Index Tracking**: Results maintain input order with `index` field

### Performance Considerations

1. **Parallel Execution**: Requests are processed in parallel across available CPU cores using Rayon
2. **Lock Management**: The policy store lock is acquired once and released before parallel processing begins
3. **Engine Snapshot**: A snapshot of the PolicyEngine is cloned for consistent evaluation

### Best Practices

1. **Batch Size**: Keep each batch within the server's configured maximum and tune batch size for the available capacity
2. **Error Handling**: Check both the HTTP status code and individual result statuses
3. **Consistency**: All requests in a batch are guaranteed to be evaluated against the same policy version
4. **Indexing**: Use the `index` field or your results to correlate responses with requests,
or use the optional `id` field for easier tracking
5. **Runtime visibility**: Inspect `/api/v1/status.request_context` to see whether evaluation is currently schema-backed
   or in permissive fallback mode
