# Configuration

This document describes configuration for `treetop-server`.

See the [security guide](security.md) for deployment trust boundaries, hardening, and credential rotation.

## Overview

The server uses command-line flags and environment variables. Admission controls are environment-only. It does not use
a configuration file.
The standalone [treetop-cli](https://github.com/treetop-policy-engine/treetop-cli) has its own
configuration documentation and release lifecycle.

## Server configuration

The server uses **command-line flags** and **environment variables**. There is **no server config file**.

### Server option precedence

1. Command-line flags
2. Environment variables
3. Built-in defaults

### Options

| Flag | Environment variable | Default | Description |
| --- | --- | --- | --- |
| `--host` | `TREETOP_LISTEN` | `127.0.0.1` | IP address to bind the server to. |
| `--port` | `TREETOP_PORT` | `9999` | Port to listen on. |
| `--workers` | `TREETOP_WORKERS` | auto | Number of Actix worker threads (computed from available CPUs). |
| `--rayon-threads` | `TREETOP_RAYON_THREADS` | auto | Number of Rayon worker threads for batch evaluation (computed from available CPUs). |
| `--par-threshold` | `TREETOP_PAR_THRESHOLD` | auto | Batch size threshold to enable parallel evaluation (0 or unset = auto). |
| `--allow-upload` | `TREETOP_ALLOW_UPLOAD` | `false` | Allow uploading policies via the API. |
| `--policy-url` | `TREETOP_POLICY_URL` | _(none)_ | URL to fetch policies from (Cedar). |
| `--update-frequency` | `TREETOP_POLICY_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_POLICY_URL`. |
| `--labels-url` | `TREETOP_LABELS_URL` | _(none)_ | URL to fetch labels from (JSON). |
| `--labels-refresh` | `TREETOP_LABELS_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_LABELS_URL`. |
| `--schema-url` | `TREETOP_SCHEMA_URL` | _(none)_ | URL to fetch Cedar schema from (JSON). |
| `--schema-refresh` | `TREETOP_SCHEMA_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_SCHEMA_URL`. |
| `--schema-validation-mode` | `TREETOP_SCHEMA_VALIDATION_MODE` | `permissive` | Schema enforcement mode (`permissive` or `strict`) for policy/schema and bundle reloads. |
| `--bundle-url` | `TREETOP_BUNDLE_URL` | _(none)_ | URL to fetch a complete `.tar.gz` policy bundle from. |
| `--bundle-refresh` | `TREETOP_BUNDLE_UPDATE_FREQUENCY` | `60` | Poll interval for `TREETOP_BUNDLE_URL`, in seconds. |
| `--bundle-engine-mode` | `TREETOP_BUNDLE_ENGINE_MODE` | `monolithic` | Compile bundles as one policy set (`monolithic`) or derive namespace stores from ordinary modules (`bundle-modules`). |
| `--max-bundle-compressed-bytes` | `TREETOP_MAX_BUNDLE_COMPRESSED_BYTES` | `10485760` | Maximum compressed bundle size. |
| `--max-bundle-uncompressed-bytes` | `TREETOP_MAX_BUNDLE_UNCOMPRESSED_BYTES` | `52428800` | Maximum total uncompressed bundle size. |
| `--bundle-trusted-key` | `TREETOP_BUNDLE_TRUSTED_KEYS` | _(none)_ | Trusted Ed25519 SPKI PEM public key; repeat the flag or comma-separate environment paths. |
| `--bundle-signature-policy` | `TREETOP_BUNDLE_SIGNATURE_POLICY` | `allow-unsigned` | Accept unsigned bundles or require a trusted signature (`allow-unsigned` or `required`). |
| `--max-context-bytes` | `TREETOP_MAX_CONTEXT_BYTES` | `16384` | Maximum `/api/v1/authorize` request context payload size in bytes. |
| `--max-context-depth` | `TREETOP_MAX_CONTEXT_DEPTH` | `8` | Maximum nesting depth for `/api/v1/authorize` request context values. |
| `--max-context-keys` | `TREETOP_MAX_CONTEXT_KEYS` | `64` | Maximum number of top-level `/api/v1/authorize` request context keys. |
| `--max-batch-size` | `TREETOP_MAX_BATCH_SIZE` | `1024` | Maximum authorization checks accepted in one request. |
| _(none)_ | `TREETOP_CLIENT_ALLOWLIST` | open | Allowed client IPv4/IPv6 addresses and CIDRs. Blank or `*` is open. |
| _(none)_ | `TREETOP_ACCESS_TOKENS` | disabled | Comma-separated opaque Bearer tokens. |
| _(none)_ | `TREETOP_TRUSTED_PROXIES` | _(none)_ | Proxy IPv4/IPv6 addresses and CIDRs trusted to append `X-Forwarded-For`. |
| `--max-request-size` | `TREETOP_MAX_REQUEST_SIZE` | `10485760` | Maximum request body size in bytes. |
| `--version` | _(none)_ | `false` | Print version information and exit. |

#### Notes

- If `--policy-url` or `--labels-url` is provided, the server polls every 60 seconds unless the corresponding refresh
value is set.
- If `--schema-url` is provided, the server polls every 60 seconds unless `--schema-refresh` is set.
- `--bundle-url` is mutually exclusive with policy, label, and schema URLs. Bundle mode validates policies, schema, and
  labels together and atomically replaces the active state only after every check succeeds. Its refresh frequency must
  be greater than zero.
- `bundle-modules` is an explicit load-time optimization. Each ordinary bundle module supplies one store ID and
  namespace root; global-module policies are installed in every store. Store IDs and namespaces are taken only from a
  validated bundle, not from authorization request data. Overlapping namespaces, cross-store policies, and unroutable
  requests fail closed. A failed store build leaves the last-known-good engine active.
- The bundle archive remains format version 1. Both remote and uploaded bundles use the configured engine mode, which
  is included in successful bundle-application logs. Raw policy uploads and the legacy policy URL remain monolithic
  because they have no trusted module layout.
- Strict schema mode rejects every fetched or uploaded bundle that does not include a schema.
- Bundle uploads obey the lower of `--max-request-size` and `--max-bundle-compressed-bytes`.
- `allow-unsigned` accepts unsigned bundles, but any signature that is present must verify against a configured trusted
  key. `required` rejects unsigned bundles and fails startup unless at least one trusted key is configured. Invalid key
  files and conflicting duplicate key IDs also fail startup. Trusted keys are loaded once and require a restart to
  change.
- `--bundle-trusted-key` and `TREETOP_BUNDLE_TRUSTED_KEYS` accept public verification keys only. The server has no
  private signing-key or signing-key-password setting and never loads that material. Keep private keys and passphrases
  on the bundle-build system and use the `treetop-bundle` CLI to sign archives before REST fetches or receives them.
- Legacy label documents use the same strict parser as bundles. When a schema is active, label kinds and input/output
  attribute types must be compatible with it, independent of the policy/schema permissive fallback mode.
- The context limit settings apply to the optional `context` object accepted by `POST /api/v1/authorize`.
- The batch size limit applies to the `requests` array accepted by `POST /api/v1/authorize`; larger batches receive
  `400 Bad Request` before policy evaluation begins.
- Histogram boundaries are intentionally fixed across server instances rather than configurable. Native histogram
  selection is controlled by Prometheus content negotiation and scrape settings; see
  [the metrics API reference](api.md#get-metrics).

## Admission controls

Admission applies to `/api/v1/**` and `/metrics`. It does not apply to `/livez`, `/readyz`, `/openapi.json`,
`/api-docs/openapi.json`, or `/swagger-ui/**`.

| `TREETOP_CLIENT_ALLOWLIST` | `TREETOP_ACCESS_TOKENS` | Result |
| --- | --- | --- |
| unset, blank, or `*` | unset or blank | Open; no admission middleware is installed. |
| addresses/CIDRs | unset or blank | ACL-only. |
| unset, blank, or `*` | tokens | Token-only. |
| addresses/CIDRs | tokens | ACL first, then Bearer token; both must pass. |

Bare addresses become host networks (`/32` for IPv4 and `/128` for IPv6). Lists reject invalid networks, empty entries,
and a wildcard mixed with other allowlist entries. Access tokens use the Bearer `b64token` character set and are held
only as unique SHA-256 digests. The server neither generates nor logs access tokens. All tokens have equal authority and
remain fixed until restart.

Use `Authorization: Bearer <token>` for protected requests. A missing, malformed, duplicated, or invalid authorization
header receives the same `401 Unauthorized` JSON error and `WWW-Authenticate: Bearer`; ACL denial or an unresolved
client address receives `403 Forbidden`. When uploads are enabled, upload requests need both the global Bearer token
and the separately generated `X-Upload-Token`.

Bearer credentials require HTTPS outside loopback. If terminating TLS at a reverse proxy, configure the socket peers
that may contribute forwarding information in `TREETOP_TRUSTED_PROXIES`. The server ignores forwarding headers from
every other peer, supports only `X-Forwarded-For`, and walks trusted chains from right to left. Malformed trusted chains
fail closed when the ACL needs a resolved client.

Rotate credentials without downtime by adding the new token alongside the old one, restarting, migrating every
consumer, and removing the old token during a later restart. Direct cross-origin browser access additionally requires
CORS permission for the `Authorization` header. Shared credentials should instead be injected by a trusted production
ingress when all users of that ingress may inherit the same authority.

### Breaking migration

The allowlist default is now open rather than `127.0.0.1,::1`. To retain the previous behavior, set:

```bash
TREETOP_CLIENT_ALLOWLIST=127.0.0.1,::1 treetop-server
```

`--client-allowlist`, `--trust-ip-headers`, and `TREETOP_TRUST_IP_HEADERS` were removed. Move the allowlist to
`TREETOP_CLIENT_ALLOWLIST` and replace blanket header trust with explicit `TREETOP_TRUSTED_PROXIES` entries.

## Summary

General server configuration comes from flags, then environment variables, then built-in defaults; admission settings
come only from environment variables. For CLI configuration—including `--server-url`, config/history paths, and legacy
host/port migration—see the [standalone CLI configuration
guide](https://github.com/treetop-policy-engine/treetop-cli/blob/main/docs/config.md).
