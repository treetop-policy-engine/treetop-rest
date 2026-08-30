# Security

This guide describes Treetop REST's security boundaries and recommended production deployment. The exact flags and
environment variables remain documented in [configuration](config.md), while endpoint behavior remains documented in
the [API reference](api.md).

## Security model

Treetop REST evaluates policies, exposes active policy metadata and content, and can optionally replace policy state.
Its built-in controls provide network admission, upload authentication, bounded request processing, artifact
validation, and bundle-signature verification. They are not a user identity system or a substitute for transport
security, rate limiting, or deployment authorization.

The operator is responsible for:

- controlling server configuration, trusted public-key files, remote source URLs, and access to logs;
- terminating TLS before requests reach the server when traffic leaves loopback;
- restricting network access to operational and documentation endpoints when their public behavior is unsuitable;
- protecting and rotating access credentials and private bundle-signing material; and
- controlling policy and bundle rollout, including freshness and rollback decisions.

The server binds to `127.0.0.1:9999` by default. If it is bound to a non-loopback address, admission is still open unless
an allowlist or access token is configured.

| Surface | Default | Built-in protection |
| --- | --- | --- |
| `/api/v1/**` | Open | Optional client allowlist and Bearer access tokens. |
| `/metrics` | Open | The same optional allowlist and Bearer controls. |
| `/livez`, `/readyz` | Public | Always bypass application admission. |
| OpenAPI JSON and `/swagger-ui/**` | Public | Always bypass application admission. |
| Policy, schema, and bundle uploads | Disabled | Must be enabled and require the generated upload token. |

Unknown routes outside `/api/v1/**` also bypass admission before returning their normal response. Apply ingress or
network policy when every HTTP path must be private.

## Network transport and perimeter

The server listens with plain HTTP and does not terminate TLS. Keep the default loopback bind or place it behind a
trusted TLS-terminating reverse proxy or service mesh. Bearer and upload credentials must not cross an unencrypted
non-loopback connection.

Treetop REST does not provide request-rate limiting, per-credential quotas, per-route credential scopes, or a CORS
policy. Configure those at the ingress when needed. All configured access tokens grant the same admission authority on
every protected endpoint, including `/metrics`; they do not identify a user or tenant. Uploads still require their
additional upload credential.

The public probes return only `ok` or `not ready`, and the public documentation surfaces describe the API. Restrict
them at the ingress if even this availability or interface information is sensitive.

Remote source URLs appear in metadata and operational logs. Do not put passwords, tokens, or other secrets in URL
userinfo or query strings. Use HTTPS and a trusted, access-controlled origin. The server has no separate configuration
for remote-request authentication headers.

## Client admission

Admission applies to `/api/v1/**` and `/metrics`. When both the allowlist and access tokens are configured, the client
IP check runs first and both checks must pass.

### Client allowlist

`TREETOP_CLIENT_ALLOWLIST` accepts IPv4 or IPv6 addresses and CIDRs. Bare addresses become host networks. Unset, blank,
or `*` means open; a wildcard cannot be combined with other entries.

Use the narrowest networks that contain the expected clients. An ACL denial or an unresolved client address returns
`403 Forbidden`. An IP allowlist is a network boundary, not caller identity, and should normally be combined with
access tokens.

### Trusted proxies

The socket peer is the client address unless it matches `TREETOP_TRUSTED_PROXIES`. Only then does the server consider
`X-Forwarded-For`. It walks the chain from the trusted socket peer toward the client and selects the rightmost
untrusted address. Forwarding headers from any other peer are ignored; malformed trusted chains fail closed when an ACL
requires a resolved address.

List only proxy addresses or networks that can directly precede the server. Configure the edge proxy to remove or
sanitize inbound forwarding headers before appending its own value. Never trust an unnecessarily broad proxy network,
because a client able to connect from that network can influence client-IP resolution.

### Bearer access tokens

`TREETOP_ACCESS_TOKENS` is an environment-only comma-separated list of opaque Bearer tokens. Unset or blank disables
token admission. Tokens are validated at startup, deduplicated as SHA-256 digests, and compared across the complete
configured digest set without early-exit equality. The server logs only the token count, not their values.

Access tokens are static until restart and have no identity, scope, expiry, or management API. Generate high-entropy
values with a secret-management system, restrict access to the process environment, and transmit them only over TLS.
Rotate without downtime by configuring old and new tokens together, restarting, migrating clients, and removing the
old token during a later restart.

Missing, malformed, duplicated, and invalid `Authorization` headers return the same `401 Unauthorized` response with
`WWW-Authenticate: Bearer`.

## Upload authorization

Uploads are disabled by default. When `TREETOP_ALLOW_UPLOAD=true`, each server process generates a new upload token at
startup, stores it in memory, and writes it to the warning log. Protect that log as secret material. Restarting the
process invalidates the previous upload token.

An upload must pass the client ACL and Bearer admission when those controls are enabled, and must also provide the
current token in `X-Upload-Token`. The upload token is an additional capability; it does not replace the global access
token. Global admission runs before handler extraction. Bundle uploads check the upload token before streaming the
payload, and every upload handler rechecks authorization before validated state is applied.

Each replica generates a different token and maintains independent policy state. Direct uploads through an arbitrary
load balancer therefore do not provide a coordinated multi-replica rollout. Prefer a controlled remote source,
especially a signed bundle, for replicated deployments. If direct uploads are unavoidable, target and verify every
replica explicitly.

## Remote policy sources

Policy, label, and schema URLs load independent components. Bundle URL mode instead loads the complete policy, schema,
and label state atomically and is mutually exclusive with those component URLs.

A remote load becomes ready only after a successful `GET` body has been validated and applied. A `HEAD`, `304 Not
Modified`, content hash, or local upload does not establish the initial remote load. After the first successful load,
later failures retain the last-known-good state and do not make the instance unready. Monitor reload-failure metrics
and logs because readiness alone does not detect stale content.

Independent policy, label, and schema responses are not signed by Treetop REST. Protect their integrity with HTTPS,
origin access controls, and deployment-level change controls. Bundle size limits do not bound these independent remote
responses, so their origins should also enforce appropriate response-size limits.

Use `TREETOP_SCHEMA_VALIDATION_MODE=strict` when every policy state must have a compatible schema. Permissive mode can
continue with schema-free or schema-incompatible fallback behavior where documented.

## Bundles and signatures

Use the [`treetop-bundle` CLI](https://github.com/treetop-policy-engine/treetop-bundle/blob/v0.0.6/README.md) to validate,
build, and optionally sign deterministic bundle archives.

`TREETOP_BUNDLE_SIGNATURE_POLICY` controls signature enforcement:

- `allow-unsigned` is the default and accepts unsigned bundles. If a signature is present, it must still be valid and
  trusted; malformed, invalid, or untrusted signatures are never downgraded to unsigned content.
- `required` rejects unsigned bundles. Startup fails unless at least one trusted public key is configured.

Production deployments that rely on bundle provenance should use `required` with
`TREETOP_BUNDLE_TRUSTED_KEYS`. The trust store accepts Ed25519 SPKI PEM public keys, supports multiple keys for rotation,
and is loaded once at startup. Invalid key files or conflicting duplicate key IDs fail startup; changing the trust store
requires a restart.

Private signing keys and passphrases belong only on the bundle-build system. Treetop REST has no private-key setting
and never loads private signing material. `treetop-bundle` 0.0.6 can load password-encrypted PKCS#8 private keys; that
feature is unnecessary in the REST service and does not affect verification of the resulting Ed25519 signature.

A signature authenticates bundle bytes and protects their integrity. It does not encrypt bundle content, hide policy
metadata, or prove that a valid bundle is the newest authorized version. Treetop REST does not use a signature as an
anti-replay or rollback mechanism. Secure the fetch and upload paths, retain rollout records, and compare the active
bundle ID and signing key ID with the intended deployment.

The status response reports whether the active bundle carried a verified signature and identifies its trusted key.
Archive and content hashes identify bytes but are not trust decisions by themselves.

## Validation and resource limits

Fetched and uploaded bundles are decoded, signature-checked, and semantically validated before they replace live state.
Policy, schema, and label state is applied atomically. A rejected update leaves the last-known-good engine and metadata
available. Strict schema mode also requires every bundle to contain a schema.

Configure limits according to expected workloads:

- `TREETOP_MAX_REQUEST_SIZE` bounds incoming JSON, text, and bundle request bodies.
- `TREETOP_MAX_BUNDLE_COMPRESSED_BYTES` bounds fetched and uploaded compressed bundles.
- `TREETOP_MAX_BUNDLE_UNCOMPRESSED_BYTES` bounds total decoded bundle content.
- Bundle uploads use the lower of the global request limit and compressed-bundle limit.
- Context byte, depth, and key limits bound per-request context.
- `TREETOP_MAX_BATCH_SIZE` bounds authorization checks in one request.

These limits reduce memory, decompression, parsing, and evaluation abuse, but they are not a substitute for ingress
rate limiting and connection limits.

## Information exposure and logs

Protected API responses can include full policy, schema, and label content as well as source URLs, hashes, bundle IDs,
and signing key IDs. `/metrics` includes operational data such as action names and a compatibility counter labeled with
client IP. Configure admission and restrict observability consumers accordingly.

Normal request logs include the method, raw path, resolved or peer client IP, generated request ID, and a caller-supplied
or generated correlation ID. Request bodies, Bearer tokens, and private signing keys are not logged. Do not place
secrets in URL paths or correlation IDs. The generated upload token is the deliberate startup-log exception described
above.

Remote fetch logs include source URLs, and bundle events can include bundle IDs, hashes, and signing key IDs. Treat logs
and status metadata as operationally sensitive even when they contain no private key material.

## Probes and stale-state monitoring

`/livez` reports only process and HTTP-worker liveness. `/readyz` checks local store access and whether every configured
remote source has completed its first validated load; it makes no network call.

Once initialized, the server deliberately stays ready and serves last-known-good content after a remote failure. Alert
on `bundle_reload_failures_total`, schema validation failures, fetch-loop errors, and unexpected bundle or content
identities. Use readiness for traffic routing, not as the only content-freshness monitor.

## Hardened deployment example

The following is illustrative. Replace networks, paths, limits, URL, and token with deployment-specific values; do not
use the placeholder credential literally.

```text
TREETOP_LISTEN=127.0.0.1
TREETOP_PORT=9999
TREETOP_CLIENT_ALLOWLIST=10.20.0.0/16
TREETOP_TRUSTED_PROXIES=127.0.0.1,::1
TREETOP_ACCESS_TOKENS=<high-entropy-secret-from-secret-manager>
TREETOP_ALLOW_UPLOAD=false
TREETOP_BUNDLE_URL=https://policy-origin.example/production.tar.gz
TREETOP_BUNDLE_SIGNATURE_POLICY=required
TREETOP_BUNDLE_TRUSTED_KEYS=/run/secrets/bundle-current.pem,/run/secrets/bundle-next.pem
TREETOP_SCHEMA_VALIDATION_MODE=strict
TREETOP_MAX_REQUEST_SIZE=10485760
TREETOP_MAX_BUNDLE_COMPRESSED_BYTES=10485760
TREETOP_MAX_BUNDLE_UNCOMPRESSED_BYTES=52428800
```

The reverse proxy should terminate TLS, sanitize `X-Forwarded-For`, enforce rate and connection limits, restrict public
operational/documentation paths as required, and forward only from an address listed in `TREETOP_TRUSTED_PROXIES`.
Mount trusted public keys read-only. Do not mount bundle private keys into the REST container.

## Rotation and compromise response

### Access token

Add a replacement token alongside the old token, restart, migrate clients, then remove the old token and restart again.
For an active compromise, remove the old token immediately and restart every replica.

### Upload token

Restart the affected process to generate a replacement, then secure or expire any logs containing the old token. Audit
policy state for unauthorized uploads.

### Bundle signing key

Add and deploy a replacement public key, restart, sign and publish with the replacement private key, and verify the
reported signing key ID before removing the old public key in a later restart. If the old private key is compromised,
remove its public key from every trust store immediately and block untrusted upload or source paths during recovery.
Previously signed content remains acceptable anywhere the compromised public key is still trusted.

### Remote source

Block or replace the source, preserve the last-known-good artifact for investigation, and compare active hashes and
bundle identity with deployment records. Component URLs have no application-level signatures; a compromised component
origin requires transport and rollout remediation. For bundle sources, require signatures from a separately protected
key.
