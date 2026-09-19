# Breaking 0.1.0 migration

Upgrade Core, Bundle, REST, SDKs, CLI, and frontend together. Early releases
prioritize correctness and a strict current contract over compatibility.

## Declared label targets

Every rule owns one exact `(fully qualified Cedar resource type, attribute)`:

```json
[
  {
    "target": {"resource_type": "App::Host", "attribute": "labels"},
    "field": "name",
    "patterns": [{"name": "prod", "regex": "^prod"}]
  }
]
```

Replace rule-level `kind` and `output` with `target.resource_type` and
`target.attribute`. Wildcards, missing or unknown fields, invalid Cedar types,
reserved `id`, and duplicate tuples fail validation. Different exact types may
own the same attribute name. Core enforces scope and clears all outputs owned
on the actual type before any labeler derives a value. Other types remain
unchanged. Policies must constrain resource types before trusting derived labels.

Set bundle and module manifests to `format_version = 2`, rebuild archives, and
re-sign them. Format 1 is rejected. REST uses Bundle's parser and Core's ownership
rules; a failed reload leaves the active policies, schema, labels, and version
intact. Existing sessions retain their complete original generation.

## HTTP and clients

- Replace `/api/v1/health` with `/livez` for liveness and `/readyz` for readiness.
- Replace `/api-docs/openapi.json` with `/openapi.json`.
- Require `hash`, `loaded_at`, `label_set`, and `generation` in every policy version.
  `label_set` can be null; `generation` is an unsigned 64-bit integer.
- Require status `request_limits` and `request_context`; `max_batch_size` is present.
- Regenerate client types from the checked-in OpenAPI and upgrade all SDKs.

## Published dependencies

The published REST 0.1.0 release requires Core 0.1.0 and Bundle 0.1.0 from crates.io.
Both the application and
fuzz lockfiles use registry sources without candidate Git patches. Release Core,
then Bundle, then REST before upgrading SDKs and their consumers.

The version endpoint reports REST and Core package versions without a `v` prefix
or Git description suffix. Policy versions require all four state fields; the
optional schema revision is a distinct object with only `hash` and `loaded_at`.

## Core 0.2 and Cedar 4.13 dependency refresh

Rebuild and re-sign policy archives using Bundle CLI 0.2.0 before deploying the
updated server. Archives must match Bundle 0.2.0, Core 0.2.0, and Cedar 4.13.0
generator metadata; do not edit signed archives. Manifest and signature format
version 2 and declared label targets are unchanged. Consumers that inspect Cedar
policy JSON must handle an array-valued `attr` for nested `has` expressions.
