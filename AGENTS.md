# Repository Guidelines

## Early-release contract

Prefer correctness and strict, uniform project contracts over compatibility.
Remove deprecated APIs and obsolete aliases when replacing a contract; document
breaking changes and concrete migration steps. Label rules must use Bundle’s
Core-validated declared targets. Coordinated PRs may pin exact unmerged dependency
revisions for verification; publication and merging require user approval.

## Verification

- Use targeted tests while iterating, then run the complete test suite before considering a change complete:
  `cargo test --verbose`.
- Format every Rust file you edit with `rustfmt`, then review the diff to avoid unrelated repository-wide formatting
  churn.
- Run the same Clippy check enforced by CI: `cargo clippy --verbose`.
- Run `cargo build --verbose` when changing dependencies, features, build metadata, binaries, or container inputs.
- Tests should not require Docker or external services. Use an in-process Actix server bound to an ephemeral loopback port
  when HTTP behavior must be exercised.
- Run Markdown lint after documentation changes:
  `npx markdownlint-cli2 --config .markdownlint.json "**/*.md" "!target"`.
- When an endpoint, request, response, or configuration option changes, update the relevant Utoipa annotations and the
  hand-maintained documentation in `README.md` and `docs/`.
- For container-affecting changes, run `docker build .` in addition to the Rust checks.

## Project Layout

- `src/bin/server.rs` composes the Actix application, shared state, middleware, background fetchers, Swagger UI, and
  runtime configuration. Keep domain behavior out of the binary.
- `src/handlers.rs` owns route registration, HTTP handlers, response shapes local to handlers, and the Utoipa
  `ApiDoc` path list.
- `src/state.rs` owns `PolicyStore`, policy/label/schema metadata, validation, engine replacement, and readiness state.
- `src/fetcher/` owns periodic remote loading. Keep transport and conditional-request behavior in `generic.rs`; keep
  policy-, label-, and schema-specific application logic in their adapters.
- `src/models.rs` contains shared API and domain-facing data types. `src/errors.rs` is the HTTP error surface.
- `src/config.rs` owns server CLI and environment configuration. Keep `README.md` and `docs/config.md` synchronized
  with it.
- `src/middleware.rs`, `src/metrics.rs`, and `src/parallel.rs` own their respective cross-cutting concerns.
- `src/cli/` owns client commands, persistence, parsing, completion, rendering, and API calls. Keep server API changes
  compatible with the CLI or update both in the same change.
- Unit tests live beside the code under `src/`; cross-module and HTTP tests live in `tests/`; reusable fixtures live
  in `testdata/`.

## API Conventions

- Put public application endpoints under `/api/v1`. Root-level paths are reserved for operational surfaces such as
  `/livez`, `/readyz`, `/metrics`, Swagger UI, and the OpenAPI document.
- Register each new endpoint in `handlers::init`, add its Utoipa annotation and `ApiDoc` entry, document it in
  `docs/api.md`, and add handler-level tests.
- Use `ServiceError` for fallible API operations so status codes and error bodies remain consistent. Return an
  explicit `HttpResponse` only when the endpoint intentionally controls media type or status directly.
- Apply validation and request-size limits at the HTTP boundary. Keep authorization request limits in
  `AuthorizeRuntimeConfig` and global body limits in the Actix application configuration.
- Preserve upload authorization semantics: uploads require both `TREETOP_ALLOW_UPLOAD=true` and the matching
  `X-Upload-Token`.
- Keep operational probes cheap and deterministic. `/livez` reports process liveness without dependencies;
  `/readyz` inspects local state without network calls or blocking for a lock. Do not fold dependency checks into
  liveness.
- Avoid high-cardinality Prometheus labels. Update metrics tests whenever endpoint or label behavior changes.

## State And Remote Fetching

- `SharedPolicyStore` is shared across Actix workers and background fetchers. Keep `RwLock` critical sections short,
  never hold a lock across `.await`, and propagate lock failures through `ServiceError` in request handlers.
- Validate new policies, labels, and schemas completely before replacing live state. A rejected update must leave the
  last-known-good engine and metadata usable.
- Remote fetches are successful only after a 2xx `GET` body has been validated and applied. A successful `HEAD`, a
  metadata hash, a manual upload, or merely parseable content from an error response must not mark a configured
  remote source as loaded.
- Readiness tracks the initial successful load of every configured remote source explicitly. Later fetch failures
  should retain last-known-good content and must not unnecessarily make an already initialized instance unready.
- Preserve policy/schema consistency in both strict and permissive validation modes. Rebuild the engine through the
  existing `PolicyStore` paths rather than mutating related metadata independently.
- Keep conditional request metadata and content hashes as fetch optimizations, not as proof that remote
  initialization succeeded.

## Rust Standards

- Follow idiomatic Rust and the conventions already present in the surrounding module. Prefer clear, explicit code
  over clever abstractions.
- Keep invariants close to the data they protect. Use validating constructors and project-owned types such as
  `Endpoint` instead of passing unchecked primitives through the application.
- Keep public interfaces small. Add behavior to the type that owns the relevant state rather than creating loosely
  related helper functions.
- Prefer `use` imports over repeated inline fully qualified paths, except where qualification resolves ambiguity.
- Use conventional Rust module discovery (`foo.rs` or `foo/mod.rs`); do not introduce `#[path = "..."]` overrides.
- Do not add dead code, unused fields, or broad `#[allow(...)]` attributes to silence compiler or test failures.
- Use structured `tracing` fields for operational diagnostics. Do not add logging of request bodies or secrets. The
  generated upload token's startup warning is an existing delivery mechanism; change it only with a coordinated
  replacement and documentation update.
- Keep asynchronous request paths free of blocking I/O. Use the existing Rayon boundary for CPU-heavy batch
  evaluation.

## Tests

- Add a regression test for every bug fix and focused tests for every behavior change.
- Prefer `rstest` cases when one behavior varies only by input. Keep each test focused on one contract rather than
  accumulating unrelated assertions.
- Use Actix test utilities for handlers and temporary loopback servers for fetcher transport behavior. Do not depend
  on public network services, fixed ports, timing races, or execution order.
- Exercise both success and failure paths at state boundaries: invalid content must not replace live state, non-2xx
  responses must not be applied, and local uploads must not impersonate successful remote loads.
- Reuse `testdata/default.cedar`, `testdata/dns.cedar`, and `testdata/labels.json` where they represent the scenario;
  keep small behavior-specific fixtures inline when that makes the contract clearer.
- Update `tests/README.md` when the suite structure or testing workflow materially changes.

## Benchmarks

- Put Gungraun entrypoints in `benches/` and add a matching `[[bench]]` entry to `Cargo.toml` with
  `harness = false`.
- Keep one benchmark target per file and use the `_callgrind` suffix so the performance workflow can discover and fan
  out targets independently.
- Prefer deterministic library-level benchmarks. Avoid network access, fixed ports, global mutable configuration,
  and setup work inside the measured region.
- Treat a reported regression above the workflow threshold as something to explain or fix, not as a check to bypass.

## Container Builds

- The Docker build has a restricted explicit context: `Cargo.toml`, `Cargo.lock`, `src/`, `build.rs`, `benches/`, and
  `testdata/`. If compilation begins to depend on another path, update the relevant `COPY` instruction in the same
  change.
- A normal host build is not a substitute for `docker build .`; the host can see files that are absent from the image
  build context.
- Preserve the non-root runtime user and keep the runtime image limited to required packages.
- Keep the container health check pointed at `/readyz`. Readiness is the correct signal for routing or restarting a
  container that requires configured remote content before serving traffic.

## Documentation And Changelog

- `docs/api.md` is the human-readable API reference; the runtime OpenAPI document is derived from Utoipa annotations.
  Keep both representations aligned with code.
- Document server configuration in both `README.md` and `docs/config.md`; document CLI behavior in the most relevant
  README or `docs/` page.
- Review `Changelog.md` for every pull request. Add user-facing additions, changes, fixes, and security notes under an
  `[Unreleased]` section, creating it when necessary. If no changelog entry is warranted, state that in the pull
  request description.
- Call out breaking changes explicitly in the changelog and pull request, including the migration action users must
  take.
- Every fenced Markdown block must declare a language; use `text` for plain output or diagrams.

## Pull Requests And Commits

- Keep changes scoped and avoid unrelated formatting, dependency, or refactoring churn.
- Add tests with behavior changes and update documentation in the same pull request.
- Commit `Cargo.lock` whenever dependency resolution changes. Do not commit `target/` or local runtime artifacts.
- Sign every commit. Keep repository signing configuration enabled and do not bypass it with `--no-gpg-sign`.
- Write pull request descriptions that explain the behavior, rationale, compatibility impact, and validation performed.
- Before merging, resolve actionable review threads and verify required checks on the final head commit.
- Squash-merge ordinary pull requests. Use the detailed pull request description as the squash commit body. Preserve
  the substantive summary, rationale, behavior notes, and issue references, but remove verification-only sections
  such as test commands, checklists, and `## Verification` before merging.

## Releases

- Before preparing a release commit, update all Rust dependencies and GitHub Actions to their latest stable versions,
  and pin every Action to its full commit SHA. Refresh `Cargo.lock`, review upstream release notes for compatibility
  and MSRV changes, and complete the repository's full verification and security checks on the resulting dependency
  set before tagging the release.
- Land dependency and GitHub Actions updates before the version-bump release commit so the signed release tag points
  at a green commit that already contains every update.

## Change Discipline

- Preserve backward compatibility unless the task explicitly requires a breaking change.
- Prefer the smallest coherent change that fully solves the problem.
- Do not weaken validation, authorization, readiness, error handling, or tests merely to make a check pass.
- When behavior spans server, CLI, documentation, metrics, and container operation, review each affected surface before
  considering the change complete.
