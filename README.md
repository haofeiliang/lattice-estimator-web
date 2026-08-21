# lattice-estimator-web

Rust backend and Svelte frontend for managing lattice-estimator runs. The
browser communicates only with the Rust backend; Sage remains isolated in the
separate `lattice-estimator-api` service.

The adaptive slow-attack scheduler accepts matching rule-v5 preflight results
with one 10-bit floor per attack. Its reviewed bounded-error domain is centered
binomial eta 1 through 8 and symmetric uniform integer radii 1 through 8.
Arora-GB and BKW admit finite or unlimited samples there. Unknown, mismatched,
and out-of-domain results run the exact attack.

## Repository layout

- `backend/`: HTTP API, scheduler, SQLite state, cache, CLI, schemas, and tests.
- `frontend/`: Svelte application managed with pnpm.
- `schemas/`: generated v2 parameter-set and security-report JSON Schemas.
- `examples/`: importable parameter sets and public request/report examples.

## Development

```bash
cargo test --locked --manifest-path backend/Cargo.toml --all-targets
cargo clippy --locked --manifest-path backend/Cargo.toml --all-targets -- -D warnings
cargo run --locked --quiet --manifest-path backend/Cargo.toml \
  --bin lattice-estimator-schema -- --check

pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend check
pnpm --dir frontend build
```

Build the combined backend/frontend image:

```bash
docker build -t lattice-estimator-web:dev .
```

Build `lattice-estimator-api:dev` in its repository, then start both services:

```bash
docker compose up -d --build
```

Open <http://127.0.0.1:8080>.

## Releases

Pull requests run the Rust and frontend checks. Ordinary branch pushes do not
trigger CI. Pushing a semantic-version tag builds and smoke-tests the combined
image against a mock estimator API before publishing it to
`ghcr.io/<repository-owner>/lattice-estimator-web`:

```bash
git tag -a v0.1.0 -m "lattice-estimator-web v0.1.0"
git push origin v0.1.0
```

Every tag publishes its exact version and `sha-<commit>`. The highest stable
semantic version also publishes `latest` from the same image manifest. A
pre-release tag such as `v0.2.0-rc.1`, or a stable tag older than an existing
release, never updates `latest`.

## File formats

The maintained formats are `lattice-estimator/parameter-set` version 2 and
`lattice-estimator/security-report` version 2. Earlier experimental formats are
not accepted or migrated.

## Configuration

Copy `.env.example` to `.env` for Compose settings. Runtime variables include:

| Variable | Default |
| --- | --- |
| `LATTICE_ESTIMATOR_WEB_BIND` | `127.0.0.1:8080` |
| `LATTICE_ESTIMATOR_WEB_DATABASE` | `/var/lib/lattice-estimator-web/data.db` |
| `LATTICE_ESTIMATOR_WEB_FRONTEND_DIR` | `frontend/dist` in development |
| `LATTICE_ESTIMATOR_WEB_API_TOKEN` | empty |
| `LATTICE_ESTIMATOR_WEB_CASE_CONCURRENCY` | `2` |
| `LATTICE_ESTIMATOR_WEB_ESTIMATOR_CONCURRENCY` | `3` |
| `LATTICE_ESTIMATOR_API_URL` | `http://estimator-api:8000/` |
| `LATTICE_ESTIMATOR_WEB_URL` | `http://127.0.0.1:8080/` for the CLI |
