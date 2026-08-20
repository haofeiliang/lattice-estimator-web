# lattice-estimator-web

Rust backend and Svelte frontend for managing lattice-estimator runs. The
browser communicates only with the Rust backend; Sage remains isolated in the
separate `lattice-estimator-api` service.

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

## File formats

The maintained formats are `lattice-estimator/parameter-set` version 2 and
`lattice-estimator/security-report` version 2. Convert an exported v1 file
without overwriting it:

```bash
cargo run --locked --manifest-path backend/Cargo.toml \
  --bin lattice-estimator-migrate -- old.json > migrated.json
```

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

The project builds local images only and contains no registry publishing job.
