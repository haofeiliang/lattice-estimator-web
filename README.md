# lattice-estimator-web

Rust backend and Svelte frontend for managing lattice-estimator runs. The
browser communicates only with the Rust backend; Sage remains isolated in the
separate `lattice-estimator-api` service.

The adaptive slow-attack scheduler uses applicability rule v4, the Arora-GB v6
threshold screen, and the BKW v5 estimate. Reviewed minimum margins are 64/10
bits for the Arora coarse/refined tiers and 10 bits for BKW. The bounded-error
domain covers centered binomial eta 1 through 8 and symmetric uniform integer
radii 1 through 8. Unknown, mismatched, and out-of-domain results run the exact
attack.

## Repository layout

- `backend/`: HTTP API, scheduler, SQLite state, cache, schemas, and tests.
- `frontend/`: Svelte application managed with pnpm.
- `schemas/`: generated v2 parameter-set and security-report JSON Schemas.
- `examples/`: importable parameter sets and public request/report examples.
- `compose.yaml`: pull and run published GHCR images.
- `compose.local.yaml`: build and test both sibling repositories locally.

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

Build only the combined backend/frontend image:

```bash
docker compose -f compose.local.yaml build estimator-web
```

## Run published images

`compose.yaml` contains no source builds. It directly pulls the latest published
API and Web images from `ghcr.io/haofeiliang`:

```bash
cp .env.example .env
docker compose pull
docker compose up -d
```

Open <http://127.0.0.1:8080>. Stop the published stack without deleting its
database:

```bash
docker compose down
```

## Test local source builds

Keep `lattice-estimator-api` and `lattice-estimator-web` next to each other in
the same parent directory. `compose.local.yaml` builds both `:local` images,
uses a separate Compose project and volume, and listens on port 8081 by default:

```bash
docker compose -f compose.local.yaml up -d --build
```

Open <http://127.0.0.1:8081>. Stop it while retaining local test data:

```bash
docker compose -f compose.local.yaml down
```

Stop it and delete the local test containers, network, and database volume:

```bash
docker compose -f compose.local.yaml down --volumes --remove-orphans
```

The local images remain available for faster rebuilds. Remove them explicitly
when they are no longer needed:

```bash
docker image rm lattice-estimator-web:local lattice-estimator-api:local
```

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

The local Compose file additionally accepts `LATTICE_ESTIMATOR_LOCAL_HOST`
(default `127.0.0.1`) and `LATTICE_ESTIMATOR_LOCAL_PORT` (default `8081`).
