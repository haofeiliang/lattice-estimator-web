# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 node:24-bookworm-slim AS frontend-builder

WORKDIR /build/frontend
RUN corepack enable && corepack prepare pnpm@11.21.0 --activate
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM --platform=linux/amd64 rust:1.97.1-bookworm AS backend-builder

WORKDIR /build
COPY rust-toolchain.toml ./
COPY backend/Cargo.toml backend/Cargo.lock backend/
COPY backend/src/ backend/src/
RUN cargo build --locked --release --manifest-path backend/Cargo.toml \
    --bin lattice-estimator-web --bin lattice-estimator-cli

FROM --platform=linux/amd64 debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="lattice-estimator-web" \
      org.opencontainers.image.description="Lattice estimator Web UI, API, scheduler, and SQLite state"

RUN groupadd --system --gid 10001 lattice-estimator \
    && useradd --system --uid 10001 --gid lattice-estimator \
      --home-dir /nonexistent --shell /usr/sbin/nologin lattice-estimator \
    && mkdir -p /var/lib/lattice-estimator-web \
    && chown lattice-estimator:lattice-estimator /var/lib/lattice-estimator-web

COPY --from=backend-builder /build/backend/target/release/lattice-estimator-web /usr/local/bin/lattice-estimator-web
COPY --from=backend-builder /build/backend/target/release/lattice-estimator-cli /usr/local/bin/lattice-estimator-cli
COPY --from=frontend-builder /build/frontend/dist/ /usr/share/lattice-estimator-web/frontend/

ENV LATTICE_ESTIMATOR_WEB_BIND=0.0.0.0:8080 \
    LATTICE_ESTIMATOR_WEB_DATABASE=/var/lib/lattice-estimator-web/data.db \
    LATTICE_ESTIMATOR_WEB_FRONTEND_DIR=/usr/share/lattice-estimator-web/frontend \
    LATTICE_ESTIMATOR_API_URL=http://estimator-api:8000/ \
    RUST_LOG=info

EXPOSE 8080
VOLUME ["/var/lib/lattice-estimator-web"]
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["lattice-estimator-web", "healthcheck"]

ENTRYPOINT ["lattice-estimator-web"]
