# Two binaries share this image: `api` serves requests, `runner` executes
# queued scan jobs. They are deployed as separate Fly processes (see
# fly.toml) from the same build so there is only one artifact to keep in
# sync between them.

FROM rust:1-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY migrations migrations

# sqlx's compile-time query checking normally needs a live database; a
# checked-in .sqlx cache (via `cargo sqlx prepare`) avoids that requirement
# during the container build. If none exists yet, this build must run with
# DATABASE_URL pointing at a reachable database instead.
RUN cargo build --release --bin api --bin runner

# --- the frontend ------------------------------------------------------

# TypeScript straight to ES modules, no bundler: the app is a handful of
# files the browser can load as they are, and a build step is a thing that
# breaks for no benefit at this size.
FROM node:22-bookworm-slim AS web

WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/tsconfig.json ./
COPY web/src src
RUN npx tsc

# --- runtime -----------------------------------------------------------

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Nuclei is the only scanner wired up so far (testssl/httpx/subfinder are
# not yet built — see the orchestrator's tool wrappers). Pinned rather than
# tracking latest, so a template-format change upstream can't break scans
# on a redeploy nobody triggered.
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
RUN curl -fsSL -o /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum --check --strict \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && apt-get purge -y unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Nuclei templates are fetched on first run and cached under this path;
# giving the scan runner its own unprivileged user and home directory
# keeps that cache (and everything else about the process) off the
# account that owns the image.
RUN useradd --system --create-home --home-dir /home/glarion glarion
WORKDIR /app
COPY --from=build /app/target/release/api /usr/local/bin/api
COPY --from=build /app/target/release/runner /usr/local/bin/runner

# The API serves these itself — see with_static_files. One origin for the
# page and the endpoints it calls means no CORS entry to maintain, and one
# thing to deploy instead of two.
COPY web/landing.html web/index.html web/privacy.html web/terms.html \
     web/robots.txt web/sitemap.xml web/site.webmanifest web/landing.js web/glarion-mark.png web/
COPY --from=web /web/dist web/dist

RUN chown -R glarion:glarion /app
USER glarion
ENV HOME=/home/glarion

# Overridden by fly.toml's per-process start_command; kept as a sane
# default for `docker run` outside Fly.
CMD ["/usr/local/bin/api"]
