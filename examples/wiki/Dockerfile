# syntax=docker/dockerfile:1.7
#
# Wolfi-based image (Chainguard's distro) for the wiki reference app.
#
# Build context = repo root, not examples/wiki/. The wiki package.json
# declares "@blamejs/core": "file:../..", so the framework source has
# to be reachable from the wiki directory at install time. Compose
# in this directory sets context: ../.. accordingly.
#
# Two stages:
#   - builder uses cgr.dev/chainguard/node:latest-dev (shell + npm
#     for the install-links resolve)
#   - runtime uses cgr.dev/chainguard/node:latest (no shell, drops
#     to the nonroot user, minimal attack surface)
#
# The vendored Argon2id native module ships glibc prebuilds; Wolfi is
# glibc-based so the existing prebuilds load without rebuild.

FROM cgr.dev/chainguard/node:latest-dev AS deps
WORKDIR /build
USER root
COPY package.json index.js NOTICE LICENSE README.md ./
COPY bin ./bin
COPY lib ./lib
COPY examples/wiki ./examples/wiki
WORKDIR /build/examples/wiki
RUN rm -rf node_modules data data-e2e public/dist \
 && npm install --no-package-lock --omit=dev --install-links \
 && chown -R nonroot:nonroot /build

FROM cgr.dev/chainguard/node:latest AS runtime
ENV NODE_ENV=production \
    WIKI_DATA_DIR=/data \
    WIKI_PORT=8080
WORKDIR /app
COPY --from=deps --chown=nonroot:nonroot /build/package.json /build/index.js /build/NOTICE /build/LICENSE /build/README.md ./
COPY --from=deps --chown=nonroot:nonroot /build/bin ./bin
COPY --from=deps --chown=nonroot:nonroot /build/lib ./lib
COPY --from=deps --chown=nonroot:nonroot /build/examples/wiki ./examples/wiki
USER nonroot
WORKDIR /app/examples/wiki
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
# The Chainguard node image has ENTRYPOINT ["/usr/bin/node"], so CMD
# is just the script path the operator wants Node to run.
CMD ["server.js"]
