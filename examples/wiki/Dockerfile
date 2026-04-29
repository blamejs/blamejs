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

# Chainguard's :latest-dev runs as the `node` user by default with HOME
# at /home/node. Anchor the build there with matching --chown=node:node
# so npm install can create node_modules without any USER root step.
# The :latest runtime image runs as `nonroot` (different user, lower
# privilege); --chown=nonroot:nonroot on the COPY --from=deps rewrites
# ownership at copy time into the runtime image.
FROM cgr.dev/chainguard/node:latest-dev AS deps
WORKDIR /home/node
COPY --chown=node:node package.json index.js NOTICE LICENSE README.md ./
COPY --chown=node:node bin ./bin
COPY --chown=node:node lib ./lib
COPY --chown=node:node examples/wiki ./examples/wiki
WORKDIR /home/node/examples/wiki
RUN rm -rf node_modules data data-e2e public/dist \
 && npm install --no-package-lock --omit=dev --install-links

FROM cgr.dev/chainguard/node:latest AS runtime
ENV NODE_ENV=production \
    WIKI_DATA_DIR=/data \
    WIKI_PORT=8080
WORKDIR /app
COPY --from=deps --chown=nonroot:nonroot /home/node/package.json /home/node/index.js /home/node/NOTICE /home/node/LICENSE /home/node/README.md ./
COPY --from=deps --chown=nonroot:nonroot /home/node/bin ./bin
COPY --from=deps --chown=nonroot:nonroot /home/node/lib ./lib
COPY --from=deps --chown=nonroot:nonroot /home/node/examples/wiki ./examples/wiki
WORKDIR /app/examples/wiki
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
# The Chainguard node image has ENTRYPOINT ["/usr/bin/node"], so CMD
# is just the script path the operator wants Node to run.
CMD ["server.js"]
