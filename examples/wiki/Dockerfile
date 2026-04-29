# syntax=docker/dockerfile:1.7
#
# Build context is the blamejs repo root, not examples/wiki/. The wiki
# package.json declares "@blamejs/core": "file:../..", so the framework
# source has to be reachable from the wiki directory at install time.
# docker-compose.yml in this directory sets context accordingly.

FROM node:24-slim AS deps
WORKDIR /build
COPY package.json index.js NOTICE LICENSE README.md ./
COPY bin ./bin
COPY lib ./lib
COPY examples/wiki ./examples/wiki
WORKDIR /build/examples/wiki
RUN rm -rf node_modules data data-e2e public/dist \
 && npm install --no-package-lock --omit=dev --install-links

FROM node:24-slim AS runtime
ENV NODE_ENV=production \
    WIKI_DATA_DIR=/data \
    WIKI_PORT=8080
WORKDIR /app
COPY --from=deps /build/package.json /build/index.js /build/NOTICE /build/LICENSE /build/README.md ./
COPY --from=deps /build/bin ./bin
COPY --from=deps /build/lib ./lib
COPY --from=deps /build/examples/wiki ./examples/wiki
WORKDIR /app/examples/wiki
RUN mkdir -p /data \
 && chown -R node:node /app /data
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>{process.exit(r.ok?0:1)}).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
