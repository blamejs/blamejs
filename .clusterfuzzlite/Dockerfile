# ClusterFuzzLite / OSS-Fuzz build image for blamejs.
#
# Inherits libFuzzer + the compile_javascript_fuzzer helper from oss-fuzz's
# JavaScript base-builder. jazzer.js is NOT in the base image — build.sh installs
# @jazzer.js/core (pinned in fuzz/package.json) into the project-root node_modules
# so the runnable compile_javascript_fuzzer emits can resolve it at fuzz time.
# Copy the framework source + harnesses, then build.sh wires each fuzz target
# into a libFuzzer-shaped runnable.
#
# This image is the OSS-Fuzz-upstream integration spec — OSS-Fuzz's own
# oss-fuzz/projects/blamejs/ Dockerfile + build.sh mirror this shape; keep them
# in sync. The in-repo CI fuzz workflows (.github/workflows/cflite_*.yml) do NOT
# use this image — they invoke jazzer.js directly on ubuntu-latest (the CFLite
# build_fuzzers wrapper is broken for JS as of 2026; see cflite_pr.yml).
#
# NOTE — the upstream path is currently LATENT and cannot execute targets: the
# base-builder-javascript image ships Node 20 + GLIBC 2.31, but blamejs needs
# Node 22+ (node:sqlite; engine floor 24.18) and @jazzer.js/core needs GLIBC 2.38.
# build.sh is correct and forward-compatible — it re-engages unchanged once
# OSS-Fuzz ships a Node 24 / Ubuntu 24.04 base-builder-javascript. Do NOT downgrade
# @jazzer.js/core to "fix" this: the Node-20 floor blocks blamejs regardless, and a
# downgrade only risks the working CI (which runs Node 24 on ubuntu-latest).
#
# The base is digest-pinned for a reproducible CI fuzz toolchain (Dependabot
# bumps it via the docker ecosystem entry for /.clusterfuzzlite). Note: the
# oss-fuzz/projects/blamejs/ copy is intentionally left on the floating tag —
# OSS-Fuzz's own build infra expects projects to track the latest base-builder,
# so pinning there would diverge from upstream convention.
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:649105c8df1de6b5e752aaad2c944198aba5cb79481b9ccbcaa189854d9f50d2

# Copy the framework source. ClusterFuzzLite mounts the repo at
# $SRC/blamejs, so we COPY everything (including fuzz/) into one
# place under $SRC.
COPY . $SRC/blamejs

# Build script wires `compile_javascript_fuzzer` for each harness.
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/blamejs
