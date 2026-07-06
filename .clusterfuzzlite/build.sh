#!/bin/bash -eu
#
# ClusterFuzzLite / OSS-Fuzz build script for blamejs.
#
# Wires every `fuzz/<name>.fuzz.js` harness into a libFuzzer-shaped
# runnable via the base-builder-javascript image's
# `compile_javascript_fuzzer` helper. The matching
# `fuzz/<name>_seed_corpus/` directory is zipped into the seed
# corpus the engine bootstraps from.
#
# Local debug:
#   docker run -it -v "$PWD:/src/blamejs" gcr.io/oss-fuzz-base/base-builder-javascript
#   cd /src/blamejs && bash .clusterfuzzlite/build.sh

cd "$SRC/blamejs"

# Install the fuzz-time runtime (@jazzer.js/core) before compiling. The
# base-builder-javascript image ships jazzer.js for the compile helper, but the
# runnable it emits execs `<project>/node_modules/@jazzer.js/core/dist/cli.js` at
# fuzz time: compile_javascript_fuzzer copies $SRC/blamejs -> $OUT/blamejs
# wholesale, so the runtime must already be present in the PROJECT-ROOT
# node_modules. @jazzer.js/core is pinned in fuzz/package.json (kept out of the
# framework's own manifest, which ships zero runtime deps), so install it there
# and surface it at the project root. Skipping this leaves every target pointing
# at a runtime that isn't present; the compile step still exits 0, so the gap is
# otherwise silent — the targets build but cannot start.
npm ci --prefix fuzz
mkdir -p node_modules
cp -r fuzz/node_modules/. node_modules/

# Stage every harness into $OUT. compile_javascript_fuzzer resolves the module
# via Node's normal resolution from the repo root, so `require("..")` in each
# harness picks up the framework entry-point.
for fuzzer in fuzz/*.fuzz.js; do
  # compile_javascript_fuzzer names the target `basename -s .js`, so
  # `fuzz/guard-csv.fuzz.js` builds the artifact `guard-csv.fuzz`. The seed
  # corpus is paired by that exact target name (`<target>_seed_corpus.zip`),
  # while the seed-corpus SOURCE dir drops `.fuzz.js` (`fuzz/<base>_seed_corpus`).
  # Using <base> for the zip (as this script once did) names it
  # `guard-csv_seed_corpus.zip`, which never pairs with `guard-csv.fuzz` — so the
  # engine silently bootstraps from an empty corpus.
  target=$(basename "$fuzzer" .js)        # guard-csv.fuzz — matches the built artifact
  base=$(basename "$fuzzer" .fuzz.js)     # guard-csv      — matches the seed-corpus dir
  echo "[blamejs build] compiling $target"
  compile_javascript_fuzzer blamejs "$fuzzer" --sync

  # Zip the seed corpus if it exists, under the target's name so it pairs.
  seed_dir="fuzz/${base}_seed_corpus"
  if [ -d "$seed_dir" ]; then
    echo "[blamejs build] packaging seed corpus for $target"
    ( cd "$seed_dir" && zip -q -r "$OUT/${target}_seed_corpus.zip" . )
  fi
done

echo "[blamejs build] done — $(find "$OUT" -mindepth 1 -maxdepth 1 | wc -l) artifacts in \$OUT"
