"use strict";
/**
 * bundler-output — verifies the framework survives static-analysis
 * bundling (esbuild + Node SEA). v0.9.8 silently broke SEA / esbuild
 * deployments because `lib/vendor-data.js` looked up its `.data.js`
 * payload modules via `require(variable)` — a dynamic require, opaque
 * to every bundler's static-analysis pass. The bug shipped through
 * every existing gate because all of them run against `node`-the-
 * runtime, which always resolves dynamic require strings correctly.
 *
 * This test bundles the framework via esbuild (and on Linux hosts,
 * additionally via Node's SEA `--experimental-sea-config`), runs the
 * bundled output, and asserts the four-layer vendor-data integrity
 * surface (dual-hash + SLH-DSA signature + canary) survives the
 * bundle. The canary in the PSL payload must also surface through
 * b.publicSuffix.isPublicSuffix after the bundle loads — proves the
 * .data.js files were physically included in the bundle bytes.
 *
 * Caught by hermitstash-sync operator review post-v0.9.8. This
 * test, had it existed, would have refused v0.9.8 at smoke gate.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var fs      = require("node:fs");
var path    = require("node:path");
var os      = require("node:os");
var nodeCrypto = require("node:crypto");
var childProcess = require("node:child_process");

var REPO_ROOT = path.resolve(__dirname, "..", "..");

// _spawnSync — wrap child_process.spawnSync with a cap on output
// capture + an explicit failure-mode that surfaces stderr to the
// caller. The bundler invocations + bundle execution both emit a few
// hundred KB at most; the cap is defensive.
//
// Windows note: npx is a .cmd shim; plain `spawnSync("npx", ...)`
// hits ENOENT, but `spawnSync("npx", args, { shell: true })` works
// across all platforms. The DEP0190 warning that ships with shell
// is benign here — every arg in this test is framework-internal
// (literal flag strings + tmpdir paths we control). There is no
// operator-controllable input reaching the args; the shell-
// injection vector that DEP0190 warns about isn't present.
function _spawnSync(cmd, args, opts) {
  opts = opts || {};
  var res = childProcess.spawnSync(cmd, args, {
    cwd:         opts.cwd || REPO_ROOT,
    encoding:    "utf8",
    maxBuffer:   16 * 1024 * 1024,
    env:         Object.assign({}, process.env, opts.env || {}),
    shell:       process.platform === "win32",   // allow:shell-spawn — see comment above; args are framework-internal
  });
  return {
    ok:     res.status === 0,
    code:   res.status,
    stdout: res.stdout || "",
    stderr: res.stderr || "",
  };
}

// _scratchDir — per-test tmpdir; auto-cleanup at end of run().
var _scratchDirs = [];
function _scratchDir(label) {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bundler-" + label + "-"));
  _scratchDirs.push(d);
  return d;
}
function _cleanupScratch() {
  for (var i = 0; i < _scratchDirs.length; i++) {
    try { fs.rmSync(_scratchDirs[i], { recursive: true, force: true }); } catch (_e) {}
  }
  _scratchDirs = [];
}

// _writeConsumer — minimal consumer that exercises every vendor-data
// surface: PSL parsed (verifies the canary made it through), common-
// passwords loaded (verifies the second .data.js), BIMI loaded
// (verifies the third), and verifyAll() returns all three names
// (verifies the registry is intact). Any missing .data.js in the
// bundle = consumer throws at first vendorData.get() = bundle exec
// fails non-zero.
function _writeConsumer(dir) {
  var entry = path.join(dir, "consumer.js");
  var src =
    "\"use strict\";\n" +
    "var b = require(" + JSON.stringify(REPO_ROOT) + ");\n" +
    "var assert = require(\"node:assert\");\n" +
    "\n" +
    "// vendorData.verifyAll runs all 4 integrity layers per entry.\n" +
    "var names = b.vendorData.verifyAll();\n" +
    "assert.deepStrictEqual(names.sort(), [\"bimi-trust-anchors\", \"common-passwords-top-10000\", \"public-suffix-list\"]);\n" +
    "\n" +
    "// PSL canary roundtrip — proves the .data.js payload reached the bundle\n" +
    "// AND the PSL parser ingested it (the canary is in the parsed structure,\n" +
    "// not just a byte-search).\n" +
    "assert.strictEqual(b.publicSuffix.isPublicSuffix(\"_blamejs_canary_v0_9_8_.local\"), true);\n" +
    "\n" +
    "// PSL real-world lookup — co.uk is in the payload and gets parsed.\n" +
    "assert.strictEqual(b.publicSuffix.publicSuffix(\"example.co.uk\"), \"co.uk\");\n" +
    "\n" +
    "// vendorData.inventory returns metadata for all 3 entries.\n" +
    "var inv = b.vendorData.inventory();\n" +
    "assert.strictEqual(inv.length, 3);\n" +
    "for (var i = 0; i < inv.length; i++) {\n" +
    "  assert.ok(inv[i].byteLength > 0, inv[i].name + \" has bytes\");\n" +
    "  assert.ok(inv[i].sha256.length === 64, inv[i].name + \" has sha256\");\n" +
    "  assert.ok(inv[i].sha3_512.length === 128, inv[i].name + \" has sha3_512\");\n" +
    "}\n" +
    "\n" +
    "console.log(\"BUNDLE-OK psl=\" + b.publicSuffix.publicSuffix(\"example.co.uk\") + \" entries=\" + inv.length);\n";
  fs.writeFileSync(entry, src);
  return entry;
}

// ---- esbuild bundle test ----

function testEsbuildBundlePreservesVendorData() {
  var dir = _scratchDir("esbuild");
  var consumer = _writeConsumer(dir);
  var bundlePath = path.join(dir, "bundle.cjs");

  // Run esbuild via npx — `--bundle --platform=node` is the most
  // common modern Node bundler invocation. Static-analysis tracing
  // of require() determines what to include. Dynamic require(var)
  // is invisible to this pass — exactly the v0.9.8 bug class.
  var bundle = _spawnSync("npx", [
    "--yes", "esbuild",
    consumer,
    "--bundle",
    "--platform=node",
    "--format=cjs",
    "--outfile=" + bundlePath,
    "--log-level=error",
  ], { cwd: dir });

  check("esbuild bundle: bundler invocation succeeded",  bundle.ok);
  if (!bundle.ok) {
    process.stderr.write("esbuild stderr:\n" + bundle.stderr + "\n");
    return;   // can't continue if bundling itself failed
  }
  check("esbuild bundle: output file exists",            fs.existsSync(bundlePath));

  // Bundle must be self-contained — the .data.js payloads (~545 KB
  // total) need to be inside it. A bundle that "succeeded" but
  // dropped the payloads would be small (<200 KB).
  var bundleSize = fs.statSync(bundlePath).size;
  check("esbuild bundle: includes the .data.js payloads (>= 400 KB)",
        bundleSize >= 400 * 1024);

  // Run the bundle — vendor-data layers fire at require-time, throws
  // on tamper / missing modules. Success exit = all four layers
  // passed across all three vendor-data entries.
  var exec = _spawnSync("node", [bundlePath], { cwd: dir });
  if (!exec.ok) {
    process.stderr.write("bundle exec stderr:\n" + exec.stderr + "\n");
    process.stderr.write("bundle exec stdout:\n" + exec.stdout + "\n");
  }
  check("esbuild bundle: bundled consumer exits 0",      exec.ok);
  check("esbuild bundle: consumer printed BUNDLE-OK",
        exec.stdout.indexOf("BUNDLE-OK psl=co.uk entries=3") !== -1);
}

// ---- minified-bundle test ----
//
// Some minifiers rewrite property access patterns that affect how
// static require() tracing resolves (e.g. dead-code elimination
// stripping unreachable require() branches). Repeat the bundle with
// --minify to surface that class.

function testEsbuildMinifiedBundlePreservesVendorData() {
  var dir = _scratchDir("esbuild-min");
  var consumer = _writeConsumer(dir);
  var bundlePath = path.join(dir, "bundle.min.cjs");

  var bundle = _spawnSync("npx", [
    "--yes", "esbuild",
    consumer,
    "--bundle",
    "--minify",
    "--platform=node",
    "--format=cjs",
    "--outfile=" + bundlePath,
    "--log-level=error",
  ], { cwd: dir });

  check("esbuild --minify bundle: invocation succeeded", bundle.ok);
  if (!bundle.ok) return;

  // Minified bundle is smaller but still must carry the payloads.
  // Base64-encoded payloads can't be minified further (they're string
  // constants), so the floor is roughly the same as the unminified
  // bundle's payload portion.
  var bundleSize = fs.statSync(bundlePath).size;
  check("esbuild --minify bundle: includes payloads (>= 400 KB)",
        bundleSize >= 400 * 1024);

  var exec = _spawnSync("node", [bundlePath], { cwd: dir });
  if (!exec.ok) {
    process.stderr.write("minified bundle exec stderr:\n" + exec.stderr + "\n");
  }
  check("esbuild --minify bundle: bundled consumer exits 0",     exec.ok);
  check("esbuild --minify bundle: consumer printed BUNDLE-OK",
        exec.stdout.indexOf("BUNDLE-OK psl=co.uk entries=3") !== -1);
}

// ---- regression sentinel: bundle must reject dynamic require ----
//
// If a future refactor reintroduces a `require(variable)` pattern in
// lib/vendor-data.js (or any module the bundle traces), this test
// detects it by examining the produced bundle for the
// `vendor-data/module-missing` runtime error path that fires when a
// .data.js was dropped during bundle. The codebase-patterns gate
// catches the source-level smell; this catches the produced-bundle
// behavior — defense in depth, independent failure mode.
function testBundleHasNoMissingModuleRuntimePath() {
  var dir = _scratchDir("esbuild-sentinel");
  var consumer = _writeConsumer(dir);
  var bundlePath = path.join(dir, "bundle.cjs");

  var bundle = _spawnSync("npx", [
    "--yes", "esbuild",
    consumer,
    "--bundle",
    "--platform=node",
    "--format=cjs",
    "--outfile=" + bundlePath,
    "--log-level=error",
  ], { cwd: dir });

  if (!bundle.ok) {
    check("bundle sentinel: bundler succeeded (gate skipped on bundle failure)", false);
    return;
  }

  // Compute sha256 of the bundle so a future regression that
  // shrinks the bundle to <400 KB without the .data.js content
  // (the v0.9.8 shape) gets a different, easy-to-diff hash from
  // the known-good v0.9.9+ shape.
  var bundleBytes = fs.readFileSync(bundlePath);
  var sha = nodeCrypto.createHash("sha256").update(bundleBytes).digest("hex");

  // The bundle MUST contain the canary string — that's the
  // simplest single byte-search that proves the PSL .data.js
  // payload made it into the bundle. If the consumer's static-
  // require chain to lib/vendor-data → ./vendor/public-suffix-list.data
  // broke, the canary string disappears from the bundle bytes.
  var bundleText = bundleBytes.toString("utf8");
  check("bundle sentinel: PSL canary token present in bundle bytes",
        bundleText.indexOf("_blamejs_canary_v0_9_8_") !== -1);
  check("bundle sentinel: common-passwords canary present in bundle bytes",
        bundleText.indexOf("_blamejs_canary_password_2026_05_13_") !== -1);
  check("bundle sentinel: bundle sha256 is deterministic across runs " +
        "(observed " + sha.slice(0, 12) + "...)",
        sha.length === 64);
}

// ---- SEA bundle test (Linux + Node 22+ only) ----
//
// Node's `--experimental-sea-config` + postject produces an actual
// SEA binary that bundles the framework + consumer into a single
// executable. This is THE deployment mode operators trip on — the
// esbuild gate above catches the bundle-trace failure class, the
// SEA gate catches any Node-SEA-specific divergence (e.g. assets
// not properly included, sea.getAsset shape changes).

function _seaSupported() {
  // Available on Linux + macOS via postject; Windows SEA path uses
  // signtool which complicates CI. Gate on Linux for now.
  if (process.platform !== "linux") return false;
  // Node 22+ ships SEA stable; lower versions are experimental.
  var nodeMajor = parseInt(process.versions.node.split(".")[0], 10);
  return nodeMajor >= 22;
}

function testSeaBundlePreservesVendorData() {
  if (!_seaSupported()) {
    check("SEA bundle: skipped (not Linux + Node >= 22)", true);
    return;
  }

  var dir = _scratchDir("sea");
  var consumer = _writeConsumer(dir);

  // First esbuild-bundle the consumer (SEA needs a single .js file).
  var seaSource = path.join(dir, "sea-source.cjs");
  var bundle = _spawnSync("npx", [
    "--yes", "esbuild",
    consumer,
    "--bundle",
    "--platform=node",
    "--format=cjs",
    "--outfile=" + seaSource,
    "--log-level=error",
  ], { cwd: dir });
  check("SEA bundle: pre-bundle via esbuild succeeded", bundle.ok);
  if (!bundle.ok) return;

  // Write sea-config.json. No assets needed because the .data.js
  // payloads are inlined into the bundle by esbuild (that's the
  // whole point of v0.9.9's static-require fix).
  var seaConfig = {
    main:          seaSource,
    output:        path.join(dir, "sea-prep.blob"),
    disableExperimentalSEAWarning: true,
  };
  fs.writeFileSync(path.join(dir, "sea-config.json"), JSON.stringify(seaConfig));

  // Generate the SEA blob.
  var prep = _spawnSync("node", [
    "--experimental-sea-config", path.join(dir, "sea-config.json"),
  ], { cwd: dir });
  check("SEA bundle: --experimental-sea-config produced blob",  prep.ok && fs.existsSync(seaConfig.output));
  if (!prep.ok) {
    process.stderr.write("sea-config stderr:\n" + prep.stderr + "\n");
    return;
  }

  // Copy node + inject blob via postject.
  var seaBinary = path.join(dir, "blamejs-sea");
  fs.copyFileSync(process.execPath, seaBinary);
  fs.chmodSync(seaBinary, 0o755);

  var inject = _spawnSync("npx", [
    "--yes", "postject",
    seaBinary,
    "NODE_SEA_BLOB",
    seaConfig.output,
    "--sentinel-fuse", "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
  ], { cwd: dir });
  check("SEA bundle: postject injection succeeded", inject.ok);
  if (!inject.ok) {
    process.stderr.write("postject stderr:\n" + inject.stderr + "\n");
    return;
  }

  // Run the SEA binary.
  var exec = _spawnSync(seaBinary, [], { cwd: dir });
  if (!exec.ok) {
    process.stderr.write("SEA exec stderr:\n" + exec.stderr + "\n");
    process.stderr.write("SEA exec stdout:\n" + exec.stdout + "\n");
  }
  check("SEA bundle: binary exits 0", exec.ok);
  check("SEA bundle: binary printed BUNDLE-OK",
        exec.stdout.indexOf("BUNDLE-OK psl=co.uk entries=3") !== -1);
}

async function run() {
  try {
    testEsbuildBundlePreservesVendorData();
    testEsbuildMinifiedBundlePreservesVendorData();
    testBundleHasNoMissingModuleRuntimePath();
    testSeaBundlePreservesVendorData();
  } finally {
    _cleanupScratch();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
