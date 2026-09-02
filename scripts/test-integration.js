// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/test-integration.js
 *
 * Integration test runner. Validates the docker-compose.test.yml stack
 * is reachable, exports the test CA out of the docker volume, then
 * spawns each test in test/integration/ as its own node process with
 * NODE_EXTRA_CA_CERTS set so every TLS handshake the framework does
 * during the test trusts the CA — no rejectUnauthorized=false bypass
 * anywhere in the test surface.
 *
 * Distinct from `test/smoke.js` because the smoke gate must remain
 * pure — runs in CI, in prepack-guard, on a developer laptop with no
 * docker stack — and a "skip silently when service is down" branch in
 * a layer-N test makes that gate's pass count misleading and masks
 * bugs that only surface against a live backend.
 *
 * Exit codes:
 *   0 — every integration test passed
 *   1 — one or more services unreachable (rerun after `docker compose up`)
 *   2 — at least one test file threw / returned non-zero
 *   3 — script-level error (no test files found, CA export failed, etc.)
 *
 * Usage:
 *   node scripts/test-integration.js
 *   node scripts/test-integration.js queue-redis           — single test
 *   node scripts/test-integration.js --skip-service-check  — assume up
 *   node scripts/test-integration.js --no-docker           — for a selection
 *     that uses no compose service: skips the readiness probe AND the CA
 *     export, which reads the certs volume out of a running container.
 */
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var spawn = require("node:child_process").spawn;

// Persist everything this run prints, the way every other gate does.
//
// Without it the only record of which file failed is the terminal, and a caller
// that pipes this through `tail` keeps the summary and throws away the failing
// file's name and its output -- which is exactly what happened when the release
// orchestrator ran it: "1 of 37 files failed" survived and the identity of the
// one did not, so the only way back to it was another full run. Synchronous fd
// writes, because an async stream does not flush before `process.exit`.
var OUT_DIR  = path.join(__dirname, "..", ".test-output");
var LOG_PATH = path.join(OUT_DIR, "test-integration.log");
try { fs.mkdirSync(OUT_DIR, { recursive: true }); } catch (_e) { /* best-effort */ }
try { fs.unlinkSync(LOG_PATH); } catch (_e) { /* fresh start */ }
var _logFd = null;
try { _logFd = fs.openSync(LOG_PATH, "w"); } catch (_e) { _logFd = null; }
function _logWrite(chunk) {
  if (_logFd === null) return;
  try {
    var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
    fs.writeSync(_logFd, buf, 0, buf.length, null);
  } catch (_e) { /* best-effort */ }
}
var _origStdout = process.stdout.write.bind(process.stdout);
var _origStderr = process.stderr.write.bind(process.stderr);
process.stdout.write = function (c, e, cb) { _logWrite(c); return _origStdout(c, e, cb); };
process.stderr.write = function (c, e, cb) { _logWrite(c); return _origStderr(c, e, cb); };
process.on("exit", function () {
  if (_logFd !== null) { try { fs.closeSync(_logFd); } catch (_e) { /* best-effort */ } }
});

var INTEGRATION_DIR = path.join(__dirname, "..", "test", "integration");
var CHECK_SERVICES  = path.join(__dirname, "check-services.js");
var CA_EXPORT_PATH  = path.join(os.tmpdir(), "blamejs-test-ca.crt");

function _padRight(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function _spawn(cmd, args, opts) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, Object.assign({ stdio: "inherit" }, opts || {}));
    child.once("exit", function (code, signal) {
      resolve({ code: code, signal: signal });
    });
    child.once("error", reject);
  });
}

function _spawnCapturing(cmd, args, env) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, { env: env, stdio: ["ignore", "pipe", "pipe"] });
    var stdout = "";
    var stderr = "";
    child.stdout.on("data", function (b) { stdout += b.toString(); });
    child.stderr.on("data", function (b) { stderr += b.toString(); });
    child.once("exit", function (code, signal) {
      resolve({ code: code, signal: signal, stdout: stdout, stderr: stderr });
    });
    child.once("error", reject);
  });
}

async function _exportCaCert() {
  // The pki-init container exits after generating certs, so we copy
  // from any container that mounts the certs volume — redis is always
  // up and has /certs read-only.
  var rv = await _spawnCapturing("docker", ["cp", "blamejs-test-redis:/certs/ca.crt", CA_EXPORT_PATH], process.env);
  if (rv.code !== 0) {
    throw new Error("docker cp ca.crt failed: " + (rv.stderr || rv.stdout || "").trim());
  }
  if (!fs.existsSync(CA_EXPORT_PATH)) {
    throw new Error("ca.crt not present at " + CA_EXPORT_PATH + " after docker cp");
  }
  var pem = fs.readFileSync(CA_EXPORT_PATH, "utf8");
  if (pem.indexOf("-----BEGIN CERTIFICATE-----") !== 0) {
    throw new Error("exported ca.crt does not look like a PEM cert");
  }
  return CA_EXPORT_PATH;
}

(async function main() {
  var args = process.argv.slice(2);
  // `--no-docker` is for a selection that needs nothing from the compose
  // stack: no readiness probe, and no CA export either. The export reaches
  // for the certs volume through a running container, so leaving it in place
  // would make a Docker daemon a precondition for tests that never touch one.
  var noDocker  = args.indexOf("--no-docker") !== -1;
  var skipCheck = noDocker || args.indexOf("--skip-service-check") !== -1;
  var named = args.filter(function (a) { return a.charAt(0) !== "-"; });

  if (!fs.existsSync(INTEGRATION_DIR)) {
    console.error("[test-integration] missing dir: " + INTEGRATION_DIR);
    process.exit(3);
  }

  var files = fs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .filter(function (f) {
      if (named.length === 0) return true;
      return named.some(function (n) { return f === n || f === n + ".test.js"; });
    })
    .sort();

  if (files.length === 0) {
    console.error("[test-integration] no test files matched " +
      (named.length === 0 ? "test/integration/*.test.js" : named.join(", ")));
    process.exit(3);
  }

  if (!skipCheck) {
    console.log("[test-integration] running scripts/check-services.js gate...");
    var checkExit = await _spawn(process.execPath, [CHECK_SERVICES]);
    if (checkExit.code !== 0) {
      console.error("[test-integration] service-check gate failed (exit " + checkExit.code + ")");
      console.error("[test-integration] bring the stack up: docker compose -f docker-compose.test.yml up -d --wait");
      console.error("[test-integration] OR re-run with --skip-service-check to bypass");
      process.exit(1);
    }
  }

  // Export the test CA so each test process trusts it at startup. This
  // is the cleanest way to test against private TLS endpoints without
  // weakening the framework's verification — operators in production
  // do exactly the same thing (set NODE_EXTRA_CA_CERTS or trust the
  // CA at the OS level).
  var caPath = null;
  if (noDocker) {
    console.log("[test-integration] --no-docker: skipping the CA export " +
      "(the selected tests use no compose service)");
  } else {
    try {
      caPath = await _exportCaCert();
      console.log("[test-integration] CA exported: " + caPath);
    } catch (e) {
      console.error("[test-integration] CA export failed: " + e.message);
      process.exit(3);
    }
  }

  var childEnv = Object.assign({}, process.env, {
    BLAMEJS_INTEGRATION_RUNNER:    "1",
  });
  // With no CA to trust, both variables must be ABSENT from the child, not
  // merely un-assigned: the environment is inherited, so a value left over
  // from an earlier run or set by the invoking shell would otherwise reach
  // tests that are supposed to trust nothing extra — quietly changing what a
  // TLS handshake in them accepts.
  if (caPath) {
    childEnv.NODE_EXTRA_CA_CERTS  = caPath;
    childEnv.BLAMEJS_TEST_CA_PATH = caPath;
  } else {
    delete childEnv.NODE_EXTRA_CA_CERTS;
    delete childEnv.BLAMEJS_TEST_CA_PATH;
  }

  console.log("");
  console.log("[test-integration] running " + files.length + " integration test file" +
    (files.length === 1 ? "" : "s") + " (each in a fresh node process)...");
  var suiteStart = Date.now();
  var failed = 0;
  for (var i = 0; i < files.length; i++) {
    var fullPath = path.join(INTEGRATION_DIR, files[i]);
    var fileStart = Date.now();
    var rv;
    try {
      rv = await _spawnCapturing(process.execPath, [fullPath], childEnv);
    } catch (err) {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " SPAWN FAILED");
      console.error("    " + (err.message || String(err)));
      continue;
    }
    var ms = Date.now() - fileStart;
    if (rv.code === 0) {
      // Success line: pull the trailing OK line out of stdout so the
      // runner output stays consistent with smoke's format.
      var okLine = (rv.stdout.match(/OK — \d+ checks? passed/g) || []).pop() || "";
      // Exit 0 alone does not mean the file tested anything. A run() that
      // resolved before reaching its assertions, or a file whose checks were
      // commented out, exits 0 exactly like a passing one — and used to print a
      // blank column here, which reads as a pass. Require the count, and
      // require it to be non-zero: `OK — 0 checks passed` matches the pattern
      // while asserting nothing at all.
      var checkCount = okLine ? Number((okLine.match(/\d+/) || [0])[0]) : -1;
      if (checkCount < 1) {
        failed += 1;
        console.error("  " + _padRight(files[i], 40) + " (" + ms + "ms) " +
          (checkCount === 0 ? "RAN 0 CHECKS" : "NO CHECK COUNT"));
        console.error("    Exited 0 without reporting a non-zero check count. Print " +
          "`OK — \" + helpers.getChecks() + \" checks passed` from the " +
          "`require.main === module` block so a file that stops asserting is " +
          "distinguishable from one that passed.");
        continue;
      }
      console.log("  " + _padRight(files[i], 40) + " (" + ms + "ms) " + okLine);
    } else {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " FAILED (exit " + rv.code + ")");
      var lines = (rv.stderr || rv.stdout || "").split(/\r?\n/).filter(Boolean).slice(-12);
      lines.forEach(function (l) { console.error("    " + l); });
    }
  }
  console.log("");
  if (failed === 0) {
    console.log("[test-integration] OK — " + files.length + " files in " +
      (Date.now() - suiteStart) + "ms");
    process.exit(0);
  }
  console.error("[test-integration] " + failed + " of " + files.length + " files failed");
  process.exit(2);
})().catch(function (err) {
  console.error("[test-integration] runner error: " + ((err && err.stack) || err));
  process.exit(3);
});
