// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.backup.runInWorker — worker_threads dispatch helper for backup
 * and restore long-running operations.
 */

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var rejected;
  try {
    await b.backup.runInWorker({});
  } catch (e) { rejected = e; }
  check("backup.runInWorker: missing workerScript rejects",
    rejected && rejected.code === "backup/no-worker-script");

  var rejected2;
  try {
    await b.backup.runInWorker({ workerScript: "/dev/null/nope.js", timeoutMs: -1 });
  } catch (e) { rejected2 = e; }
  check("backup.runInWorker: negative timeoutMs rejects",
    rejected2 && rejected2.code === "backup/bad-timeout");

  await testSharedGateReachesTheWorker();
  await testDocumentedWorkerAdoptionRuns();
}

// The runInWorker documentation names the call a worker makes to adopt the
// handle it receives. That call is read out of the JSDoc block and run inside a
// worker started by runInWorker against the real gate(), so the documentation
// cannot name a form gate() refuses.
function _documentedAdoptionCall() {
  var src = fs.readFileSync(path.resolve(__dirname, "..", "..", "lib", "backup", "index.js"), "utf8");
  var start = src.indexOf("@primitive b.backup.runInWorker");
  var end = src.indexOf("*/", start);
  if (start === -1 || end === -1) return { calls: [], error: "runInWorker JSDoc block not found" };
  var prose = src.slice(start, end).split(/\r?\n/).map(function (line) {
    return line.replace(/^\s*\*\s?/, "");
  }).join(" ");
  var spans = prose.match(/`[^`]+`/g) || [];
  var calls = spans.map(function (s) { return s.slice(1, -1); }).filter(function (s) {
    return s.indexOf("b.auth.password.gate(") === 0 && s.indexOf("workerData.argon2GateHandle") !== -1;
  });
  return { calls: calls, error: null };
}

async function testDocumentedWorkerAdoptionRuns() {
  var found = _documentedAdoptionCall();
  check("the runInWorker JSDoc names exactly one worker adoption call",
    found.error === null && found.calls.length === 1,
    found.error || JSON.stringify(found.calls));
  if (found.calls.length !== 1) return;

  var prior = b.auth.password.stats();
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wdoc-"));
  try {
    var script = path.join(dir, "doc-worker.js");
    fs.writeFileSync(script,
      "var { parentPort, workerData } = require('node:worker_threads');\n" +
      "var b = { auth: { password: require(" +
        JSON.stringify(path.resolve(__dirname, "..", "..", "lib", "auth", "password.js")) + ") } };\n" +
      "var adopted = false;\n" +
      "try { " + found.calls[0] + "; adopted = true; }\n" +
      "catch (_e) { adopted = String(_e.code || _e.message); }\n" +
      "var s = b.auth.password.stats();\n" +
      "parentPort.postMessage({ adopted: adopted, shared: s.shared, limit: s.limit });\n");

    b.auth.password.gate(3, { shared: true });
    var msg = await b.backup.runInWorker({
      workerScript: script, shareArgon2Gate: true, timeoutMs: 120000,
    });
    check("the documented adoption call is accepted by gate() in the worker",
      msg && msg.adopted === true, JSON.stringify(msg) + " call=" + found.calls[0]);
    check("and leaves the worker on the parent's shared limit",
      msg && msg.shared === true && msg.limit === 3, JSON.stringify(msg));
  } finally {
    b.auth.password.gate(prior.limit, { shared: false });
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// runInWorker created the Worker itself and returned only a promise, so a
// caller could not add the shared Argon2id handle to workerData without
// putting it in `args`, and could not read worker.threadId to reclaim the
// permits of a Worker terminated at timeoutMs. A permit held by such a Worker
// stayed taken for the life of the process, and with a shared limit of 1 every
// later derivation waited or was refused.
async function testSharedGateReachesTheWorker() {
  var badOpt = null;
  try {
    await b.backup.runInWorker({ workerScript: "/nope.js", shareArgon2Gate: "yes" });
  } catch (e) { badOpt = e; }
  check("shareArgon2Gate must be a boolean",
    badOpt && badOpt.code === "backup/bad-opt", String(badOpt && badOpt.code));

  // Without a shared gate there is nothing for the Worker to join, and saying
  // so beats handing it a handle that bounds only itself.
  b.auth.password.gate(2);
  var noShared = null;
  try {
    await b.backup.runInWorker({ workerScript: "/nope.js", shareArgon2Gate: true });
  } catch (e) { noShared = e; }
  check("a per-thread gate cannot be shared with a worker",
    noShared && noShared.code === "backup/no-shared-gate", String(noShared && noShared.code));

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wgate-"));
  try {
    // The worker reports whether it received a handle and whether adopting it
    // puts it under the same limit the parent set.
    // The worker requires the MODULE, not the package root: the gate lives in
    // lib/auth/password.js module state, so the assembled framework adds
    // nothing a gate test needs. Measured in the container against the bind
    // mount, 5290ms for index.js against 469ms for the module, on each of the
    // two Workers below. That cost is what turned the boot budget into a real
    // limit under SMOKE_PARALLEL=64, where the container leg failed with a
    // healthy Worker still loading.
    var script = path.join(dir, "gate-worker.js");
    fs.writeFileSync(script,
      "var { parentPort, workerData } = require('node:worker_threads');\n" +
      "var password = require(" +
        JSON.stringify(path.resolve(__dirname, "..", "..", "lib", "auth", "password.js")) + ");\n" +
      "var handle = workerData && workerData.argon2GateHandle;\n" +
      "var adopted = false;\n" +
      "try { password.gate(2, { shared: handle }); adopted = true; } catch (_e) { adopted = String(_e.message); }\n" +
      "parentPort.postMessage({ gotHandle: !!handle, adopted: adopted });\n");

    b.auth.password.gate(2, { shared: true });
    check("the parent holds a shared gate",
      b.auth.password.gateHandle() !== null);

    // A generous budget on purpose: what this test measures is whether the
    // handle arrives and is adopted, not how fast a Worker boots, so the
    // budget is a precondition and costs nothing when healthy.
    var msg = await b.backup.runInWorker({
      workerScript: script, shareArgon2Gate: true, timeoutMs: 120000,
    });
    check("the worker receives the shared gate handle",
      msg && msg.gotHandle === true, JSON.stringify(msg));
    check("and adopts it as its own limit",
      msg && msg.adopted === true, JSON.stringify(msg));

    // The control: without the option the worker gets no handle, which is the
    // behaviour every existing caller keeps.
    var plain = await b.backup.runInWorker({
      workerScript: script, timeoutMs: 120000,
    });
    check("a worker started without the option gets no handle",
      plain && plain.gotHandle === false, JSON.stringify(plain));
  } finally {
    b.auth.password.gate(null);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-worker] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
