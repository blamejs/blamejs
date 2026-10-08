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
    var script = path.join(dir, "gate-worker.js");
    fs.writeFileSync(script,
      "var { parentPort, workerData } = require('node:worker_threads');\n" +
      "var b = require(" + JSON.stringify(path.resolve(__dirname, "..", "..", "index.js")) + ");\n" +
      "var handle = workerData && workerData.argon2GateHandle;\n" +
      "var adopted = false;\n" +
      "try { b.auth.password.gate(2, { shared: handle }); adopted = true; } catch (_e) { adopted = String(_e.message); }\n" +
      "parentPort.postMessage({ gotHandle: !!handle, adopted: adopted });\n");

    b.auth.password.gate(2, { shared: true });
    check("the parent holds a shared gate",
      b.auth.password.gateHandle() !== null);

    var msg = await b.backup.runInWorker({
      workerScript: script, shareArgon2Gate: true, timeoutMs: 30000,
    });
    check("the worker receives the shared gate handle",
      msg && msg.gotHandle === true, JSON.stringify(msg));
    check("and adopts it as its own limit",
      msg && msg.adopted === true, JSON.stringify(msg));

    // The control: without the option the worker gets no handle, which is the
    // behaviour every existing caller keeps.
    var plain = await b.backup.runInWorker({
      workerScript: script, timeoutMs: 30000,
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
