// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * storage.getBackend — the escape-hatch accessor that returns a named
 * backend instance from the underlying object-store adapter (or null when
 * unknown), and throws before storage.init has run.
 *
 * Run standalone: `node test/layer-0-primitives/storage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;
var check = helpers.check;

async function testGetBackend() {
  var uploadDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-storage-"));
  b.storage._resetForTest();
  try {
    // Before init, any file-op accessor refuses.
    var preThrew = null;
    try { b.storage.getBackend("default"); } catch (e) { preThrew = e; }
    check("storage.getBackend before init throws NOT_INITIALIZED",
          preThrew && preThrew.code === "NOT_INITIALIZED");

    b.storage.init({ backend: "local", uploadDir: uploadDir });

    var backend = b.storage.getBackend("default");
    check("storage.getBackend returns the registered backend instance",
          backend && typeof backend === "object");
    check("storage.getBackend backend reports protocol 'local'",
          backend.protocol === "local");
    check("storage.getBackend unknown name returns null",
          b.storage.getBackend("does-not-exist") === null);

    // The escape-hatch handle corresponds to what listBackends reports.
    var listed = b.storage.listBackends();
    check("storage.getBackend default name matches listBackends",
          listed.length === 1 && listed[0].name === "default" && listed[0].protocol === "local");
    // Same registry object on repeat lookups (not a fresh build per call).
    check("storage.getBackend returns a stable handle across calls",
          b.storage.getBackend("default") === backend);
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(uploadDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  await testGetBackend();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[storage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
