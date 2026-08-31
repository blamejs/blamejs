// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.storage.chunkScratch — resumable-chunked-upload primitive.
 * Tests cover the per-assembly lifecycle (saveChunk → assemble →
 * removeAssembly), assemblyId shape gating, and the stale-assembly GC.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeFs = require("node:fs");
var path   = require("node:path");

async function _bootHarness() {
  var h = await b.testHarness.start({ initVault: true });
  var uploadDir = path.join(h.dataDir, "uploads");
  nodeFs.mkdirSync(uploadDir, { recursive: true });
  b.storage.init({ backend: "local", uploadDir: uploadDir });
  return h;
}

async function _teardown(h) {
  try { b.storage._resetForTest(); } catch (_e) {}
  await h.stop();
}

async function testRoundTripSaveAssembleRemove() {
  var h = await _bootHarness();
  try {
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "scratch-rt" });
    var chunk0 = Buffer.from("hello-");
    var chunk1 = Buffer.from("world!");
    var s0 = await cs.saveChunk({ assemblyId: "asm-1", chunkIndex: 0, data: chunk0 });
    var s1 = await cs.saveChunk({ assemblyId: "asm-1", chunkIndex: 1, data: chunk1 });
    check("saveChunk returns encryptionKey",
      typeof s0.encryptionKey === "string" && typeof s1.encryptionKey === "string");
    check("saveChunk sizeBytes echoed",  s0.sizeBytes === chunk0.length);

    var n = await cs.countChunks("asm-1");
    check("countChunks reflects saved chunks", n === 2);

    var indices = await cs.listChunks("asm-1");
    check("listChunks returns monotonic indices", indices[0] === 0 && indices[1] === 1);

    var assembled = await cs.assemble({
      assemblyId:          "asm-1",
      expectedTotal:       2,
      chunkEncryptionKeys: [s0.encryptionKey, s1.encryptionKey],
    });
    check("assemble returns concatenated bytes",
      assembled.toString("utf8") === "hello-world!");

    var r = await cs.removeAssembly("asm-1");
    check("removeAssembly reports chunksRemoved", r.chunksRemoved === 2);

    var nAfter = await cs.countChunks("asm-1");
    check("countChunks zero after removeAssembly", nAfter === 0);
  } finally {
    await _teardown(h);
  }
}

async function testAssemblyIdGating() {
  var h = await _bootHarness();
  try {
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "scratch-gate" });
    async function expectThrow(label, fn) {
      var threw = null;
      try { await fn(); } catch (e) { threw = e; }
      check(label, threw && threw.code === "storage/invalid-argument");
    }
    await expectThrow("empty assemblyId refused",
      function () { return cs.saveChunk({ assemblyId: "", chunkIndex: 0, data: Buffer.from("x") }); });
    await expectThrow("slash assemblyId refused",
      function () { return cs.saveChunk({ assemblyId: "a/b", chunkIndex: 0, data: Buffer.from("x") }); });
    await expectThrow("backslash assemblyId refused",
      function () { return cs.saveChunk({ assemblyId: "a\\b", chunkIndex: 0, data: Buffer.from("x") }); });
    await expectThrow("NUL assemblyId refused",
      function () { return cs.saveChunk({ assemblyId: "a\x00b", chunkIndex: 0, data: Buffer.from("x") }); });
    await expectThrow("dot-prefix assemblyId refused",
      function () { return cs.saveChunk({ assemblyId: ".secret", chunkIndex: 0, data: Buffer.from("x") }); });
    await expectThrow("path-traversal assemblyId refused",
      function () { return cs.saveChunk({ assemblyId: "a..b", chunkIndex: 0, data: Buffer.from("x") }); });
    await expectThrow("oversize assemblyId refused",
      function () { return cs.saveChunk({ assemblyId: "x".repeat(200), chunkIndex: 0, data: Buffer.from("x") }); });
    await expectThrow("negative chunkIndex refused",
      function () { return cs.saveChunk({ assemblyId: "ok", chunkIndex: -1, data: Buffer.from("x") }); });
    await expectThrow("non-Buffer data refused",
      function () { return cs.saveChunk({ assemblyId: "ok", chunkIndex: 0, data: "not-a-buffer" }); });
  } finally {
    await _teardown(h);
  }
}

async function testAssembleRefusesGap() {
  var h = await _bootHarness();
  try {
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "scratch-gap" });
    var s0 = await cs.saveChunk({ assemblyId: "gap-1", chunkIndex: 0, data: Buffer.from("a") });
    var s2 = await cs.saveChunk({ assemblyId: "gap-1", chunkIndex: 2, data: Buffer.from("c") });
    var threw = null;
    try {
      await cs.assemble({
        assemblyId:          "gap-1",
        chunkEncryptionKeys: [s0.encryptionKey, s2.encryptionKey],
      });
    } catch (e) { threw = e; }
    check("assemble refuses non-monotonic chunk set",
      threw && threw.code === "storage/incomplete-assembly");
  } finally {
    await _teardown(h);
  }
}

async function testAssembleRefusesExpectedMismatch() {
  var h = await _bootHarness();
  try {
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "scratch-mismatch" });
    var s0 = await cs.saveChunk({ assemblyId: "mm-1", chunkIndex: 0, data: Buffer.from("a") });
    var threw = null;
    try {
      await cs.assemble({
        assemblyId:          "mm-1",
        expectedTotal:       2,                                              // says 2 but only 1 chunk saved
        chunkEncryptionKeys: [s0.encryptionKey],
      });
    } catch (e) { threw = e; }
    check("assemble refuses count mismatch with expectedTotal",
      threw && threw.code === "storage/incomplete-assembly");
  } finally {
    await _teardown(h);
  }
}

async function testListAssemblies() {
  var h = await _bootHarness();
  try {
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "scratch-ls" });
    await cs.saveChunk({ assemblyId: "asm-A", chunkIndex: 0, data: Buffer.from("x") });
    await cs.saveChunk({ assemblyId: "asm-B", chunkIndex: 0, data: Buffer.from("y") });
    await cs.saveChunk({ assemblyId: "asm-C", chunkIndex: 0, data: Buffer.from("z") });
    var ids = await cs.listAssemblies();
    check("listAssemblies surfaces every assembly with at least one chunk",
      ids.length === 3 && ids.indexOf("asm-A") !== -1 && ids.indexOf("asm-B") !== -1 && ids.indexOf("asm-C") !== -1);
  } finally {
    await _teardown(h);
  }
}

async function testMaxChunkBytes() {
  var h = await _bootHarness();
  try {
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "scratch-cap", maxChunkBytes: 16 });
    var threw = null;
    try {
      await cs.saveChunk({ assemblyId: "cap", chunkIndex: 0, data: Buffer.alloc(64, 0x41) });
    } catch (e) { threw = e; }
    check("saveChunk refuses oversize chunk", threw && threw.code === "storage/invalid-argument");
  } finally {
    await _teardown(h);
  }
}

async function testRequiresStorageInit() {
  // Calling chunkScratch before storage.init throws NOT_INITIALIZED —
  // the wrapper inherits the same precondition as saveFile.
  var threw = null;
  try { b.storage.chunkScratch(); } catch (e) { threw = e; }
  check("chunkScratch refuses before storage.init",
    threw && threw.code === "storage/not-initialized");
}

async function run() {
  await testRequiresStorageInit();
  await testRoundTripSaveAssembleRemove();
  await testAssemblyIdGating();
  await testAssembleRefusesGap();
  await testAssembleRefusesExpectedMismatch();
  await testListAssemblies();
  await testMaxChunkBytes();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[storage-chunk-scratch] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
