// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * _codebase-shingle-worker — worker_threads entry point invoked by
 * testNoDuplicateCodeBlocks in codebase-patterns.test.js.
 *
 * Receives a shard via workerData: {files, repoRoot, shingleSizes,
 * minDistinctTokens}. Tokenizes and filters it once, announces
 * `{ready:true}`, then answers one `{pass, size}` request at a time
 * with the fingerprint map for that combination.
 *
 * The shard is prepared once and held for the life of the thread: the
 * main thread walks sixteen (pass, size) combinations, and re-reading
 * and re-filtering the corpus for each would cost far more than the
 * tokens are worth keeping. What is NOT held is the fingerprint maps —
 * each is built, posted, and dropped, which is what keeps the scan
 * inside a normal heap.
 */
var workerThreads = require("worker_threads");
var shingle       = require("./_codebase-shingle");

if (!workerThreads.parentPort) {
  throw new Error("_codebase-shingle-worker.js must be launched via Worker, not required directly");
}

var port = workerThreads.parentPort;
var data = workerThreads.workerData || {};

var prepared = shingle.prepareShard(data.files || [], {
  repoRoot:          data.repoRoot,
  shingleSizes:      data.shingleSizes,
  minDistinctTokens: data.minDistinctTokens,
});

port.on("message", function (req) {
  if (!req || req.done) { port.close(); return; }
  port.postMessage({
    pass:   req.pass,
    size:   req.size,
    bucket: shingle.scanRound(prepared, { pass: req.pass, size: req.size }),
  });
});

port.postMessage({ ready: true });
