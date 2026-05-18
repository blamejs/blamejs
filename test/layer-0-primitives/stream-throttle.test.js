"use strict";
/**
 * b.streamThrottle — token-bucket bandwidth limiter for node:stream
 * pipelines. Tests cover the rate-enforcement path, shared-bucket
 * across-N-transforms accounting, and the refusal classes.
 */

var nodeStream = require("node:stream");
var helpers = require("../helpers");
var check   = helpers.check;
var b       = require("../../index");

function _pipeBuf(transform, totalBytes, chunkBytes) {
  return new Promise(function (resolve, reject) {
    var sent = 0;
    var src = new nodeStream.Readable({
      read: function () {
        if (sent >= totalBytes) { this.push(null); return; }
        var n = Math.min(chunkBytes, totalBytes - sent);
        sent += n;
        this.push(Buffer.alloc(n));
      },
    });
    var got = 0;
    var sink = new nodeStream.Writable({
      write: function (chunk, _enc, cb) { got += chunk.length; cb(); },
    });
    nodeStream.pipeline(src, transform, sink, function (e) {
      if (e) reject(e); else resolve(got);
    });
  });
}

async function testRefusesBadRate() {
  var threw = false;
  try { b.streamThrottle.create({ bytesPerSec: 0 }); }
  catch (e) { threw = e.code === "stream-throttle/bad-rate"; }
  check("bytesPerSec=0 refused", threw);
  threw = false;
  try { b.streamThrottle.create({ bytesPerSec: -10 }); }
  catch (e) { threw = e.code === "stream-throttle/bad-rate"; }
  check("negative bytesPerSec refused", threw);
}

async function testRefusesBurstSmallerThanRate() {
  var threw = false;
  try { b.streamThrottle.create({ bytesPerSec: 1000, burstBytes: 500 }); }
  catch (e) { threw = e.code === "stream-throttle/bad-burst"; }
  check("burst < rate refused", threw);
}

async function testRefusesOversizeChunkByDefault() {
  var t = b.streamThrottle.create({ bytesPerSec: 1000, burstBytes: 1000 });
  var tx = t.transform();
  var threw = false;
  await _pipeBuf(tx, 5000, 5000).catch(function (e) {
    threw = e && e.code === "stream-throttle/oversize-chunk";
  });
  check("chunk > burst refused without allowOversize", threw);
}

async function testAllowsOversizeWhenOptedIn() {
  // Small burst, allowOversize splits the wait across windows; verify
  // the bytes still get through.
  var t = b.streamThrottle.create({ bytesPerSec: 100000, burstBytes: 100000 });
  var tx = t.transform({ allowOversize: true });
  var got = await _pipeBuf(tx, 500000, 500000);
  check("allowOversize: all bytes delivered", got === 500000);
}

async function testRateEnforcement() {
  // 100 KiB/s rate; send 200 KiB in 4 chunks of 50 KiB. First chunk
  // consumes the full burst; remaining 3 chunks each wait ~500ms.
  // Total elapsed should be > 1.4s (3 × 500ms - some refill overlap).
  var rate    = 100 * 1024;
  var t       = b.streamThrottle.create({ bytesPerSec: rate, burstBytes: rate });
  var started = Date.now();
  await _pipeBuf(t.transform(), 200 * 1024, 50 * 1024);
  var elapsed = Date.now() - started;
  // 200 KiB / 100 KiB/s = 2s steady-state; account for initial burst
  // (the bucket starts full). Floor is ~900ms (1s of refill needed
  // for the post-burst 100 KiB).
  check("rate enforcement: elapsed >= 900ms (got " + elapsed + ")",
    elapsed >= 900);
  // Also assert it isn't ridiculously slow (would indicate a bug).
  check("rate enforcement: elapsed < 3500ms (got " + elapsed + ")",
    elapsed < 3500);
}

async function testSharedBucketAcrossTransforms() {
  // Two transforms drawing from the same 100 KiB/s bucket should
  // together total ~2s for 200 KiB. (Each transform on its own would
  // also be ~2s, but two transforms in parallel sharing the bucket
  // SHOULD also total ~2s — that's the entire point of the shared
  // primitive vs per-stream limiter.)
  var rate    = 100 * 1024;
  var t       = b.streamThrottle.create({ bytesPerSec: rate, burstBytes: rate });
  var started = Date.now();
  await Promise.all([
    _pipeBuf(t.transform(), 100 * 1024, 25 * 1024),
    _pipeBuf(t.transform(), 100 * 1024, 25 * 1024),
  ]);
  var elapsed = Date.now() - started;
  check("shared bucket: 2 transforms × 100 KiB at 100 KiB/s elapsed >= 700ms (got " + elapsed + ")",
    elapsed >= 700);
}

async function testStreamThrottleErrorClassExported() {
  check("b.streamThrottle.StreamThrottleError is a constructor",
    typeof b.streamThrottle.StreamThrottleError === "function");
}

async function testStateReturnsBucketShape() {
  var t = b.streamThrottle.create({ bytesPerSec: 1000, burstBytes: 2000 });
  var s = t.state();
  check("state.bytesPerSec",  s.bytesPerSec === 1000);
  check("state.burstBytes",   s.burstBytes  === 2000);
  check("state.tokens initially full", s.tokens === 2000);
  check("state.lastRefillMs is a number", typeof s.lastRefillMs === "number");
}

async function run() {
  await testRefusesBadRate();
  await testRefusesBurstSmallerThanRate();
  await testRefusesOversizeChunkByDefault();
  await testAllowsOversizeWhenOptedIn();
  await testRateEnforcement();
  await testSharedBucketAcrossTransforms();
  await testStreamThrottleErrorClassExported();
  await testStateReturnsBucketShape();
}

if (require.main === module) {
  run().catch(function (e) { console.error(e); process.exit(1); });
}
module.exports = { run: run };
