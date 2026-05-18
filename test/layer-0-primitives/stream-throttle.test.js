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

// Per-test wall-clock guard — caps each stream-throttle test to 10
// seconds. If a future Node release / OS runner has a setTimeout /
// stream-pipeline interaction that hangs (the symptom is opaque on a
// remote CI runner; the test runner's hard cap surfaces it as a clean
// failure with a label rather than a 6-hour stuck job).
function _withGuard(label, fn) {
  return new Promise(function (resolve, reject) {
    var timer = setTimeout(function () {
      reject(new Error("stream-throttle test timed out: " + label));
    }, 10000);                                                                                         // allow:raw-byte-literal // allow:raw-time-literal — 10s test wall-clock cap
    Promise.resolve().then(fn).then(function (v) {
      clearTimeout(timer); resolve(v);
    }, function (e) {
      clearTimeout(timer); reject(e);
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
  // the bytes still get through. Budget is 20 KiB/s with a 30 KiB
  // single-chunk payload — the chunk exceeds burst so the wait kicks
  // in, but the wait is bounded at ~500 ms so the test runs cheap.
  await _withGuard("allowOversize", async function () {
    var t = b.streamThrottle.create({ bytesPerSec: 20 * 1024, burstBytes: 20 * 1024 });
    var tx = t.transform({ allowOversize: true });
    var got = await _pipeBuf(tx, 30 * 1024, 30 * 1024);
    check("allowOversize: all bytes delivered", got === 30 * 1024);
  });
}

async function testRateEnforcement() {
  // 20 KiB/s rate; send 40 KiB in 4 × 10 KiB chunks. First chunk
  // consumes the full burst; remaining 3 chunks each wait ~500 ms
  // (10 KiB / 20 KiB-per-s). Total elapsed should be at least
  // ~700 ms after accounting for the initial burst headroom; ceiling
  // at 5 s catches a hang.
  await _withGuard("rateEnforcement", async function () {
    var rate    = 20 * 1024;
    var t       = b.streamThrottle.create({ bytesPerSec: rate, burstBytes: rate });
    var started = Date.now();
    await _pipeBuf(t.transform(), 40 * 1024, 10 * 1024);
    var elapsed = Date.now() - started;
    check("rate enforcement: elapsed >= 700ms (got " + elapsed + ")",
      elapsed >= 700);
    check("rate enforcement: elapsed < 5000ms (got " + elapsed + ")",
      elapsed < 5000);
  });
}

async function testSharedBucketAcrossTransforms() {
  // Two transforms drawing from the same 20 KiB/s bucket should
  // together total ~2 s for 40 KiB. The point is that two parallel
  // transforms SHARE the budget rather than each getting their own.
  await _withGuard("sharedBucket", async function () {
    var rate    = 20 * 1024;
    var t       = b.streamThrottle.create({ bytesPerSec: rate, burstBytes: rate });
    var started = Date.now();
    await Promise.all([
      _pipeBuf(t.transform(), 20 * 1024, 5 * 1024),
      _pipeBuf(t.transform(), 20 * 1024, 5 * 1024),
    ]);
    var elapsed = Date.now() - started;
    check("shared bucket: 2 transforms × 20 KiB at 20 KiB/s elapsed >= 500ms (got " + elapsed + ")",
      elapsed >= 500);
  });
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
