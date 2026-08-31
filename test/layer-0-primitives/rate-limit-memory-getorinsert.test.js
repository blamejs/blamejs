// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Memory rate-limit backends — get-or-insert routing regression guard.
 *
 * Both in-memory backends keep a request-keyed Map (token buckets /
 * fixed-window counters) and lazily create the per-key record on first
 * sight. This pins the observable verdict behaviour across the
 * insert path AND the existing-record path (token refill / window
 * rollover) so the routing of those get-or-insert sites through
 * b.boundedMap.getOrInsert stays behaviour-identical.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  var rateLimitMod = b.middleware._modules.rateLimit;

  // ---- token-bucket backend ----
  var tb = rateLimitMod._memoryTokenBucketBackend({ burst: 3, refillPerSecond: 1 });

  // First take on a brand-new key inserts the bucket and spends one token.
  var t1 = tb.take("ip-a", 1);
  check("token-bucket: first take allowed", t1.allowed === true);
  check("token-bucket: first take reports full burst as limit", t1.limit === 3);
  check("token-bucket: first take remaining = burst - 1", t1.remaining === 2);

  // Subsequent takes on the SAME key hit the existing-bucket branch and
  // keep decrementing (no refill in the same millisecond window).
  var t2 = tb.take("ip-a", 1);
  check("token-bucket: second take allowed", t2.allowed === true);
  check("token-bucket: second take remaining decremented", t2.remaining === 1);
  var t3 = tb.take("ip-a", 1);
  check("token-bucket: third take allowed", t3.allowed === true);
  var t4 = tb.take("ip-a", 1);
  check("token-bucket: fourth take denied (bucket drained)", t4.allowed === false);
  check("token-bucket: denied verdict has retryAfter", t4.retryAfter >= 1);

  // A different key gets its own fresh bucket (independent insert).
  var u1 = tb.take("ip-b", 1);
  check("token-bucket: distinct key gets fresh bucket", u1.allowed === true && u1.remaining === 2);

  // reset drops the key; the next take re-inserts a full bucket.
  tb.reset("ip-a");
  var t5 = tb.take("ip-a", 1);
  check("token-bucket: after reset, bucket re-inserted full", t5.allowed === true && t5.remaining === 2);
  tb.close();

  // ---- fixed-window backend ----
  var fw = rateLimitMod._memoryFixedWindowBackend({ max: 2, windowMs: 60000 });

  // First take inserts the counter (count -> 1).
  var f1 = fw.take("ip-c", 1);
  check("fixed-window: first take allowed", f1.allowed === true);
  check("fixed-window: first take limit = max", f1.limit === 2);
  check("fixed-window: first take remaining = max - 1", f1.remaining === 1);

  // Same window increments the existing counter.
  var f2 = fw.take("ip-c", 1);
  check("fixed-window: second take allowed (at max)", f2.allowed === true);
  check("fixed-window: second take remaining 0", f2.remaining === 0);
  var f3 = fw.take("ip-c", 1);
  check("fixed-window: third take over max denied", f3.allowed === false);
  check("fixed-window: denied verdict has retryAfter", f3.retryAfter >= 1);

  // Distinct key inserts its own counter.
  var g1 = fw.take("ip-d", 1);
  check("fixed-window: distinct key gets fresh counter", g1.allowed === true && g1.remaining === 1);

  // reset drops the key; next take re-inserts.
  fw.reset("ip-c");
  var f4 = fw.take("ip-c", 1);
  check("fixed-window: after reset, counter re-inserted", f4.allowed === true && f4.remaining === 1);
  fw.close();

  // ---- fixed-window: window rollover re-seeds the existing key ----
  // Drive a 1ms window so a real wall-clock advance rolls the window and
  // exercises the "key present but window changed -> re-seed" branch.
  var fwRoll = rateLimitMod._memoryFixedWindowBackend({ max: 1, windowMs: 1 });
  var r1 = fwRoll.take("ip-e", 1);
  check("fixed-window rollover: first take allowed", r1.allowed === true);
  await helpers.waitUntil(function () {
    // Once the wall clock advances past the 1ms window, a fresh take
    // re-seeds count to 1 and is allowed again on the SAME key.
    var v = fwRoll.take("ip-e", 1);
    return v.allowed === true;
  }, { timeoutMs: 5000, label: "fixed-window rollover: same key allowed in new window" });
  check("fixed-window rollover: same key re-seeded in new window", true);
  fwRoll.close();

  // ---- both backends measure against a supplied clock ----
  // The rollover above waits on the WALL clock, which is the only reading these
  // backends had. An application that puts its other budgets on a monotonic one
  // — auth.lockout and cache both take opts.clock — could not put these on it,
  // so a clock step forward ended a sign-in window that was partway through.
  // The middleware validator enumerates accepted names and REFUSES the rest,
  // so passing one was rejected rather than quietly ignored.
  var ct = 5000000;
  function _fixedClock() { return ct; }

  var fwClock = rateLimitMod._memoryFixedWindowBackend({
    max: 1, windowMs: 60000, clock: _fixedClock,                                                       // allow:raw-time-literal — one-minute window on the injected clock
  });
  check("fixed-window: first take on the supplied clock is allowed",
    fwClock.take("ip-clock", 1).allowed === true);
  check("fixed-window: second take in the same window is denied",
    fwClock.take("ip-clock", 1).allowed === false);
  ct += 61000;                                                                                         // allow:raw-time-literal — past the window on the injected clock
  check("fixed-window: past the window on that clock, allowed again",
    fwClock.take("ip-clock", 1).allowed === true);
  fwClock.close();

  var tbClock = rateLimitMod._memoryTokenBucketBackend({
    burst: 1, refillPerSecond: 1, clock: _fixedClock,
  });
  check("token-bucket: first take on the supplied clock is allowed",
    tbClock.take("ip-tb", 1).allowed === true);
  check("token-bucket: the drained bucket denies on the same reading",
    tbClock.take("ip-tb", 1).allowed === false);
  ct += 5000;                                                                                          // allow:raw-time-literal — five seconds of refill on the injected clock
  check("token-bucket: the bucket refills as that clock advances",
    tbClock.take("ip-tb", 1).allowed === true);
  tbClock.close();

  // A mistyped clock has to be refused where it is CONFIGURED. `opts.clock ||
  // Date.now` accepts a number or a string as readily as a function, and the
  // failure then surfaces inside backend.take() — which this middleware catches
  // and fails open. So the wrong type would not raise at boot; it would quietly
  // stop limiting every request, which is the opposite of what configuring a
  // rate limiter is for.
  [12345, "now", {}, []].forEach(function (bad) {
    var threw = null;
    try {
      b.middleware.rateLimit({ max: 1, windowMs: 1000, algorithm: "fixed-window", clock: bad });      // allow:raw-time-literal — test-only window
    } catch (e) { threw = e; }
    check("middleware.rateLimit refuses a non-function clock at create: " +
          JSON.stringify(bad), threw !== null, "accepted " + JSON.stringify(bad));
  });
  var okThrew = null;
  try {
    b.middleware.rateLimit({ max: 1, windowMs: 1000, algorithm: "fixed-window",                        // allow:raw-time-literal — test-only window
      clock: function () { return 1; } });
  } catch (e) { okThrew = e; }
  check("middleware.rateLimit accepts a function clock",
    okThrew === null, okThrew && okThrew.message);

  // But not for a window that spans processes. The cluster backend derives its
  // boundary from this reading and writes it into a row every node upserts
  // against, keeping whichever windowStart is newer — so two nodes on different
  // clocks stop sharing a window, the node running ahead keeps resetting the
  // shared counter, and the cluster-wide limit is not the limit anyone gets.
  // A process-local monotonic reading is exactly the shape a caller supplies,
  // and nothing here can distinguish it from an epoch-accurate one. Refused at
  // configuration rather than ignored, so a caller cannot believe their clock
  // is governing a budget it is not.
  var clusterThrew = null;
  try {
    b.middleware.rateLimit({ backend: "cluster", limit: 1, windowMs: 1000,                             // allow:raw-time-literal — test-only window
      clock: function () { return 1; } });
  } catch (e) { clusterThrew = e; }
  check("middleware.rateLimit refuses a caller clock on the cluster backend",
    clusterThrew !== null && /cluster/.test(String(clusterThrew.message)),
    clusterThrew && clusterThrew.message);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
