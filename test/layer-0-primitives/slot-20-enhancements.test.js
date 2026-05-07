"use strict";
/**
 * Slot 20 (v0.8.40) operator enhancements — direct test references for
 * b.honeytoken, b.middleware.cspReport, b.auditTools.forensicSnapshot,
 * and b.network.tls.pinsetDriftMonitor.
 *
 * Per CLAUDE.md rule §6 every new operator-facing primitive needs at
 * least one test reference; the test-coverage gate is satisfied by
 * naming `b.<primitive>` somewhere under test/layer-0-primitives/.
 *
 * Run standalone: `node test/layer-0-primitives/slot-20-enhancements.test.js`
 */

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function _testHoneytoken() {
  var honey = b.honeytoken.create({});
  check("honeytoken.create returns issue/lookup/revoke",
    typeof honey.issue === "function" && typeof honey.lookup === "function" &&
    typeof honey.revoke === "function" && typeof honey.size === "function");

  var issued = honey.issue({ kind: "apiKey", metadata: { plantedAt: "test" } });
  check("honeytoken.issue: returns id + value",
    typeof issued.id === "string" && typeof issued.value === "string" &&
    issued.value.indexOf("bk_canary_") === 0);

  var record = honey.lookup(issued.value, { ip: "203.0.113.5" });
  check("honeytoken.lookup: tripped record returned",
    record && record.id === issued.id && record.kind === "apiKey");

  check("honeytoken.lookup: unknown value returns null",
    honey.lookup("not-a-canary") === null);

  check("honeytoken.revoke: known id removed",
    honey.revoke(issued.id) === true && honey.size() === 0);

  var threw;
  try { honey.issue({ kind: "garbage" }); } catch (e) { threw = e; }
  check("honeytoken.issue: unknown kind throws",
    threw && threw.code === "honeytoken/unknown-kind");

  check("honeytoken.KINDS exports the supported list",
    Array.isArray(b.honeytoken.KINDS) && b.honeytoken.KINDS.indexOf("apiKey") !== -1);

  check("honeytoken.HoneytokenError class registered",
    typeof b.honeytoken.HoneytokenError === "function");
}

async function _testCspReport() {
  var middleware = b.middleware.cspReport({});
  check("middleware.cspReport returns a function", typeof middleware === "function");

  // Reject non-POST quickly — uses fake req/res shape.
  var sent = {};
  var req = { method: "GET", headers: {} };
  var res = {
    headersSent: false,
    writeHead: function (s, h) { sent.status = s; sent.headers = h; },
    end:       function () { sent.ended = true; },
  };
  await middleware(req, res, function () {});
  check("middleware.cspReport: GET returns 405",
    sent.status === 405 && sent.ended === true);
}

async function _testForensicSnapshot() {
  // Validation path only — without a real audit DB the call would fail
  // on the read-rows step. We exercise the reason / passphrase /
  // outDir guards.
  var threw;
  try { await b.auditTools.forensicSnapshot({}); } catch (e) { threw = e; }
  check("auditTools.forensicSnapshot: missing passphrase throws",
    threw && /passphrase/i.test(threw.message));

  var tmpParent = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fs-"));
  var tmpOut = path.join(tmpParent, "fs-out");
  var threw2;
  try {
    await b.auditTools.forensicSnapshot({
      out: tmpOut, passphrase: "test-pass-".padEnd(32, "x"),
      since: Date.now() - 60000,
    });
  } catch (e) { threw2 = e; }
  check("auditTools.forensicSnapshot: missing reason throws",
    threw2 && /reason/i.test(threw2.message));
}

async function _testPinsetDriftMonitor() {
  var threw;
  try { b.network.tls.pinsetDriftMonitor({}); } catch (e) { threw = e; }
  check("network.tls.pinsetDriftMonitor: missing intervalMs throws",
    threw && threw.code === "tls/bad-interval");

  // Capture baseline (empty trust store still captures an empty array)
  // so the monitor has a reference to compare against.
  b.network.tls.captureBaselineFingerprints();
  var monitor = b.network.tls.pinsetDriftMonitor({
    intervalMs: 60_000,
    audit: false,
  });
  check("network.tls.pinsetDriftMonitor: returns stop handle",
    monitor && typeof monitor.stop === "function");
  monitor.stop();
}

async function run() {
  await _testHoneytoken();
  await _testCspReport();
  await _testForensicSnapshot();
  await _testPinsetDriftMonitor();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[slot-20-enhancements] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
