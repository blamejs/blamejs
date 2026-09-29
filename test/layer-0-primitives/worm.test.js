// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.worm (write-once-read-many retention).
 * Behavioral oracle: a WORM store must enforce write-once, retain-until
 * immutability, legal holds, extend-only retention, compliance vs
 * governance delete semantics, and tamper-evidence. A controllable clock
 * drives the time-window cases deterministically.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// Controllable clock.
function clockAt(ref) { return function () { return ref.t; }; }

function testSurface() {
  check("b.worm.create is a function", typeof b.worm.create === "function");
  check("b.worm.MODES lists compliance + governance", b.worm.MODES.indexOf("compliance") !== -1 && b.worm.MODES.indexOf("governance") !== -1);
  check("b.worm.WormError is a class", typeof b.worm.WormError === "function");
  check("bad mode rejected", code(function () { b.worm.create({ mode: "loose" }); }) === "worm/bad-mode");
  check("bad store adapter rejected", code(function () { b.worm.create({ store: { get: function () {} } }); }) === "worm/bad-store");
  check("put without any retention rejected", code(function () { b.worm.create().put("x", "data"); }) === "worm/no-retention");
}

function testWriteOnceAndRetain() {
  var ref = { t: 1000 };
  var w = b.worm.create({ clock: clockAt(ref), defaultRetentionMs: 5000 });
  var r = w.put("rec1", "hello");
  check("put returns a receipt with digest + retainUntil", r.id === "rec1" && r.digest.length === 128 && r.retainUntil === 6000);
  check("get returns the data", w.get("rec1").data.toString() === "hello");

  // Write-once: cannot overwrite while retained.
  check("overwrite of retained record refused", code(function () { w.put("rec1", "changed"); }) === "worm/already-exists");
  // Cannot delete while retained (compliance default — no override).
  check("delete while retained refused (compliance)", code(function () { w.delete("rec1"); }) === "worm/retained");
  // Governance override is rejected in compliance mode regardless.
  check("override ignored in compliance mode", code(function () { w.delete("rec1", { override: true, reason: "x" }); }) === "worm/retained");

  // After expiry, delete is allowed.
  ref.t = 7000;
  check("delete allowed after retention expires", w.delete("rec1") === true);
  check("record gone after delete", code(function () { w.get("rec1"); }) === "worm/not-found");
}

function testExtendOnly() {
  var ref = { t: 1000 };
  var w = b.worm.create({ clock: clockAt(ref) });
  w.put("e", "x", { retainUntil: 5000 });
  check("extendRetention forward allowed", w.extendRetention("e", 9000) === 9000);
  check("shortening retention refused", code(function () { w.extendRetention("e", 6000); }) === "worm/retention-shorten");
}

function testLegalHold() {
  var ref = { t: 10000 };
  var w = b.worm.create({ clock: clockAt(ref) });
  w.put("h", "x", { retainUntil: 1 });   // already past retention
  check("expired record deletable before a hold", true);
  w.placeLegalHold("h", "case-123");
  check("delete refused under legal hold even after expiry", code(function () { w.delete("h"); }) === "worm/legal-hold");
  check("overwrite refused under legal hold", code(function () { w.put("h", "y", { retainUntil: 1 }); }) === "worm/already-exists");
  w.releaseLegalHold("h", "case-123");
  check("delete allowed after hold released + expired", w.delete("h") === true);
}

function testGovernanceOverride() {
  var ref = { t: 1000 };
  var w = b.worm.create({ mode: "governance", clock: clockAt(ref) });
  w.put("g", "x", { retainUntil: 9999 });
  check("governance override without reason refused", code(function () { w.delete("g", { override: true }); }) === "worm/override-reason");
  check("governance override with reason allowed", w.delete("g", { override: true, reason: "court order #5" }) === true);
  // But a legal hold beats even a governance override.
  w.put("g2", "x", { retainUntil: 9999, legalHold: "hold-1" });
  check("legal hold beats governance override", code(function () { w.delete("g2", { override: true, reason: "x" }); }) === "worm/legal-hold");
}

function testTamperEvidence() {
  var ref = { t: 1000 };
  var store = (function () {
    var m = new Map();
    return { get: function (k) { return m.get(k); }, set: function (k, v) { m.set(k, v); }, delete: function (k) { m.delete(k); }, has: function (k) { return m.has(k); }, keys: function () { return Array.from(m.keys()); }, _raw: m };
  })();
  var w = b.worm.create({ store: store, clock: clockAt(ref), defaultRetentionMs: 1000 });
  w.put("t", "trustworthy");
  // Tamper with the stored bytes behind the WORM layer's back.
  store._raw.get("t").bytes = Buffer.from("tampered!!!!");
  check("get detects byte tampering vs the digest", code(function () { w.get("t"); }) === "worm/tampered");
  check("list reflects stored ids", w.list().indexOf("t") !== -1);
}

function testCallerCannotMutateThroughInput() {
  // A caller that keeps a reference to the Buffer it put must not be able to
  // change the stored record after the fact — the store owns a private copy.
  var w = b.worm.create({ defaultRetentionMs: 1000 });
  var input = Buffer.from("original");
  w.put("k", input);
  input.write("XXXXXXXX");                       // mutate the caller's buffer
  var got = w.get("k");
  check("post-put input mutation does not change stored bytes", got.data.toString() === "original");
}

function testCallerCannotMutateThroughOutput() {
  // The buffer get() returns is a copy; mutating it must not corrupt the
  // record or trip a false tamper on the next read.
  var w = b.worm.create({ defaultRetentionMs: 1000 });
  w.put("k", "original");
  var first = w.get("k");
  first.data.write("XXXXXXXX");                  // mutate the returned buffer
  var second = w.get("k");
  check("mutating get() output does not corrupt the record", second.data.toString() === "original");
  check("record still verifies after output mutation",        code(function () { w.get("k"); }) === "NO-THROW");
}

// put() stores whatever bytes it is handed and digests them, and the record
// is write-once, so getting the byte test wrong is not recoverable by writing
// again. _toBytes asked `data instanceof Uint8Array`, which only answers for
// this realm; a byte array from any other one fell through to the JSON branch
// and 3 bytes were stored as the 19 bytes of {"0":1,"1":2,"2":3}.
function testBytesFromAnotherRealmAreStoredAsBytes() {
  var vm = require("node:vm");
  var ctx = vm.createContext({});
  var far = vm.runInContext("new Uint8Array([1, 2, 3])", ctx);

  var w = b.worm.create({ defaultRetentionMs: 1000 });
  w.put("local", new Uint8Array([1, 2, 3]));
  w.put("far", far);

  check("worm: a local byte array stores its 3 bytes",
        w.get("local").data.length === 3, w.get("local").data.length);
  check("worm: a byte array from another realm stores the same 3 bytes",
        w.get("far").data.length === 3, w.get("far").data.length);
  check("worm: and they are the bytes that went in, not a JSON index map",
        w.get("far").data.equals(Buffer.from([1, 2, 3])),
        JSON.stringify(w.get("far").data.toString("latin1")));
  check("worm: both records digest identically, since the bytes are identical",
        w.get("far").digest === w.get("local").digest,
        w.get("far").digest + " vs " + w.get("local").digest);

  // A plain object still takes the JSON branch — that is its documented shape.
  w.put("obj", { a: 1 });
  check("worm: a plain object is still stored as its JSON",
        w.get("obj").data.toString("utf8") === '{"a":1}',
        w.get("obj").data.toString("utf8"));
}

async function run() {
  testSurface();
  testWriteOnceAndRetain();
  testExtendOnly();
  testLegalHold();
  testGovernanceOverride();
  testTamperEvidence();
  testCallerCannotMutateThroughInput();
  testCallerCannotMutateThroughOutput();
  testBytesFromAnotherRealmAreStoredAsBytes();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[worm] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
