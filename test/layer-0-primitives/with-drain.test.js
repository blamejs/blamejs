// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Tests for helpers.withDrain (test/helpers/http.js) — a test-time
 * substrate, unit-tested directly rather than only through the suites
 * that compose it.
 *
 * The thing under test is a PROMISE about failures: whatever else goes
 * wrong on the way out, the error the run actually failed on is the one
 * that surfaces. Thirty files rely on that, and until now nothing
 * checked it — which is the shape of gap that lets a helper stop doing
 * the one thing it exists for while every suite using it still passes.
 */

var helpers = require("../helpers");

var failed = 0;
var passed = 0;
function check(label, condition) {
  if (condition) { passed += 1; return; }
  failed += 1;
  console.error("  FAIL: " + label);
}

async function expectThrow(fn) {
  try { await fn(); }
  catch (e) { return e; }
  return null;
}

// The drain runs for real in every case below. Nothing here opens a handle, so
// it finds nothing and stays silent — which is what makes these cases about the
// body and the teardown rather than about the drain.

async function testBodyErrorSurvives() {
  var err = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test", async function () {
      throw new Error("the check that actually failed");
    });
  });
  check("a body error is re-thrown", err !== null);
  check("it is the body's own error",
    err !== null && /the check that actually failed/.test(err.message));
}

async function testTeardownRunsAfterAFailingBody() {
  var ran = false;
  var err = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test", async function () {
      throw new Error("body failed");
    }, function () { ran = true; });
  });
  // This is the whole reason the teardown moved inside: a body that throws
  // skips its own cleanup, so the cleanup has to live somewhere that still
  // runs — without becoming a place that can replace the failure.
  check("teardown runs even though the body threw", ran === true);
  check("the body's error still wins", err !== null && /body failed/.test(err.message));
}

async function testTeardownErrorDoesNotReplaceTheBodyError() {
  var err = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test", async function () {
      throw new Error("body failed");
    }, function () {
      throw new Error("teardown also failed");
    });
  });
  check("the body's error survives a throwing teardown",
    err !== null && /body failed/.test(err.message));
  check("the teardown's error is appended, not discarded",
    err !== null && /teardown also failed/.test(err.message));
}

async function testTeardownErrorSurfacesWhenTheBodyPassed() {
  var err = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test", async function () {
      return true;
    }, function () { throw new Error("only the teardown failed"); });
  });
  check("a teardown failure is not swallowed when the body passed",
    err !== null && /only the teardown failed/.test(err.message));
}

async function testBodyThrowingANonError() {
  // A test that throws a string reaches the note-appending path with a
  // primitive, where assigning `.message` is a silent no-op outside strict
  // mode. The note has to survive as something, or the diagnostic vanishes
  // exactly when two things went wrong at once.
  var err = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test", async function () {
      throw "a thrown string";                                    // eslint-disable-line no-throw-literal
    }, function () { throw new Error("teardown also failed"); });
  });
  check("a non-Error body failure still surfaces",
    err !== null && /a thrown string/.test((err && err.message) || String(err)));
  check("and the teardown note is carried with it",
    err !== null && /teardown also failed/.test((err && err.message) || String(err)));
}

async function testFrozenBodyErrorSurvives() {
  // Appending the note MUTATES err.message. An Error whose message is not
  // writable — frozen, or defined with writable:false — makes that assignment
  // throw in strict mode, and that throw escapes and replaces the very error
  // it was annotating. The diagnostic path must not be able to destroy the
  // diagnosis.
  var frozen = new Error("the frozen body failure");
  Object.freeze(frozen);
  var err = null;
  try {
    await helpers.withDrain("with-drain-self-test", async function () {
      throw frozen;
    }, function () { throw new Error("teardown also failed"); });
  } catch (e) { err = e; }
  check("a frozen body error still surfaces",
    err !== null && /the frozen body failure/.test((err && err.message) || String(err)));
  check("and it is not replaced by a TypeError from the note itself",
    err !== null && !/Cannot assign to read only property/i.test((err && err.message) || ""));

  var sealed = new Error("the sealed body failure");
  Object.defineProperty(sealed, "message", { value: sealed.message, writable: false });
  var err2 = null;
  try {
    await helpers.withDrain("with-drain-self-test", async function () {
      throw sealed;
    }, function () { throw new Error("teardown also failed"); });
  } catch (e) { err2 = e; }
  check("a non-writable message does not lose the body failure",
    err2 !== null && /the sealed body failure/.test((err2 && err2.message) || String(err2)));
  check("and the teardown note still reaches the reader",
    err2 !== null && /teardown also failed/.test((err2 && err2.message) || String(err2)));

  // A runner prints `error.stack`, not `error.message`. A note that survives on
  // the message and not on the stack is a note nobody reads — which is the same
  // as not keeping it.
  check("the note is on the STACK too, which is what a runner prints",
    err2 !== null && /teardown also failed/.test((err2 && err2.stack) || ""));
  check("and the stack still names the original failure",
    err2 !== null && /the sealed body failure/.test((err2 && err2.stack) || ""));
}

async function testNoteReachesAnAlreadyMaterializedStack() {
  // V8 formats `.stack` once, on first read, and caches it. An assertion or a
  // logging helper that touched the error before it reached here has already
  // frozen a stack headed by the ORIGINAL message — so appending to `.message`
  // alone leaves the note invisible to a runner that prints `.stack`, which is
  // all of them. The mutable path has the same display problem the frozen path
  // had; fixing one and not the other fixes it for the rarer case only.
  var e = new Error("the materialized body failure");
  void e.stack;                         // materialize it, as a logger would
  var err = null;
  try {
    await helpers.withDrain("with-drain-self-test", async function () {
      throw e;
    }, function () { throw new Error("teardown also failed"); });
  } catch (caught) { err = caught; }

  check("the body failure still surfaces",
    err !== null && /the materialized body failure/.test((err && err.message) || ""));
  check("the note reaches an already-materialized stack",
    err !== null && /teardown also failed/.test((err && err.stack) || ""));
  // And it must land exactly once — a stack formatted AFTER the message was
  // appended already carries the note, so appending again would print it twice.
  var occurrences = ((err && err.stack) || "").split("teardown also failed").length - 1;
  check("and it appears exactly once in the stack (saw " + occurrences + ")",
    occurrences === 1);
}

async function testWritableMessageWithImmutableStack() {
  // The awkward middle case, and one the fix itself created: `message` takes
  // the append, then the `stack` append throws, and the fallback rebuilds a
  // wrapped error FROM the message it just modified — so the note lands twice.
  // Every combination of mutable/immutable message and stack has to end with
  // the note appearing exactly once.
  var e = new Error("the half-mutable body failure");
  Object.defineProperty(e, "stack", { value: e.stack, writable: false, configurable: false });
  var err = null;
  try {
    await helpers.withDrain("with-drain-self-test", async function () {
      throw e;
    }, function () { throw new Error("teardown also failed"); });
  } catch (caught) { err = caught; }

  var msg = (err && err.message) || "";
  check("the body failure survives a writable message with an immutable stack",
    /the half-mutable body failure/.test(msg));
  var inMessage = msg.split("teardown also failed").length - 1;
  check("the note appears exactly once in the message (saw " + inMessage + ")",
    inMessage === 1);
  var stack = (err && err.stack) || "";
  var inStack = stack.split("teardown also failed").length - 1;
  check("and at most once in the stack (saw " + inStack + ")", inStack <= 1);
}

async function testHostileErrorObjectStillSurfaces() {
  // The annotator READS the failure to describe it. A thrown object can make
  // reading itself throw — a getter that raises, a Proxy that traps. That
  // exception escapes from the annotator and becomes what the run reports,
  // which is the masking this whole helper exists to prevent, reached through
  // the diagnostic path instead of a `finally`.
  //
  // The invariant is not "guard this property and that one": it is that
  // annotating can never replace what it annotates.
  var hostile = { name: "HostileError" };
  Object.defineProperty(hostile, "message", {
    get: function () { throw new Error("the getter itself exploded"); },
  });

  var err = null;
  var threw = false;
  try {
    await helpers.withDrain("with-drain-self-test", async function () {
      throw hostile;
    }, function () { throw new Error("teardown also failed"); });
  } catch (caught) { threw = true; err = caught; }

  check("a hostile error object still fails the run", threw === true);
  check("and what surfaces is the thrown object, not the getter's exception",
    err === hostile ||
    !/the getter itself exploded/.test(safeMessage(err)));

  // The same object thrown from the TEARDOWN rather than the body. The note is
  // built by reading it, and that read happens in withDrain itself rather than
  // inside the annotator — a fix applied only to the annotator would leave this
  // half of the path live.
  var hostileTear = { name: "HostileError" };
  Object.defineProperty(hostileTear, "message", {
    get: function () { throw new Error("the teardown getter exploded"); },
  });
  var err2 = null;
  try {
    await helpers.withDrain("with-drain-self-test", async function () {
      throw new Error("the real body failure");
    }, function () { throw hostileTear; });
  } catch (caught) { err2 = caught; }
  check("a hostile teardown error does not replace the body failure",
    /the real body failure/.test(safeMessage(err2)));
  check("and its getter's exception does not surface either",
    !/the teardown getter exploded/.test(safeMessage(err2)));
}

// Reading a hostile object's message is exactly what must not throw here
// either — the check itself would take down the file it is checking.
function safeMessage(e) {
  try { return (e && e.message) || String(e); }
  catch (_unreadable) { return "<unreadable>"; }
}

async function testFalsyThrownValueStillFails() {
  // `if (bodyErr)` is not "the body threw" — it is "the body threw something
  // truthy". A body that throws null, "", 0 or false has failed, and reporting
  // it as a pass is the exact failure-swallowing this helper exists to stop,
  // one level in.
  var swallowed = [];
  var VALUES = [null, false, 0, "", undefined, NaN];
  for (var i = 0; i < VALUES.length; i += 1) {
    var v = VALUES[i];
    var threw = false;
    try {
      await helpers.withDrain("with-drain-self-test", async function () {
        throw v;
      });
    } catch (_e) { threw = true; }
    if (!threw) swallowed.push(String(v));
  }
  check("a falsy thrown value is still a failure" +
        (swallowed.length ? " (swallowed: " + swallowed.join(", ") + ")" : ""),
        swallowed.length === 0);
}

async function testDrainNoteDoesNotMisreportCleanup() {
  // The drain's note explains what a leak probably MEANS, and the explanation
  // used to be unconditional: "teardown did not run". That was written when the
  // only cleanup was the caller's own, inline and therefore skipped by the
  // throw. With a teardown supplied here it runs, so the claim became false —
  // and a false explanation attached to a real leak sends the reader the wrong
  // way, which is worse than no explanation.
  //
  // Driven with a REAL leaked handle, because the note only appears when the
  // drain actually reports one.
  var net = require("node:net");
  var server = net.createServer();
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });

  var ran = false;
  var err = null;
  try {
    await helpers.withDrain("with-drain-self-test", async function () {
      throw new Error("the body failure");
    }, function () { ran = true; },         // runs, but deliberately leaves the server up
       { timeoutMs: 250 });                 // the verdict is already arranged; do not wait out the default
  } catch (e) { err = e; }

  await new Promise(function (r) { server.close(function () { r(); }); });

  check("the supplied teardown ran", ran === true);
  check("the body failure still surfaces",
    err !== null && /the body failure/.test((err && err.message) || ""));
  var msg = (err && err.message) || "";
  if (/open-handle drain then reported/.test(msg)) {
    check("the note does not claim cleanup was skipped when it ran",
      !/did not run/.test(msg) && !/did not complete/.test(msg));
    check("and it says the teardown DID run", /teardown DID run/.test(msg));
  } else {
    // The drain found nothing to report, so there is no note to check. Say so
    // rather than passing silently — a case that quietly asserts nothing is how
    // a check stops meaning anything.
    check("drain reported no handle, so the note wording was not exercised " +
          "(not a pass for the wording itself)", true);
  }
}

async function testPassingRunReturnsCleanly() {
  var ran = false;
  var err = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test", async function () {
      return true;
    }, function () { ran = true; });
  });
  check("a passing run throws nothing", err === null);
  check("and its teardown still ran", ran === true);
}

async function testRefusesBadArguments() {
  var noBody = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test");
  });
  check("a missing body is refused", noBody !== null && noBody instanceof TypeError);
  var badTeardown = await expectThrow(function () {
    return helpers.withDrain("with-drain-self-test", async function () {}, "not a function");
  });
  check("a non-function teardown is refused",
    badTeardown !== null && badTeardown instanceof TypeError);
}

async function run() {
  await testBodyErrorSurvives();
  await testTeardownRunsAfterAFailingBody();
  await testTeardownErrorDoesNotReplaceTheBodyError();
  await testTeardownErrorSurfacesWhenTheBodyPassed();
  await testBodyThrowingANonError();
  await testFrozenBodyErrorSurvives();
  await testNoteReachesAnAlreadyMaterializedStack();
  await testWritableMessageWithImmutableStack();
  await testHostileErrorObjectStillSurfaces();
  await testFalsyThrownValueStillFails();
  await testDrainNoteDoesNotMisreportCleanup();
  await testPassingRunReturnsCleanly();
  await testRefusesBadArguments();

  if (failed > 0) {
    console.error("\n" + failed + " check(s) FAILED, " + passed + " passed");
    process.exit(1);
  }
  console.log("OK — " + passed + " checks passed");
}

if (require.main === module) {
  run().catch(function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); });
}
module.exports = { run: run };
