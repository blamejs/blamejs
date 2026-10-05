// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.password — Argon2id hashing + verify + needsRehash + the
 * b.auth.password.policy() presentation-time gate (length / common /
 * dictionary / context / complexity / HIBP breach check).
 *
 * This file exercises the ERROR, ADVERSARIAL, DEFENSIVE and
 * OPTION-DEFAULT branches: config-time throws (bad params / bad
 * policy), fail-closed request-shape readers (verify tolerates garbage
 * by returning false), the concurrency semaphore's queue path, and the
 * HIBP breach-check response handling — network error, non-200,
 * poisoned-mirror, match and no-match — driven through an injected
 * http-client stub (NEVER real network). Sibling
 * auth-password-audit.test.js covers b.auth.password.params().
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// The password policy's HIBP breach check calls httpClient.request.
// password.js captures `require("../http-client")` (the shared module
// object) once at load; requiring the same resolved path here hands
// back that identical object, so replacing `.request` injects a stub
// into the live consumer path with no real network. Each test restores
// the original in a finally. Layer-0 files fork into their own process
// (smoke isolation), so this patch never bleeds into a sibling file.
var httpClient = require("../../lib/http-client");
// The framework's own SHA-1 (the only in-process SHA-1, HIBP-only) —
// used here to build a REALISTIC k-anonymity response body whose suffix
// matches the plaintext under test, not to mock anything.
var hibpSha1 = require("../../lib/framework-sha1-hibp");

// Fast Argon2 params for round-trip tests — the framework default of
// 64 MiB / t=3 / p=4 is ~250-500ms per call; 1 MiB / t=1 / p=1 keeps
// the suite quick while still driving the real vendor hash + verify.
var FAST = { memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 1 };

// ---- hash / verify happy path + defensive readers ------------------

async function testHashVerifyRoundtrip() {
  var h = await b.auth.password.hash("hunter2", FAST);
  check("hash produces argon2id PHC string", h.indexOf("$argon2id$") === 0);
  check("verify matches the original plaintext",
        (await b.auth.password.verify(h, "hunter2")) === true);
  check("verify rejects a wrong plaintext (returns false, not throw)",
        (await b.auth.password.verify(h, "wrong")) === false);
}

async function testHashRejectsBadPlain() {
  var threwEmpty, threwType, threwBig;
  try { await b.auth.password.hash(""); } catch (e) { threwEmpty = e; }
  check("hash: empty plaintext throws invalid-plain",
        threwEmpty && threwEmpty.code === "auth-password/invalid-plain");
  try { await b.auth.password.hash(12345); } catch (e) { threwType = e; }
  check("hash: non-string plaintext throws invalid-plain",
        threwType && threwType.code === "auth-password/invalid-plain");
  // 4 KiB is the plaintext cap; one byte over must be refused.
  var oversize = "a".repeat(b.constants.BYTES.kib(4) + 1);
  try { await b.auth.password.hash(oversize, FAST); } catch (e) { threwBig = e; }
  check("hash: oversize plaintext throws plain-too-large",
        threwBig && threwBig.code === "auth-password/plain-too-large");
}

async function testHashRejectsBadParams() {
  var threwMem, threwTime, threwPar;
  try {
    await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(1) - 1, timeCost: 1, parallelism: 1 });
  } catch (e) { threwMem = e; }
  check("hash: memoryCost below 1 MiB floor throws bad-params",
        threwMem && threwMem.code === "auth-password/bad-params");
  try {
    await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(1), timeCost: 0, parallelism: 1 });
  } catch (e) { threwTime = e; }
  check("hash: timeCost below 1 throws bad-params",
        threwTime && threwTime.code === "auth-password/bad-params");
  try {
    await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 0 });
  } catch (e) { threwPar = e; }
  check("hash: parallelism below 1 throws bad-params",
        threwPar && threwPar.code === "auth-password/bad-params");
}

// verify() ran Argon2id with whatever `m`, `t` and `p` the STORED string named,
// and the PHC decode accepted any finite integer for each, so a stored
// `$argon2id$v=19$m=4194304,t=1,p=1$...` asked for 4 GiB on a login attempt and a
// large `t` ran for as long as it said. Stored hashes usually come from this
// module's own hash(), but some arrive from configuration, an import or a
// restored backup. The cost is bounded before Argon2id is entered now, and
// because verify() must never throw on a bad stored value, an over-ceiling hash
// answers false instead of raising.
// The gate counted only hash() and verify(), and nothing reported or bounded it.
// Three defects in one mechanism: `_release` handed its slot to the next waiter
// whenever one was queued and only decremented when the list was empty, so a
// lowered gate(n) took effect only after the queue drained; the waiter list had
// no bound and no timeout; and no function reported how many were running or
// waiting. Argon2id also ran ungated in backup/crypto, vault/wrap and the
// password policy's reuse check, so a consumer lowering the gate to bound memory
// still got those on top.
async function testGateBoundsEveryArgon2Run() {
  // memoryCost is counted in KiB, so BYTES.kib(1) is one MiB of working set.
  var cheap = { memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 1 };
  var holds = { memoryCost: b.constants.BYTES.kib(16), timeCost: 2, parallelism: 1 };
  var before = b.auth.password.stats();
  check("stats reports the gate's shape",
    before && typeof before.running === "number" && typeof before.waiting === "number" &&
    typeof before.limit === "number", JSON.stringify(before));

  // A lowered limit applies to the slots, not only to an empty queue.
  b.auth.password.gate(1, { maxQueued: 1, waitTimeoutMs: 0 });
  var a = b.auth.password.hash("pw-123456", cheap);
  var queued = b.auth.password.hash("pw-123456", cheap);
  var mid = b.auth.password.stats();
  check("one run holds the only slot and the next waits",
    mid.running === 1 && mid.waiting === 1, JSON.stringify(mid));

  var threw = null;
  try { await b.auth.password.hash("pw-123456", cheap); }
  catch (e) { threw = e; }
  check("a run past maxQueued refuses rather than queueing without bound",
    threw !== null && threw.code === "argon2/busy", "code=" + (threw && threw.code));
  await Promise.all([a, queued]);

  // A waiter that cannot get a slot in time gives up instead of waiting forever.
  b.auth.password.gate(1, { maxQueued: 8, waitTimeoutMs: 1 });
  var hold = b.auth.password.hash("pw-123456", holds);
  var timedOut = null;
  try { await b.auth.password.hash("pw-123456", cheap); }
  catch (e) { timedOut = e; }
  check("a waiter past waitTimeoutMs rejects with a typed code",
    timedOut !== null && timedOut.code === "argon2/queue-timeout",
    "code=" + (timedOut && timedOut.code));
  await hold;

  // The other three Argon2id callers go through the same gate now.
  b.auth.password.gate(1, { maxQueued: 0, waitTimeoutMs: 0 });
  var slow = b.auth.password.hash("pw-123456", holds);
  var vaultRefused = null;
  try {
    await require("../../lib/vault/wrap").deriveWrappingKey(
      "passphrase-123456", Buffer.alloc(16, 7), { memoryCost: 1024, timeCost: 1, parallelism: 1 });
  } catch (e) { vaultRefused = e; }
  check("a vault key derivation is counted against the same gate",
    vaultRefused !== null && vaultRefused.code === "argon2/busy",
    "code=" + (vaultRefused && vaultRefused.code));
  await slow;

  // verify and the policy's reuse check wait on the same gate, and its refusals
  // have to reach the caller. argon2.verify answered false for them, so a
  // correct password read as wrong under load, and the reuse check reported no
  // reuse, which approves a password the policy exists to refuse.
  var storedCheap = await b.auth.password.hash("pw-123456", cheap);
  var pol = b.auth.password.policy({ historyMinDistance: 1, useBundledCommon: false });

  var holdForVerify = b.auth.password.hash("pw-123456", holds);
  var verifyRefused = null;
  try { await b.auth.password.verify(storedCheap, "pw-123456"); }
  catch (e) { verifyRefused = e; }
  check("verify surfaces the gate's refusal rather than answering false",
    verifyRefused !== null && verifyRefused.code === "argon2/busy",
    "code=" + (verifyRefused && verifyRefused.code));
  await holdForVerify;

  var holdForReuse = b.auth.password.hash("pw-123456", holds);
  var reuseRefused = null;
  try { await pol.reuseProhibited("pw-123456", [storedCheap]); }
  catch (e) { reuseRefused = e; }
  check("the reuse check surfaces the gate's refusal rather than reporting no reuse",
    reuseRefused !== null && reuseRefused.code === "argon2/busy",
    "code=" + (reuseRefused && reuseRefused.code));
  await holdForReuse;

  // A consumer that wraps the derivation in a catch-all is where the refusal
  // stops being recognizable. b.archive.unwrapWithPassphrase reported a valid
  // archive as archive-wrap/decrypt-failed, which is permanent, so a caller
  // reading it goes looking for a wrong passphrase instead of retrying.
  b.auth.password.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });
  var sealedArchive = await b.archive.wrapWithPassphrase(
    Buffer.from("archive-bytes"), { passphrase: "operator-supplied-long-passphrase" });

  b.auth.password.gate(1, { maxQueued: 0, waitTimeoutMs: 0 });
  var holdForArchive = b.auth.password.hash("pw-123456", holds);
  var archiveRefused = null;
  try {
    await b.archive.unwrapWithPassphrase(sealedArchive,
      { passphrase: "operator-supplied-long-passphrase" });
  } catch (e) { archiveRefused = e; }
  check("a passphrase-sealed archive surfaces the gate's refusal rather than " +
        "reporting the archive as undecryptable",
    archiveRefused !== null && archiveRefused.code === "argon2/busy",
    "code=" + (archiveRefused && archiveRefused.code));
  check("and that refusal is retryable, which a translated one is not",
    archiveRefused !== null && b.retry.isRetryable(archiveRefused) === true,
    "permanent=" + (archiveRefused && archiveRefused.permanent));
  await holdForArchive;

  // A refusal is only retryable if nothing irreversible happened first.
  // b.backup.bundle.create created outDir and its files/ subdirectory before
  // deriving, so a refusal left both behind and the retry it invites failed
  // permanently with backup-bundle/outdir-exists.
  var nodeFs = require("node:fs");
  var nodeOs = require("node:os");
  var nodePath = require("node:path");
  var bundleRoot = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "pw-gate-bundle-"));
  var bundleOut = nodePath.join(bundleRoot, "out");
  var holdForBundle = b.auth.password.hash("pw-123456", holds);
  var bundleRefused = null;
  try {
    await b.backupBundle.create({
      dataDir: bundleRoot,
      outDir: bundleOut,
      passphrase: "operator-supplied-long-passphrase",
      vaultKeyJson: "{\"kem\":\"ml-kem-1024\"}",
      files: [{ relativePath: "vault.key", absolutePath: nodePath.join(bundleRoot, "vault.key") }],
    });
  } catch (e) { bundleRefused = e; }
  check("a bundle create surfaces the gate's refusal",
    bundleRefused !== null && bundleRefused.code === "argon2/busy",
    "code=" + (bundleRefused && bundleRefused.code));
  check("and leaves no output directory behind, so the retry it invites can run",
    !nodeFs.existsSync(bundleOut), bundleOut);
  await holdForBundle;
  try { nodeFs.rmSync(bundleRoot, { recursive: true, force: true }); }
  catch (_e) { /* best-effort */ }

  // A refusal must not skip a secure-zero either. vaultWrap.wrap copies a
  // string plaintext into a buffer it owns, which is how the vault key and the
  // audit-signing private key reach it, and the cleanup used to begin after the
  // derivation: a refusal left that copy to the garbage collector. The zeroing
  // is observed by recording the calls, since the buffer is internal to wrap.
  var safeBufferModule = require("../../lib/safe-buffer");
  var realSecureZero = safeBufferModule.secureZero;
  var zeroedLengths = [];
  safeBufferModule.secureZero = function (buf) {
    if (buf && typeof buf.length === "number") zeroedLengths.push(buf.length);
    return realSecureZero.apply(this, arguments);
  };
  var wrapRefused = null;
  var secretPlaintext = "{\"privateKey\":\"a-generated-signing-key\"}";
  var holdForWrap = b.auth.password.hash("pw-123456", holds);
  try {
    await require("../../lib/vault/wrap").wrap(secretPlaintext, "passphrase-123456");
  } catch (e) { wrapRefused = e; }
  finally { safeBufferModule.secureZero = realSecureZero; }
  check("a wrap refused by the gate surfaces the refusal",
    wrapRefused !== null && wrapRefused.code === "argon2/busy",
    "code=" + (wrapRefused && wrapRefused.code));
  check("and still zeroes the plaintext copy it owns",
    zeroedLengths.indexOf(Buffer.byteLength(secretPlaintext, "utf8")) !== -1,
    "zeroed=" + zeroedLengths.join(","));
  await holdForWrap;

  // The control: with the gate open all of them answer normally, so the
  // assertions above read the gate rather than a broken hash, policy or archive.
  b.auth.password.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });
  check("verify answers true once the gate is open",
    (await b.auth.password.verify(storedCheap, "pw-123456")) === true);
  check("the reuse check reports the reuse once the gate is open",
    (await pol.reuseProhibited("pw-123456", [storedCheap])) === true);
  check("the archive opens once the gate is open",
    (await b.archive.unwrapWithPassphrase(sealedArchive,
      { passphrase: "operator-supplied-long-passphrase" })).toString("utf8") ===
      "archive-bytes");

  // A rejected reconfiguration must change nothing. The limits were assigned as
  // each one validated, so a call carrying one bad option raised and left the
  // earlier ones applied: a caller catching the error ran on with a higher
  // concurrency and an unbounded queue it had not asked for.
  b.auth.password.gate(2, { maxQueued: 4, waitTimeoutMs: 100 });
  var beforeBad = b.auth.password.stats();
  var badGate = null;
  try { b.auth.password.gate(8, { maxQueued: Infinity, waitTimeoutMs: -1 }); }
  catch (e) { badGate = e; }
  check("a gate call with a bad waitTimeoutMs is refused",
    badGate !== null && badGate.code === "argon2/bad-gate",
    "code=" + (badGate && badGate.code));
  var afterBad = b.auth.password.stats();
  check("and it leaves every limit as it was",
    afterBad.limit === beforeBad.limit &&
    afterBad.maxQueued === beforeBad.maxQueued &&
    afterBad.waitTimeoutMs === beforeBad.waitTimeoutMs,
    JSON.stringify(beforeBad) + " → " + JSON.stringify(afterBad));

  var badMax = null;
  try { b.auth.password.gate(16, { maxQueued: -3 }); }
  catch (e) { badMax = e; }
  check("a gate call with a bad maxQueued is refused",
    badMax !== null && badMax.code === "argon2/bad-gate",
    "code=" + (badMax && badMax.code));
  check("and that one leaves the limit alone too",
    b.auth.password.stats().limit === beforeBad.limit,
    JSON.stringify(b.auth.password.stats()));

  // The control: a call with every option valid still applies all of them.
  var applied = b.auth.password.gate(3, { maxQueued: 9, waitTimeoutMs: 50 });
  check("a valid reconfiguration applies in full",
    applied.limit === 3 && applied.maxQueued === 9 && applied.waitTimeoutMs === 50,
    JSON.stringify(applied));

  b.auth.password.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });
  var restored = b.auth.password.stats();
  check("the gate restores to its default shape",
    restored.limit === 8 && restored.waiting === 0, JSON.stringify(restored));
}

async function testVerifyBoundsTheStoredCost() {
  // Reading the ceiling must not change it. `undefined` shared the reset
  // branch with `null`, so a read after a deliberate lowering silently put the
  // default back and widened what verify would spend.
  var defaults = b.auth.password.costCeiling();
  check("costCeiling() reports the default before anything sets it",
    defaults.timeCost === 24 && defaults.parallelism === 16,
    JSON.stringify(defaults));
  var lowered = b.auth.password.costCeiling({ timeCost: 12 });
  check("costCeiling sets what it is given", lowered.timeCost === 12);
  check("costCeiling() reads the ceiling in force",
    b.auth.password.costCeiling().timeCost === 12,
    JSON.stringify(b.auth.password.costCeiling()));
  check("and reading it twice still reports it",
    b.auth.password.costCeiling().timeCost === 12);
  check("costCeiling(null) restores the default",
    b.auth.password.costCeiling(null).timeCost === 24);

  // A ceiling under what `hash` writes by default would leave the module
  // refusing every credential it produces, so it is refused rather than set.
  // The same call used to succeed and leave `hash` raising on its own defaults.
  [["memoryCost", 1024], ["timeCost", 2], ["parallelism", 1]].forEach(function (row) {
    var opts = {};
    opts[row[0]] = row[1];
    var refused = null;
    try { b.auth.password.costCeiling(opts); } catch (e) { refused = e; }
    check("costCeiling refuses a " + row[0] + " below the hash default",
      refused !== null && refused.code === "auth-password/bad-ceiling",
      "code=" + (refused && refused.code));
  });
  check("and the ceiling is unchanged by a refused call",
    b.auth.password.costCeiling().timeCost === 24,
    JSON.stringify(b.auth.password.costCeiling()));

  // Typed, so a caller can branch on it. These used to arrive as a bare Error
  // naming `argon2.costCeiling`, a module the caller never invoked.
  [{ memory: 1 }, [], [{ memoryCost: 1024 }], { memoryCost: 2.5 },
   { memoryCost: "600000" }].forEach(function (bad, i) {
    var refused = null;
    try { b.auth.password.costCeiling(bad); } catch (e) { refused = e; }
    check("costCeiling refuses a malformed ceiling [" + i + "] with its own code",
      refused !== null && refused.code === "auth-password/bad-ceiling",
      "code=" + (refused && refused.code));
  });

  // A history entry hashed above the ceiling cannot be verified without
  // spending the work the ceiling exists to refuse, and `verify` answers
  // `false` for it. On a login that is a failed sign-in. In the reuse check,
  // `false` reads as "not one of the old passwords", so the exact historical
  // password was approved for reuse: a fail-open in the control that exists to
  // refuse it. The check must not answer at all.
  b.auth.password.costCeiling({ parallelism: 24 });
  var raisedHash = await b.auth.password.hash("pw-history-123456",
    { memoryCost: b.constants.BYTES.kib(1), timeCost: 2, parallelism: 17 });
  b.auth.password.costCeiling(null);
  check("a hash made above the restored ceiling is over it",
    require("../../lib/argon2-builtin").exceedsCostCeiling(raisedHash) === true);
  check("and verify answers false for it rather than spending the work",
    (await b.auth.password.verify(raisedHash, "pw-history-123456")) === false);

  // `verify` answers false for a wrong password and for a stored hash it
  // cannot check, and `needsRehash` does not separate them either, so an
  // application had no way to tell a failed sign-in from a credential it must
  // stop refusing and re-hash. The discriminator has to be on the public
  // surface beside the ceiling that creates the condition.
  var cheapHash = await b.auth.password.hash("pw-history-123456",
    { memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 1 });
  check("the ceiling check is on the public surface",
    typeof b.auth.password.exceedsCostCeiling === "function");
  check("  and it separates a hash it cannot check from a wrong password",
    b.auth.password.exceedsCostCeiling(raisedHash) === true &&
    b.auth.password.exceedsCostCeiling(cheapHash) === false,
    "raised=" + b.auth.password.exceedsCostCeiling(raisedHash) +
    " cheap=" + b.auth.password.exceedsCostCeiling(cheapHash));
  check("  while verify still answers false for both the wrong password and the one it cannot check",
    (await b.auth.password.verify(cheapHash, "not-the-password")) === false &&
    (await b.auth.password.verify(raisedHash, "pw-history-123456")) === false);
  check("  and a string that is not a stored hash is not reported as over the ceiling",
    b.auth.password.exceedsCostCeiling("not-a-phc-string") === false &&
    b.auth.password.exceedsCostCeiling("") === false);
  var overCeiling = null;
  var reusePolicy = b.auth.password.policy({
    historyMinDistance: 1, useBundledCommon: false,
  });
  try { await reusePolicy.reuseProhibited("pw-history-123456", [raisedHash]); }
  catch (e) { overCeiling = e; }
  check("the reuse check refuses to answer rather than approving the old password",
    overCeiling !== null && overCeiling.code === "auth-password/history-over-ceiling",
    "code=" + (overCeiling && overCeiling.code) +
    " returned=" + JSON.stringify(overCeiling === null));

  // A whole number is what Argon2 takes, and the lower bounds alone let a
  // fractional value through to node's own RangeError on the request path.
  var fractional = null;
  try { await b.auth.password.hash("pw-123456", { timeCost: 3.5 }); }
  catch (e) { fractional = e; }
  check("hash refuses a fractional timeCost as its own bad-params",
    fractional !== null && fractional.code === "auth-password/bad-params",
    "code=" + (fractional && fractional.code));
  var fractionalRehash = null;
  try { b.auth.password.needsRehash("$argon2id$v=19$m=65536,t=3,p=4$eHg$eXk", { parallelism: 4.5 }); }
  catch (e) { fractionalRehash = e; }
  check("and needsRehash does too",
    fractionalRehash !== null && fractionalRehash.code === "auth-password/bad-params",
    "code=" + (fractionalRehash && fractionalRehash.code));

  // A typo'd gate option is this primitive's refusal, not a bare Error from a
  // module the caller never named. The second argument used to be ignored.
  var badGateOpt = null;
  try { b.auth.password.gate(4, { maxQueuedTasks: 64 }); }
  catch (e) { badGateOpt = e; }
  check("gate refuses an unknown option with auth-password/bad-gate",
    badGateOpt !== null && badGateOpt.code === "auth-password/bad-gate",
    "code=" + (badGateOpt && badGateOpt.code));
  var badGateShape = null;
  try { b.auth.password.gate(4, 64); }
  catch (e) { badGateShape = e; }
  check("and a non-object opts the same way",
    badGateShape !== null && badGateShape.code === "auth-password/bad-gate",
    "code=" + (badGateShape && badGateShape.code));
  b.auth.password.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });

  // The tag length is the fourth cost input a stored row decides, so an absurd
  // one reads as a row this cannot decode rather than being asked of Argon2.
  var hugeTag = "$argon2id$v=19$m=65536,t=3,p=4$" +
    Buffer.from("0123456789abcdef").toString("base64url") + "$" +
    Buffer.alloc(4096, 7).toString("base64url");
  check("a stored row carrying an absurd tag length answers false",
    (await b.auth.password.verify(hugeTag, "pw-123456")) === false);
  check("and needsRehash reports it for re-derivation",
    b.auth.password.needsRehash(hugeTag) === true);

  var huge = "$argon2id$v=19$m=4194304,t=1,p=1$" +
    Buffer.from("0123456789abcdef").toString("base64url") + "$" +
    Buffer.from("0123456789abcdef0123456789abcdef").toString("base64url");
  var started = Date.now();
  var ok = await b.auth.password.verify(huge, "pw-123456");
  var elapsedMs = Date.now() - started;
  check("verify: a stored cost over the ceiling answers false", ok === false);
  check("verify: and does so without running Argon2id at that cost",
    elapsedMs < 1000, "elapsedMs=" + elapsedMs);
  check("needsRehash flags the same hash so an operator can re-derive it",
    b.auth.password.needsRehash(huge) === true);

  // `huge` is also cheaper in passes than the default, so it would be flagged
  // either way. This one is over the ceiling and at the defaults everywhere
  // else, so only the ceiling can flag it. Without that check, verify refuses
  // the row forever and needsRehash calls it current, which leaves no path to
  // replacing it.
  var overCeilingOnly = "$argon2id$v=19$m=4194304,t=3,p=4$" +
    Buffer.from("0123456789abcdef").toString("base64url") + "$" +
    Buffer.from("0123456789abcdef0123456789abcdef").toString("base64url");
  check("needsRehash: a hash over the ceiling and current in every other " +
    "parameter is still flagged",
    b.auth.password.needsRehash(overCeilingOnly) === true);
  check("verify: and that hash answers false",
    (await b.auth.password.verify(overCeilingOnly, "pw-123456")) === false);

  // The control: the same parameters with the memory brought back under the
  // ceiling are reported current, so the assertion above reads the ceiling
  // rather than one of the three below-target comparisons.
  var atCeiling = "$argon2id$v=19$m=524288,t=3,p=4$" +
    Buffer.from("0123456789abcdef").toString("base64url") + "$" +
    Buffer.from("0123456789abcdef0123456789abcdef").toString("base64url");
  check("needsRehash: the same hash at the ceiling is reported current",
    b.auth.password.needsRehash(atCeiling) === false);

  // A non-positive cost is not a cost. These decoded before and reached
  // nodeCrypto.argon2 with m=-1 / t=0 / p=0.
  check("verify: negative memoryCost answers false",
    (await b.auth.password.verify("$argon2id$v=19$m=-1,t=1,p=1$eHg$eXk", "pw-123456")) === false);
  check("verify: zero timeCost answers false",
    (await b.auth.password.verify("$argon2id$v=19$m=1024,t=0,p=1$eHg$eXk", "pw-123456")) === false);
  check("verify: zero parallelism answers false",
    (await b.auth.password.verify("$argon2id$v=19$m=1024,t=1,p=0$eHg$eXk", "pw-123456")) === false);

  // Writing a PHC string over the ceiling would store a credential this same
  // process refuses to verify, so hash refuses the parameters instead.
  var hashRefused = null;
  try {
    await b.auth.password.hash("pw-123456",
      { memoryCost: b.constants.BYTES.kib(1024), timeCost: 3, parallelism: 4 });
  } catch (e) { hashRefused = e; }
  check("hash: parameters over the ceiling are refused",
    hashRefused !== null && hashRefused.code === "argon2/cost-over-ceiling",
    "code=" + (hashRefused && hashRefused.code));

  // The ceiling bounds WORK, so it applies to a raw derivation too. This
  // asserted the opposite until 0.21.0, on the reasoning that a raw derivation
  // is a KDF whose cost nothing later reads. That is true and beside the point:
  // the parameters reaching a raw derivation come from a sealed file's header,
  // which `parseHeader` bounds at 4 GiB, so the exemption let a file ask for
  // 1 GiB and get it. The refusal has to arrive before the allocation.
  var rawArgon2 = require("../../lib/argon2-builtin");
  var rawRefused = null;
  try {
    await rawArgon2.hash("pw-123456", {
      memoryCost: 1024, timeCost: 25, parallelism: 1, raw: true,
    });
  } catch (e) { rawRefused = e; }
  check("hash: a raw derivation over the ceiling is refused too",
    rawRefused !== null && rawRefused.code === "argon2/cost-over-ceiling",
    "code=" + (rawRefused && rawRefused.code));

  // And one inside the ceiling still runs, so the check above reads the ceiling
  // rather than refusing every raw derivation.
  var rawWithin = await rawArgon2.hash("pw-123456", {
    memoryCost: 1024, timeCost: 3, parallelism: 1, raw: true,
  });
  check("hash: a raw derivation inside the ceiling still runs",
    Buffer.isBuffer(rawWithin) && rawWithin.length === 32,
    "len=" + (rawWithin && rawWithin.length));

  // A legitimately expensive deployment can raise the ceiling.
  var raised = b.auth.password.costCeiling({ memoryCost: b.constants.BYTES.mib(8) });
  check("costCeiling reports what it set",
    raised && raised.memoryCost === b.constants.BYTES.mib(8));
  // Over the default ceiling of 512 MiB, under the 8 GiB one just set, so a
  // pass here reads the raise rather than the default.
  var within = await b.auth.password.hash("pw-123456",
    { memoryCost: b.constants.BYTES.kib(600), timeCost: 1, parallelism: 1 });
  check("a hash inside the raised ceiling still verifies",
    (await b.auth.password.verify(within, "pw-123456")) === true);
  b.auth.password.costCeiling(null);
}

async function testVerifyDefensiveReturnsFalse() {
  // verify() never throws on garbage — login flows treat false as
  // "credentials didn't match" and shouldn't wrap each call in try/catch.
  check("verify: non-string stored → false",
        (await b.auth.password.verify(null, "pw")) === false);
  check("verify: empty stored → false",
        (await b.auth.password.verify("", "pw")) === false);
  check("verify: non-string plain → false",
        (await b.auth.password.verify("$argon2id$v=19$m=1024,t=1,p=1$x$y", 42)) === false);
  check("verify: empty plain → false",
        (await b.auth.password.verify("$argon2id$v=19$m=1024,t=1,p=1$x$y", "")) === false);
  // Other Argon2 variants are out of spec — verify() refuses without
  // even attempting to validate them.
  check("verify: argon2i variant (wrong prefix) → false",
        (await b.auth.password.verify("$argon2i$v=19$m=1024,t=1,p=1$x$y", "pw")) === false);
  // Oversize plaintext is rejected before touching the vendor.
  var oversize = "a".repeat(b.constants.BYTES.kib(4) + 1);
  check("verify: oversize plain → false",
        (await b.auth.password.verify("$argon2id$v=19$m=1024,t=1,p=1$x$y", oversize)) === false);
  // A corrupted PHC string surfaces as a vendor throw; verify() must
  // swallow it and return false rather than break the login flow.
  check("verify: corrupted argon2id PHC (vendor throws) → false",
        (await b.auth.password.verify("$argon2id$this-is-not-a-valid-phc-body", "pw")) === false);
}

async function testNeedsRehash() {
  var strong = await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(64), timeCost: 3, parallelism: 4 });
  check("needsRehash: hash at current defaults → false",
        b.auth.password.needsRehash(strong) === false);
  // A hash weaker than the requested target must be flagged for rehash.
  var weak = await b.auth.password.hash("pw", FAST);
  check("needsRehash: weaker-than-target hash → true",
        b.auth.password.needsRehash(weak, { memoryCost: b.constants.BYTES.kib(64), timeCost: 3, parallelism: 4 }) === true);
  // Non-argon2id / malformed stored value forces a rehash on next login.
  check("needsRehash: non-argon2id variant → true",
        b.auth.password.needsRehash("$argon2i$v=19$m=1024,t=1,p=1$x$y") === true);
  check("needsRehash: non-string stored → true",
        b.auth.password.needsRehash(null) === true);
  // Unparseable argon2id body → vendor throws → forced rehash.
  check("needsRehash: unparseable argon2id PHC → true",
        b.auth.password.needsRehash("$argon2id$broken") === true);

  // The answer is three comparisons against the wanted cost, and a comparison
  // with a non-number is false, so a wanted cost that is not a number would
  // report every stored hash as current and stop the rehash-on-login upgrade.
  // Costs raised from an environment variable arrive as strings, so an operator
  // could believe a fleet had been re-hashed while every legacy hash stayed
  // weak. `_resolveParams` refuses the bad cost before the comparison and that
  // is what keeps it from happening; lib/argon2-builtin.js underneath reads
  // these with `opts.x || DEFAULT` and validates nothing, so this guarantee
  // rests entirely on this layer and nothing else asserted it.
  //
  // Either answer is safe: refusing, or reporting that a rehash is needed. What
  // must never happen is `false` for a hash that is below the target. The stored
  // hash here is weak ONLY on timeCost, at the default memory and parallelism,
  // so neither of the other two comparisons can answer for it.
  var weakOnPassesOnly = await b.auth.password.hash("pw", {
    memoryCost: b.constants.BYTES.kib(64), timeCost: 1, parallelism: 1,
  });
  function verdict(params) {
    try { return b.auth.password.needsRehash(weakOnPassesOnly, params); }
    catch (e) { return "refused:" + e.code; }
  }
  check("needsRehash: a t=1 hash is flagged against a numeric target of 3",
        verdict({ memoryCost: b.constants.BYTES.kib(64), timeCost: 3, parallelism: 1 }) === true);
  [["timeCost", { memoryCost: b.constants.BYTES.kib(64), timeCost: "abc", parallelism: 1 }],
   ["memoryCost", { memoryCost: "lots", timeCost: 3, parallelism: 1 }],
   ["parallelism", { memoryCost: b.constants.BYTES.kib(64), timeCost: 3, parallelism: "many" }],
  ].forEach(function (row) {
    var got = verdict(row[1]);
    check("needsRehash: a non-numeric " + row[0] + " never reports a below-target " +
          "hash as current",
          got !== false, String(got));
  });
  // A hash already at the target is still reported current, so the checks above
  // cannot be satisfied by answering true for everything.
  var atDefaults = await b.auth.password.hash("pw", {
    memoryCost: b.constants.BYTES.kib(64), timeCost: 3, parallelism: 4,
  });
  check("needsRehash: a hash at the target is still reported current",
        b.auth.password.needsRehash(atDefaults) === false);
}

async function testGate() {
  var threw;
  try { b.auth.password.gate(1.5); } catch (e) { threw = e; }
  check("gate: non-integer rejected with bad-gate",
        threw && threw.code === "auth-password/bad-gate");
  var threwNeg;
  try { b.auth.password.gate(0); } catch (e) { threwNeg = e; }
  check("gate: zero rejected with bad-gate",
        threwNeg && threwNeg.code === "auth-password/bad-gate");
}

async function testConcurrencySemaphoreQueue() {
  // gate(1) shrinks the semaphore to a single slot; two concurrent
  // hashes force the second to queue on _waiters, then be released when
  // the first finishes — exercising the queue push + release-to-waiter
  // path that a single-call test never reaches.
  b.auth.password.gate(1);
  try {
    var order = [];
    var p1 = b.auth.password.hash("first", FAST).then(function () { order.push("first"); });
    var p2 = b.auth.password.hash("second", FAST).then(function () { order.push("second"); });
    await Promise.all([p1, p2]);
    check("concurrency gate: both queued hashes complete", order.length === 2);
  } finally {
    // Restore a sane default so no later work runs single-slot.
    b.auth.password.gate(8);
  }
}

// ---- policy() config-time throws -----------------------------------

function _expectPolicyThrow(label, opts) {
  var threw;
  try { b.auth.password.policy(opts); } catch (e) { threw = e; }
  check(label, threw && threw.code === "auth-password/bad-policy");
}

function testPolicyConstructionRejects() {
  _expectPolicyThrow("policy: unknown profile rejected", { profile: "totally-made-up" });
  _expectPolicyThrow("policy: minLength below 1 rejected", { minLength: 0 });
  _expectPolicyThrow("policy: minLength above cap rejected", { minLength: b.constants.BYTES.kib(4) + 1 });
  _expectPolicyThrow("policy: maxLength below minLength rejected", { minLength: 10, maxLength: 5 });
  _expectPolicyThrow("policy: unsupported breachCheck rejected", { breachCheck: "some-other-service" });
  _expectPolicyThrow("policy: non-positive mustRotateAfterMs rejected", { mustRotateAfterMs: -1 });
  _expectPolicyThrow("policy: non-finite mustRotateAfterMs rejected", { mustRotateAfterMs: Infinity });
  _expectPolicyThrow("policy: fractional historyMinDistance rejected", { historyMinDistance: 2.5 });
  _expectPolicyThrow("policy: negative historyMinDistance rejected", { historyMinDistance: -1 });
  _expectPolicyThrow("policy: non-object complexity rejected", { complexity: "yes" });
  _expectPolicyThrow("policy: complexity.minCategories out of range rejected",
    { complexity: { minCategories: 9, categories: ["lower", "upper"] } });
  _expectPolicyThrow("policy: complexity.categories bad token rejected",
    { complexity: { minCategories: 1, categories: ["lower", "emoji"] } });
  // hibpEndpoint must be a valid https URL (safeUrl ALLOW_HTTP_TLS).
  var threwUrl;
  try { b.auth.password.policy({ hibpEndpoint: "ftp://evil.example/range" }); } catch (e) { threwUrl = e; }
  check("policy: non-https hibpEndpoint rejected", threwUrl !== undefined);
}

function testPolicyProfilesApply() {
  var nist = b.auth.password.policy({ profile: "nist-aal2" });
  var d1 = nist.describe();
  check("policy profile nist-aal2: 8-byte floor + breach check",
        d1.minLength === b.constants.BYTES.bytes(8) && d1.breachCheck === "haveibeenpwned");
  var pci = b.auth.password.policy({ profile: "pci-4.0" });
  var d2 = pci.describe();
  check("policy profile pci-4.0: 12 min, rotation + history",
        d2.minLength === 12 && d2.mustRotateAfterMs === b.constants.TIME.days(90) && d2.historyMinDistance === 4);
  var hipaa = b.auth.password.policy({ profile: "hipaa-aal2" });
  var d3 = hipaa.describe();
  check("policy profile hipaa-aal2: complexity enabled",
        d3.complexity && d3.complexity.minCategories === 3);
  // Operator field override wins over the named profile.
  var overridden = b.auth.password.policy({ profile: "pci-4.0", minLength: 20 });
  check("policy: operator opt overrides profile default",
        overridden.describe().minLength === 20);
  // POLICY_PROFILES constant surface (verbatim dotted form for the gate).
  check("b.auth.password.POLICY_PROFILES exposes the three profiles",
        b.auth.password.POLICY_PROFILES["nist-aal2"] &&
        b.auth.password.POLICY_PROFILES["pci-4.0"] &&
        b.auth.password.POLICY_PROFILES["hipaa-aal2"]);
  check("b.auth.password.DEFAULT_POLICY minLength is the NIST 8 floor",
        b.auth.password.DEFAULT_POLICY.minLength === 8);
  check("b.auth.password.DEFAULT_PARAMS memoryCost is 64 MiB in KiB",
        b.auth.password.DEFAULT_PARAMS.memoryCost === b.constants.BYTES.kib(64));
}

// ---- policy.check() gates (no breach check) ------------------------

async function testCheckLengthAndTypeGates() {
  var pol = b.auth.password.policy({ minLength: 8, maxLength: 20, useBundledCommon: false });
  var r1 = await pol.check(1234);
  check("check: non-string plaintext → bad-input", r1.ok === false && r1.code === "policy/bad-input");
  var r2 = await pol.check("short");
  check("check: below minLength → too-short", r2.ok === false && r2.code === "policy/too-short");
  var r3 = await pol.check("x".repeat(21));
  check("check: above maxLength → too-long", r3.ok === false && r3.code === "policy/too-long");
  var r4 = await pol.check("a-perfectly-fine-pw");
  check("check: in-range unique pw passes (no breach check) → ok", r4.ok === true);
}

async function testCheckCommonAndDictionary() {
  // Bundled top-10000 set is on by default — "password" is in it.
  var pol = b.auth.password.policy({ minLength: 4 });
  var r1 = await pol.check("password");
  check("check: bundled common password → forbidden-common",
        r1.ok === false && r1.code === "policy/forbidden-common");
  // Operator-supplied forbidCommon (bundled off to isolate the branch).
  var pol2 = b.auth.password.policy({ minLength: 4, useBundledCommon: false, forbidCommon: ["s3cr3t-corp-pw"] });
  var r2 = await pol2.check("s3cr3t-corp-pw");
  check("check: operator forbidCommon match → forbidden-common",
        r2.ok === false && r2.code === "policy/forbidden-common");
  // Dictionary substring (brand names) — case-insensitive substring.
  var pol3 = b.auth.password.policy({ minLength: 4, useBundledCommon: false, dictionary: ["acmecorp"] });
  var r3 = await pol3.check("myAcmeCorpLogin");
  check("check: dictionary substring → forbidden-dictionary",
        r3.ok === false && r3.code === "policy/forbidden-dictionary");
}

async function testCheckContextSubstrings() {
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false });
  var r1 = await pol.check("alice-and-friends", { email: "alice@example.com" });
  check("check: password containing email local-part → contains-context",
        r1.ok === false && r1.code === "policy/contains-context");
  var r2 = await pol.check("mybobbypassword", { username: "bob" });
  check("check: password containing username → contains-context",
        r2.ok === false && r2.code === "policy/contains-context");
  var r3 = await pol.check("secret-widgets-99", { deny: ["widgets"] });
  check("check: password containing operator deny string → contains-context",
        r3.ok === false && r3.code === "policy/contains-context");
}

async function testCheckComplexity() {
  var pol = b.auth.password.policy({
    minLength: 4, useBundledCommon: false,
    complexity: { minCategories: 3, minRunRepeat: 3, minSequenceLength: 3 },
  });
  var r1 = await pol.check("alllowercaseonly");
  check("check: too few character categories → complexity-categories",
        r1.ok === false && r1.code === "policy/complexity-categories");
  var r2 = await pol.check("Aaaa1!wxqz");
  check("check: N-identical-run → complexity-run",
        r2.ok === false && r2.code === "policy/complexity-run");
  var r3 = await pol.check("Xabcdef1!q");
  check("check: ascending sequence → complexity-sequence",
        r3.ok === false && r3.code === "policy/complexity-sequence");
  // A password that clears every complexity gate (4 categories, no
  // 3-run, no 3-char sequence) drives the run/sequence scanners through
  // their "not found" return arms and yields ok.
  var r4 = await pol.check("Xk9!mQ2w");
  check("check: complexity all-clear → ok", r4.ok === true);
}

function testParamsAudit() {
  var p = b.auth.password.params();
  check("params: algorithm is argon2id + meets OWASP floor",
        p.algorithm === "argon2id" && p.meetsFloor === true);
  check("params: active memoryCost matches the 64 MiB default (in KiB)",
        p.active.memoryCostKib === b.constants.BYTES.kib(64));
  check("b.auth.password.OWASP_FLOOR_2026 is the 19 MiB / t2 / p1 floor",
        b.auth.password.OWASP_FLOOR_2026.memoryCostKib === b.constants.BYTES.kib(19) &&
        b.auth.password.OWASP_FLOOR_2026.timeCost === 2 &&
        b.auth.password.OWASP_FLOOR_2026.parallelism === 1);
}

// ---- HIBP breach check via injected stub ---------------------------

// Build a k-anonymity response body: for the target plaintext, place
// its real SHA-1 suffix into the returned list with `count` sightings,
// plus a couple of decoy lines. This is exactly the shape HIBP returns.
function _hibpBodyFor(plaintext, count, extraLines) {
  var full = hibpSha1.sha1Hex(plaintext).toUpperCase();
  var suffix = full.slice(5);
  var lines = ["00000000000000000000000000000000000:3",
               suffix + ":" + count,
               "11111111111111111111111111111111111:9"];
  if (extraLines) lines = lines.concat(extraLines);
  return lines.join("\r\n");
}

// Run `fn` with httpClient.request replaced by `stub`; always restore.
async function _withStub(stub, fn) {
  var orig = httpClient.request;
  httpClient.request = stub;
  try { return await fn(); }
  finally { httpClient.request = orig; }
}

async function testBreachCheckMatch() {
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () {
    return { statusCode: 200, body: _hibpBodyFor("breached-pw-xyz", 42) };
  }, async function () {
    var r = await pol.check("breached-pw-xyz");
    check("check: plaintext found in HIBP → breached",
          r.ok === false && r.code === "policy/breached");
  });
}

async function testBreachCheckNoMatchAndThreshold() {
  // No matching suffix in the body → ok, breachCheckCount 0.
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () {
    return { statusCode: 200, body: "00000000000000000000000000000000000:3\r\n11111111111111111111111111111111111:9" };
  }, async function () {
    var r = await pol.check("unbreached-unique-pw");
    check("check: no HIBP match → ok with breachCheckCount 0",
          r.ok === true && r.breachCheckCount === 0);
  });
  // Suffix present but below breachThreshold → not flagged.
  var polHi = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", breachThreshold: 100 });
  await _withStub(async function () {
    return { statusCode: 200, body: _hibpBodyFor("rare-pw", 5) };
  }, async function () {
    var r = await polHi.check("rare-pw");
    check("check: HIBP count below threshold → ok (not breached)", r.ok === true);
  });
}

async function testBreachCheckNetworkError() {
  // Default (fail-open): a request throw → skip the check, allow.
  var polOpen = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () { throw new Error("ECONNREFUSED simulated"); }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: HIBP request error, fail-open → breachCheckSkipped",
          r.ok === true && r.breachCheckSkipped === true);
  });
  // fail-closed: a request throw → reject.
  var polClosed = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", failClosed: true });
  await _withStub(async function () { throw new Error("ECONNREFUSED simulated"); }, async function () {
    var r = await polClosed.check("some-pw");
    check("check: HIBP request error, fail-closed → breach-check-failed",
          r.ok === false && r.code === "policy/breach-check-failed");
  });
}

async function testBreachCheckBadStatus() {
  // Non-200 (rate limited): fail-open skips, fail-closed rejects.
  var polOpen = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () { return { statusCode: 429, body: "" }; }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: HIBP non-200, fail-open → breachCheckSkipped",
          r.ok === true && r.breachCheckSkipped === true);
  });
  var polClosed = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", failClosed: true });
  await _withStub(async function () { return { statusCode: 503, body: null }; }, async function () {
    var r = await polClosed.check("some-pw");
    check("check: HIBP non-200, fail-closed → breach-check-failed",
          r.ok === false && r.code === "policy/breach-check-failed");
  });
  // 200 with an empty body isolates the `!resp.body` arm (status is
  // fine but there's nothing to scan) — fail-open skips.
  await _withStub(async function () { return { statusCode: 200, body: null }; }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: HIBP 200 with empty body → breachCheckSkipped",
          r.ok === true && r.breachCheckSkipped === true);
  });
}

async function testBreachCheckPoisonedMirror() {
  // A body shaped like HIBP but mostly-unparseable (missing colons /
  // non-numeric counts) must not read as "looks fine". fail-open skips
  // with a reason; fail-closed rejects.
  var poisoned = ["no-colon-line-one", "another-bad-line", "third-bad-line",
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:notanumber",
                  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:7"].join("\r\n");
  var polOpen = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () { return { statusCode: 200, body: poisoned }; }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: poisoned HIBP mirror, fail-open → skipped w/ reason",
          r.ok === true && r.breachCheckSkipped === true &&
          r.breachCheckSkipReason === "hibp-response-mostly-unparseable");
  });
  var polClosed = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", failClosed: true });
  await _withStub(async function () { return { statusCode: 200, body: poisoned }; }, async function () {
    var r = await polClosed.check("some-pw");
    check("check: poisoned HIBP mirror, fail-closed → breach-check-failed",
          r.ok === false && r.code === "policy/breach-check-failed");
  });
}

async function testBreachCheckEndpointTrailingSlash() {
  // A custom endpoint with trailing slashes must be normalized (the
  // linear backward slash-strip) before "/range/<prefix>" is appended.
  var seenUrl = null;
  var pol = b.auth.password.policy({
    minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned",
    hibpEndpoint: "https://api.pwnedpasswords.com///",
  });
  await _withStub(async function (reqOpts) {
    seenUrl = reqOpts.url;
    return { statusCode: 200, body: "00000000000000000000000000000000000:3" };
  }, async function () {
    await pol.check("some-pw");
    check("check: trailing slashes stripped before /range/ appended",
          seenUrl === "https://api.pwnedpasswords.com/range/" + hibpSha1.sha1Hex("some-pw").toUpperCase().slice(0, 5));
  });
}

// ---- shouldRotate + reuseProhibited --------------------------------

function testShouldRotate() {
  var noRotate = b.auth.password.policy({ minLength: 4, useBundledCommon: false });
  check("shouldRotate: no rotation policy → false",
        noRotate.shouldRotate(Date.now()) === false);
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, mustRotateAfterMs: b.constants.TIME.days(90) });
  var longAgo = Date.now() - b.constants.TIME.days(200);
  check("shouldRotate: password older than window → true",
        pol.shouldRotate(longAgo) === true);
  check("shouldRotate: fresh password → false",
        pol.shouldRotate(Date.now()) === false);
  // Explicit `now` argument path.
  check("shouldRotate: explicit now arg respected",
        pol.shouldRotate(0, b.constants.TIME.days(91)) === true);
  var threw;
  try { pol.shouldRotate("not-a-timestamp"); } catch (e) { threw = e; }
  check("shouldRotate: non-numeric passwordSetAt throws bad-input",
        threw && threw.code === "auth-password/bad-input");
}

async function testReuseProhibited() {
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, historyMinDistance: 4 });
  var stored = await b.auth.password.hash("old-password-1", FAST);
  check("reuseProhibited: candidate matches a stored history hash → true",
        (await pol.reuseProhibited("old-password-1", [stored])) === true);
  check("reuseProhibited: candidate absent from history → false",
        (await pol.reuseProhibited("brand-new-pw", [stored])) === false);
  // Non-argon2id history entry is skipped safely (returns false there).
  check("reuseProhibited: non-argon2id history entry ignored → false",
        (await pol.reuseProhibited("whatever", ["$argon2i$garbage"])) === false);
  // Empty plaintext short-circuits false.
  check("reuseProhibited: empty candidate → false",
        (await pol.reuseProhibited("", [stored])) === false);
  // Empty / non-array history short-circuits false.
  check("reuseProhibited: empty history → false",
        (await pol.reuseProhibited("old-password-1", [])) === false);
  // history-distance disabled short-circuits false regardless of match.
  var polOff = b.auth.password.policy({ minLength: 4, useBundledCommon: false });
  check("reuseProhibited: history disabled → false",
        (await polOff.reuseProhibited("old-password-1", [stored])) === false);
}

// The gate is module state, so a worker_threads Worker loads its own copy and
// holds its own limit and counts: the card and `stats` called it process-wide
// while N workers granted N times the advertised concurrency. Both halves are
// driven here — that the default really is per-thread, which is what the
// wording now says, and that a shared handle does bound every thread.
async function testTheGateIsPerThreadAndShareable() {
  var nodeWorker = require("node:worker_threads");
  var nodeFs = require("node:fs");
  var nodeOs = require("node:os");
  var nodePath = require("node:path");

  // The module, not the package root: a Worker loading the whole framework
  // boots three times slower, and under SMOKE_PARALLEL=64 in a container that
  // was the difference between booting and timing out.
  var entry = nodePath.join(__dirname, "..", "..", "lib", "auth", "password.js");
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "argon-gate-"));
  var script = nodePath.join(dir, "gate-worker.js");
  // The worker samples the gate's own counts rather than bracketing the call:
  // a counter raised before `hash` resolves its permit would count waiters as
  // running, and the ceiling assertion would then be measuring the queue.
  nodeFs.writeFileSync(script, [
    "var wt = require(\"node:worker_threads\");",
    "var d = wt.workerData;",
    "var P = require(d.entry);",
    "if (d.gate) P.gate(null, { shared: d.gate });",
    "else P.gate(d.limit);",
    "var FASTW = { memoryCost: 1024, timeCost: 1, parallelism: 1 };",
    "var maxRunning = 0;",
    "var minAvailable = Infinity;",
    "var sampling = true;",
    "function sample() {",
    "  if (!sampling) return;",
    "  var s = P.stats();",
    "  if (s.running > maxRunning) maxRunning = s.running;",
    "  if (s.available !== undefined && s.available < minAvailable) minAvailable = s.available;",
    "  setTimeout(sample, 1);",
    "}",
    "(async function () {",
    "  sample();",
    "  var runs = [];",
    "  for (var i = 0; i < d.n; i += 1) {",
    "    runs.push(P.hash(\"pw-\" + i + \"-\" + d.tag, FASTW));",
    "  }",
    "  await Promise.all(runs);",
    "  sampling = false;",
    "  wt.parentPort.postMessage({ ok: true, maxRunning: maxRunning,",
    "    minAvailable: minAvailable === Infinity ? null : minAvailable });",
    "}()).catch(function (e) { sampling = false;",
    "  wt.parentPort.postMessage({ ok: false, err: String(e && e.message) }); });",
  ].join("\n"));

  function _spawn(workerData) {
    return new Promise(function (resolve, reject) {
      var w = new nodeWorker.Worker(script, { workerData: workerData });
      var done = null;
      w.on("message", function (m) { done = m; });
      w.on("error", reject);
      w.on("exit", function () { resolve(done || { ok: false, err: "no message" }); });
    });
  }

  try {
    // --- shared: one permit count across every thread ---------------------
    b.auth.password.gate(2, { shared: true });
    var handle = b.auth.password.gateHandle();
    check("a shared gate reports itself as shared",
      b.auth.password.stats().shared === true &&
      b.auth.password.stats().limit === 2 &&
      b.auth.password.stats().available === 2,
      JSON.stringify(b.auth.password.stats()));
    check("and the handle is a SharedArrayBuffer to hand to a Worker",
      handle instanceof SharedArrayBuffer);
    var adoptWithOtherLimit = null;
    try { b.auth.password.gate(5, { shared: handle }); }
    catch (e) { adoptWithOtherLimit = e; }
    check("adopting the handle with a different limit is refused",
      adoptWithOtherLimit !== null && adoptWithOtherLimit.code === "argon2/bad-gate",
      "code=" + (adoptWithOtherLimit && adoptWithOtherLimit.code));

    // The parent samples the shared count while the workers run, so the
    // ceiling is read from the pool every thread draws on.
    var worstInFlight = 0;
    var sawSaturation = false;
    var watching = true;
    (function watch() {
      if (!watching) return;
      var s = b.auth.password.stats();
      if (s.available !== undefined) {
        var inFlight = s.limit - s.available;
        if (inFlight > worstInFlight) worstInFlight = inFlight;
        if (s.available === 0) sawSaturation = true;
      }
      setTimeout(watch, 1);
    }());
    var sharedResults = await Promise.all([
      _spawn({ entry: entry, gate: handle, n: 10, tag: "a" }),
      _spawn({ entry: entry, gate: handle, n: 10, tag: "b" }),
      _spawn({ entry: entry, gate: handle, n: 10, tag: "c" }),
    ]);
    watching = false;
    check("every worker finished through the shared gate",
      sharedResults.every(function (r) { return r.ok === true; }),
      JSON.stringify(sharedResults));
    check("the shared permit count never went below zero on any thread",
      sharedResults.every(function (r) { return r.minAvailable === null || r.minAvailable >= 0; }),
      JSON.stringify(sharedResults.map(function (r) { return r.minAvailable; })));
    check("three threads never had more than the shared limit of 2 in flight",
      worstInFlight <= 2, "worst in flight=" + worstInFlight);
    // Without this the ceiling assertion could pass over a gate nothing
    // contended for, which is the shape of an assertion that cannot fail.
    check("and the gate was actually saturated, so the ceiling was exercised",
      sawSaturation || sharedResults.some(function (r) { return r.minAvailable === 0; }),
      "worst in flight=" + worstInFlight);
    check("the permit count returned to the limit once every thread finished",
      b.auth.password.stats().available === 2,
      JSON.stringify(b.auth.password.stats()));

    // --- the default: each thread holds its own limit ----------------------
    b.auth.password.gate(8, { shared: false, maxQueued: Infinity, waitTimeoutMs: 0 });
    check("a gate can be returned to this thread's own limit",
      b.auth.password.stats().shared === false &&
      b.auth.password.stats().available === undefined);

    var ownResults = await Promise.all([
      _spawn({ entry: entry, limit: 1, n: 6, tag: "x" }),
      _spawn({ entry: entry, limit: 1, n: 6, tag: "y" }),
    ]);
    check("every worker finished on its own gate",
      ownResults.every(function (r) { return r.ok === true; }),
      JSON.stringify(ownResults));
    check("each thread held its own limit of 1",
      ownResults.every(function (r) { return r.maxRunning <= 1; }),
      JSON.stringify(ownResults.map(function (r) { return r.maxRunning; })));
    check("so two threads under gate(1) ran two derivations between them, " +
          "which is why the limit is documented as per-thread",
      ownResults.reduce(function (a, r) { return a + r.maxRunning; }, 0) > 1,
      JSON.stringify(ownResults.map(function (r) { return r.maxRunning; })));
  } finally {
    b.auth.password.gate(8, { shared: false, maxQueued: Infinity, waitTimeoutMs: 0 });
    try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

// A thread waiting for a shared permit has nothing else pending, and
// Atomics.waitAsync does not hold the event loop open, so the worker exited
// successfully with the hash never run and no result posted. The test above
// cannot see this: its sampling timer keeps the worker alive, which is what
// made it worth a test of its own that does nothing but await the hash.
async function testAWorkerWaitingForASharedPermitDoesNotExitEarly() {
  var nodeWorker = require("node:worker_threads");
  var nodeFs = require("node:fs");
  var nodeOs = require("node:os");
  var nodePath = require("node:path");

  var entry = nodePath.join(__dirname, "..", "..", "lib", "auth", "password.js");
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "argon-wait-"));
  var script = nodePath.join(dir, "wait-worker.js");
  nodeFs.writeFileSync(script, [
    "var wt = require(\"node:worker_threads\");",
    "var d = wt.workerData;",
    "var P = require(d.entry);",
    "P.gate(null, { shared: d.gate });",
    "wt.parentPort.postMessage({ ready: true });",
    "P.hash(\"pw-waiter\", { memoryCost: 1024, timeCost: 1, parallelism: 1 })",
    "  .then(function (stored) { wt.parentPort.postMessage({ ok: true, len: stored.length }); },",
    "        function (e) { wt.parentPort.postMessage({ ok: false, err: String(e && e.code) }); });",
  ].join("\n"));

  try {
    // The permit is taken straight out of the handle rather than by running a
    // derivation, so the worker is certain to be waiting: a derivation on this
    // thread would finish long before a Worker has finished booting.
    b.auth.password.gate(1, { shared: true });
    var handle = b.auth.password.gateHandle();
    var permits = new Int32Array(handle);
    Atomics.sub(permits, 0, 1);
    check("the parent holds the only permit", Atomics.load(permits, 0) === 0);

    var ready = false;
    var finished = null;
    var exited = null;
    var w = new nodeWorker.Worker(script, {
      workerData: { entry: entry, gate: handle },
    });
    var failed = null;
    w.on("message", function (m) {
      if (m && m.ready) { ready = true; return; }
      finished = m;
    });
    w.on("error", function (e) { failed = e; });
    w.on("exit", function (code) { exited = code; });

    // A Worker boot is a precondition rather than an assertion, so the budget
    // is generous: under SMOKE_PARALLEL=64 in a container it took longer than
    // 20s, and a short budget there fails a healthy run.
    await helpers.waitUntil(function () { return ready || exited !== null || failed; }, {
      timeoutMs: 60000,
      label: "shared argon2 gate: worker booted and adopted the handle",
    });
    check("the worker adopted the handle", ready === true,
      "exited=" + exited + " err=" + (failed && failed.message));

    // The worker cannot proceed while the permit is held. If waiting does not
    // hold its event loop open, it exits during this window instead.
    // Long enough that an unpinned worker would have reached its wait and
    // exited inside the window, which is what makes this discriminating.
    await helpers.passiveObserve(1500,
      "shared argon2 gate: worker blocked on a held permit");
    check("the worker is still alive while the permit is held",
      exited === null, "exited with code " + exited);
    check("  and has not completed a derivation it holds no permit for",
      finished === null, JSON.stringify(finished));

    Atomics.add(permits, 0, 1);
    Atomics.notify(permits, 0);

    await helpers.waitUntil(function () { return finished !== null || exited !== null; }, {
      timeoutMs: 60000,
      label: "shared argon2 gate: worker finished once the permit freed",
    });
    check("releasing the permit wakes the worker",
      finished !== null && finished.ok === true && finished.len > 0,
      JSON.stringify(finished) + " exit=" + exited);
    await helpers.waitUntil(function () { return exited !== null; }, {
      timeoutMs: 30000,
      label: "shared argon2 gate: worker exited after finishing",
    });
    check("  and the worker then exits rather than being held open",
      exited === 0, "exit code " + exited);
    check("  leaving the permit count whole",
      Atomics.load(permits, 0) === 1, "available=" + Atomics.load(permits, 0));
  } finally {
    b.auth.password.gate(8, { shared: false, maxQueued: Infinity, waitTimeoutMs: 0 });
    try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

// Three accounting seams that a shared gate adds, each of which silently
// inflates or strands the permit count rather than failing visibly.
async function testTheSharedGateAccountsPermitsToTheGateThatGrantedThem() {
  var FASTG = { memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 1 };
  try {
    // A refused option leaves the gate it was called on in place: the shared
    // attachment must not land when a later option in the same call is bad.
    b.auth.password.gate(4, { shared: false, maxQueued: Infinity, waitTimeoutMs: 0 });
    var before = b.auth.password.stats();
    var refused = null;
    try { b.auth.password.gate(1, { shared: true, maxQueued: -1 }); }
    catch (e) { refused = e; }
    check("a gate call with a bad maxQueued is refused",
      refused !== null && /bad-gate/.test(refused.code || ""),
      "code=" + (refused && refused.code));
    check("  and leaves the thread on the gate it was already using",
      b.auth.password.stats().shared === before.shared &&
      b.auth.password.stats().limit === before.limit,
      JSON.stringify(b.auth.password.stats()));

    // The shared permit count is a 32-bit signed integer, so a limit above
    // that range stores truncated: the count goes negative, every hash is
    // refused as busy with nothing running, and a zero-timeout wait returns
    // synchronously so the retry recurses. A limit the counter cannot hold is
    // a configuration error, not a gate.
    // The public layer already refuses an `n` outside the integer range, so
    // the bound is asserted on the module that owns the counter: a limit it
    // cannot store is a configuration error there too, whoever calls it.
    var argon2 = require("../../lib/argon2-builtin");
    var TOO_BIG = 2147483648;
    var publicRefused = null;
    try { b.auth.password.gate(TOO_BIG, { shared: true }); }
    catch (e) { publicRefused = e; }
    check("the public gate refuses a limit outside the integer range",
      publicRefused !== null && /bad-gate/.test(publicRefused.code || ""),
      "code=" + (publicRefused && publicRefused.code));

    var tooBig = null;
    try { argon2.gate(TOO_BIG, { shared: true }); } catch (e) { tooBig = e; }
    check("and the shared counter refuses a limit it cannot hold",
      tooBig !== null && tooBig.code === "argon2/bad-gate",
      "code=" + (tooBig && tooBig.code) + " stats=" + JSON.stringify(argon2.stats()));

    // The same limit inherited from this thread's own gate rather than passed.
    argon2.gate(TOO_BIG, { shared: false });
    var inherited = null;
    try { argon2.gate(null, { shared: true }); } catch (e) { inherited = e; }
    check("  including one inherited from the thread's own limit",
      inherited !== null && inherited.code === "argon2/bad-gate",
      "code=" + (inherited && inherited.code) + " stats=" + JSON.stringify(argon2.stats()));

    // The control: the largest limit the counter does hold is accepted, so the
    // refusal reads the range rather than refusing anything large.
    argon2.gate(8, { shared: false });
    var atMax = argon2.gate(2147483647, { shared: true });
    check("  while the largest representable limit is accepted",
      atMax.shared === true && atMax.available === 2147483647,
      JSON.stringify(atMax));

    // A derivation releases to the pool that granted it, so switching pools
    // underneath a running derivation cannot strand a permit in the old one.
    b.auth.password.gate(1, { shared: true });
    var strandedHandle = b.auth.password.gateHandle();
    var inFlight = b.auth.password.hash("pw-switch", {
      memoryCost: b.constants.BYTES.kib(16), timeCost: 3, parallelism: 1,
    });
    b.auth.password.gate(1, { shared: false });
    await inFlight;
    b.auth.password.gate(null, { shared: strandedHandle });
    check("a derivation that outlived the switch released to its own gate",
      b.auth.password.stats().available === 1,
      JSON.stringify(b.auth.password.stats()));

    // A no-argument gate() call must not start a shared waiter: it reads the
    // thread-local count, which says nothing about the shared permits.
    b.auth.password.gate(1, { shared: true, maxQueued: Infinity, waitTimeoutMs: 0 });
    var occupant = b.auth.password.hash("pw-occupant", {
      memoryCost: b.constants.BYTES.kib(16), timeCost: 3, parallelism: 1,
    });
    var queued = b.auth.password.hash("pw-queued", FASTG);
    b.auth.password.gate();
    b.auth.password.gate();
    check("a shared waiter is not admitted by a bare gate() call",
      b.auth.password.stats().available >= 0,
      JSON.stringify(b.auth.password.stats()));
    await Promise.all([occupant, queued]);
    check("  and the permit count is whole once both finish, not inflated",
      b.auth.password.stats().available === 1,
      JSON.stringify(b.auth.password.stats()));

    // A shared derivation held a slot in the local count too, so a hash queued
    // after the thread returned to its own gate waited on a count that the
    // shared release never decremented, and with the default unbounded wait it
    // waited forever.
    b.auth.password.gate(1, { shared: true, maxQueued: Infinity, waitTimeoutMs: 0 });
    var acrossSwitch = b.auth.password.hash("pw-across", {
      memoryCost: b.constants.BYTES.kib(16), timeCost: 3, parallelism: 1,
    });
    b.auth.password.gate(1, { shared: false });
    var afterSwitch = b.auth.password.hash("pw-after", FASTG);
    var stranded = false;
    await Promise.race([
      Promise.all([acrossSwitch, afterSwitch]),
      helpers.passiveObserve(4000, "argon2 gate: a hash queued across a pool switch")
        .then(function () { stranded = true; }),
    ]);
    check("a hash queued after a pool switch is not stranded behind the old one",
      stranded === false, "still waiting after 4s");
    await Promise.all([acrossSwitch, afterSwitch]);

    // Reporting a lower limit while the handle still carries the old permit
    // count is a bound nothing enforces, so the change is refused.
    b.auth.password.gate(4, { shared: true });
    var lowered = null;
    try { b.auth.password.gate(1); } catch (e) { lowered = e; }
    check("lowering the limit of an attached shared gate is refused",
      lowered !== null && lowered.code === "argon2/bad-gate",
      "code=" + (lowered && lowered.code));
    check("  and the gate keeps the limit its permits actually enforce",
      b.auth.password.stats().limit === 4 &&
      b.auth.password.stats().available === 4,
      JSON.stringify(b.auth.password.stats()));
    check("  while restating the same limit is accepted",
      b.auth.password.gate(4).limit === 4);
  } finally {
    b.auth.password.gate(8, { shared: false, maxQueued: Infinity, waitTimeoutMs: 0 });
  }
}

// The held copy exists for the retry a transient refusal invites, and for
// nothing else: every consumer zeroes the buffer it was handed when it is done,
// and a copy that outlives that defeats the erasure.
async function testAHeldPassphraseIsReleasedWhenTheOperationEnds() {
  var source = require("../../lib/vault/passphrase-source");
  var nodeFs = require("node:fs");
  var nodeOs = require("node:os");
  var nodePath = require("node:path");

  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "held-pass-"));
  var priorPass = process.env.BLAMEJS_VAULT_PASSPHRASE;
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    process.env.BLAMEJS_VAULT_PASSPHRASE = "a-long-enough-test-passphrase";
    b.vault._resetForTest();
    source._clearHeldEnvPassphrase(source.ENV_PASSPHRASE);

    await b.vault.init({ dataDir: dir, mode: "wrapped" });
    check("the init consumed the variable",
      process.env.BLAMEJS_VAULT_PASSPHRASE === undefined,
      "env=" + String(process.env.BLAMEJS_VAULT_PASSPHRASE));
    // `sourceKind` answers "env" while a copy is held and stops once it is
    // released, so it reads the retention itself rather than a flag about it.
    // Asked the way the vault reads it, with the retry window on: a reader
    // that has not asked for that window never sees the copy at all.
    var RETRY = { _holdForRetry: true };
    check("a completed vault init releases the held copy",
      source.sourceKind(RETRY) !== "env", "kind=" + source.sourceKind(RETRY));

    // And a transient refusal keeps it, which is the one case it exists for.
    process.env.BLAMEJS_VAULT_PASSPHRASE = "a-long-enough-test-passphrase";
    b.vault._resetForTest();
    var P = b.auth.password;
    var hold = null;
    try {
      P.gate(1, { maxQueued: 0 });
      hold = P.hash("occupant", {
        memoryCost: b.constants.BYTES.kib(16), timeCost: 2, parallelism: 1,
      });
      var refused = null;
      try { await b.vault.init({ dataDir: dir, mode: "wrapped" }); }
      catch (e) { refused = e; }
      check("a gate-refused init is the transient case",
        refused !== null && refused.code === "argon2/busy",
        "code=" + (refused && refused.code));
      check("  and it keeps the copy the retry needs",
        source.sourceKind(RETRY) === "env", "kind=" + source.sourceKind(RETRY));
    } finally {
      if (hold !== null) { try { await hold; } catch (_e) { /* released */ } }
      P.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });
    }
  } finally {
    b.vault._resetForTest();
    source._clearHeldEnvPassphrase(source.ENV_PASSPHRASE);
    if (priorPass === undefined) delete process.env.BLAMEJS_VAULT_PASSPHRASE;
    else process.env.BLAMEJS_VAULT_PASSPHRASE = priorPass;
    try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

async function run() {
  await testTheGateIsPerThreadAndShareable();
  await testAWorkerWaitingForASharedPermitDoesNotExitEarly();
  await testTheSharedGateAccountsPermitsToTheGateThatGrantedThem();
  await testAHeldPassphraseIsReleasedWhenTheOperationEnds();
  await testHashVerifyRoundtrip();
  await testHashRejectsBadPlain();
  await testHashRejectsBadParams();
  await testVerifyDefensiveReturnsFalse();
  await testVerifyBoundsTheStoredCost();
  await testGateBoundsEveryArgon2Run();
  await testNeedsRehash();
  await testGate();
  await testConcurrencySemaphoreQueue();
  testPolicyConstructionRejects();
  testPolicyProfilesApply();
  await testCheckLengthAndTypeGates();
  await testCheckCommonAndDictionary();
  await testCheckContextSubstrings();
  await testCheckComplexity();
  testParamsAudit();
  await testBreachCheckMatch();
  await testBreachCheckNoMatchAndThreshold();
  await testBreachCheckNetworkError();
  await testBreachCheckBadStatus();
  await testBreachCheckPoisonedMirror();
  await testBreachCheckEndpointTrailingSlash();
  testShouldRotate();
  await testReuseProhibited();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
