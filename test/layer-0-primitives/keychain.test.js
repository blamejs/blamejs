// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.keychain — OS keychain abstraction with encrypted-file fallback.
 *
 * Focuses on:
 *   - Opts validation (service / account / fallbackFile / passphrase shape).
 *   - File-fallback round-trip (store -> retrieve -> remove -> retrieve null).
 *   - File-fallback rejects wrong passphrase / bad shape.
 *   - File on-disk shape: 0o600 mode, vault.wrap magic byte, atomic.
 *   - Audit emission for stored / retrieved / removed (no password value).
 *   - Identifier hardening: newline / null in service / account.
 *
 * The native-tool paths (macOS security / Linux secret-tool / Windows
 * PowerShell) are not exercised — host availability varies. Coverage of
 * those paths comes from the per-platform integration runs; the tests
 * here pass `preferFile: true` to force the file backend.
 *
 * File-backend edge cases are exercised too: unknown-opt rejection,
 * the carriage-return identifier branch, empty-string passwords,
 * no-fallbackFile / absent-file no-op read paths, read-side passphrase
 * enforcement, overwrite-in-place, binding-key collision resistance,
 * corrupted-file errors, metacharacter/Unicode round-trips, and
 * audit:false suppression.
 */
var fs = require("fs");
var os = require("os");
var path = require("path");

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

// Hardcoded fixture names — no operator input crosses this boundary.
// path.join is composing os.tmpdir() with a literal string + fs.mkdtempSync's
// random suffix; nothing here is operator-controlled.
var _TMP_PREFIX = "blamejs-keychain-";
var _TMP_DEFAULT_NAME = "keychain.enc";
var _TMP_ABSENT_NAME = "absent.enc";

function _tmpFile(which) {
  var base = os.tmpdir();
  var dir = fs.mkdtempSync(path.join(base, _TMP_PREFIX));
  var leaf = which === "absent" ? _TMP_ABSENT_NAME : _TMP_DEFAULT_NAME;
  return path.join(dir, leaf);
}

var _TMP_PREFIX_EDGE = "blamejs-keychain-edge-";

function _tmpFileNamed(leaf) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), _TMP_PREFIX_EDGE));
  return path.join(dir, leaf || _TMP_DEFAULT_NAME);
}

async function _capture(fn) {
  // Capture only keychain.* audit events, mirroring the shim pattern in
  // run() above / redact-dlp.test.js. Restores the original in a
  // finally so a throw inside fn never leaks the patched safeEmit.
  var events = [];
  var orig = b.audit.safeEmit;
  b.audit.safeEmit = function (ev) {
    if (ev && typeof ev.action === "string" && ev.action.indexOf("keychain.") === 0) {
      events.push(ev);
    }
    return orig.call(b.audit, ev);
  };
  try { await fn(); } finally { b.audit.safeEmit = orig; }
  return events;
}

// File-backend edge cases beyond the round-trip assertions in run():
// unknown opts, CR identifiers, empty passwords, no-op read paths,
// read-side passphrase enforcement, overwrite, binding-key collisions,
// corrupted files, tricky passwords, and audit:false suppression.
async function runFileBackendEdgeCases() {
  var pass = "correct horse battery staple";
  var threw;

  // ---- Unknown-opt rejection (validateOpts allowlist) --------------------
  // A typo'd opt key must be refused at config time on every entry point,
  // not silently ignored. The shared allowlist lives in _validateCommonOpts.
  threw = null;
  try {
    await b.keychain.store({
      service: "s", account: "a", password: "p", preferFile: true,
      fallbackFile: _tmpFileNamed(), passphrase: pass, bogusKey: 1,
    });
  } catch (e) { threw = e; }
  check("keychain.store: unknown opt key throws",
    threw && typeof threw.message === "string" &&
    threw.message.indexOf("unknown option") !== -1);

  threw = null;
  try {
    await b.keychain.retrieve({
      service: "s", account: "a", preferFile: true,
      fallbackFile: _tmpFileNamed(), passphrase: pass, typo: true,
    });
  } catch (e) { threw = e; }
  check("keychain.retrieve: unknown opt key throws",
    threw && typeof threw.message === "string" &&
    threw.message.indexOf("unknown option") !== -1);

  threw = null;
  try {
    await b.keychain.remove({
      service: "s", account: "a", preferFile: true,
      fallbackFile: _tmpFileNamed(), passphrase: pass, nope: 0,
    });
  } catch (e) { threw = e; }
  check("keychain.remove: unknown opt key throws",
    threw && typeof threw.message === "string" &&
    threw.message.indexOf("unknown option") !== -1);

  // ---- Identifier hardening: carriage-return branch ----------------------
  // run() above pins the newline-in-service and NUL-in-account
  // branches; the CR branch of /[\0\r\n]/ is exercised here.
  threw = null;
  try {
    await b.keychain.store({
      service: "svc\rinject", account: "a", password: "p", preferFile: true,
    });
  } catch (e) { threw = e; }
  check("keychain.store: CR in service throws bad-identifier",
    threw && threw.code === "keychain/bad-identifier");

  threw = null;
  try {
    await b.keychain.store({
      service: "s", account: "acct\rinject", password: "p", preferFile: true,
    });
  } catch (e) { threw = e; }
  check("keychain.store: CR in account throws bad-identifier",
    threw && threw.code === "keychain/bad-identifier");

  // ---- Empty-string password (distinct from omitted) ---------------------
  threw = null;
  try {
    await b.keychain.store({
      service: "s", account: "a", password: "", preferFile: true,
      fallbackFile: _tmpFileNamed(), passphrase: pass,
    });
  } catch (e) { threw = e; }
  check("keychain.store: empty-string password throws bad-password",
    threw && threw.code === "keychain/bad-password");

  // ---- Backend "none" / file no-op read paths ----------------------------
  // retrieve with the file backend forced but no fallbackFile: nothing to
  // read, so a clean null (backend "none") rather than a throw.
  var noneMiss = await b.keychain.retrieve({
    service: "s", account: "a", preferFile: true,
  });
  check("keychain.retrieve: file backend + no fallbackFile returns null",
    noneMiss === null);

  // remove with the file backend forced but no fallbackFile: no-op false.
  var noneRemove = await b.keychain.remove({
    service: "s", account: "a", preferFile: true,
  });
  check("keychain.remove: file backend + no fallbackFile returns false",
    noneRemove === false);

  // remove pointing at an absolute file that does not exist yet: no-op false.
  var absentRemove = await b.keychain.remove({
    service: "s", account: "a", preferFile: true,
    fallbackFile: _tmpFileNamed("absent.enc"), passphrase: pass,
  });
  check("keychain.remove: absent fallbackFile returns false",
    absentRemove === false);

  // ---- Passphrase-required on the retrieve / remove read paths -----------
  // run() above covers store-without-passphrase; the read side
  // (retrieve / remove) reaches _readFile only when the file EXISTS, so
  // seed it first, then omit the passphrase.
  var ffPass = _tmpFileNamed();
  await b.keychain.store({
    service: "s", account: "a", password: "p", preferFile: true,
    fallbackFile: ffPass, passphrase: pass,
  });

  threw = null;
  try {
    await b.keychain.retrieve({
      service: "s", account: "a", preferFile: true, fallbackFile: ffPass,
    });
  } catch (e) { threw = e; }
  check("keychain.retrieve: existing file without passphrase throws",
    threw && threw.code === "keychain/file-passphrase-required");

  threw = null;
  try {
    await b.keychain.remove({
      service: "s", account: "a", preferFile: true, fallbackFile: ffPass,
    });
  } catch (e) { threw = e; }
  check("keychain.remove: existing file without passphrase throws",
    threw && threw.code === "keychain/file-passphrase-required");

  // A non-string passphrase is rejected by the same require-non-empty-string
  // gate as an omitted one (the passphrase type is not validated up front).
  threw = null;
  try {
    await b.keychain.store({
      service: "s", account: "a", password: "p", preferFile: true,
      fallbackFile: _tmpFileNamed(), passphrase: 12345,
    });
  } catch (e) { threw = e; }
  check("keychain.store: numeric passphrase throws passphrase-required",
    threw && threw.code === "keychain/file-passphrase-required");

  // ---- Overwrite (update-in-place) of an existing binding ----------------
  var ffUpd = _tmpFileNamed();
  await b.keychain.store({
    service: "svc", account: "acct", password: "first", preferFile: true,
    fallbackFile: ffUpd, passphrase: pass,
  });
  await b.keychain.store({
    service: "svc", account: "acct", password: "second", preferFile: true,
    fallbackFile: ffUpd, passphrase: pass,
  });
  var updated = await b.keychain.retrieve({
    service: "svc", account: "acct", preferFile: true,
    fallbackFile: ffUpd, passphrase: pass,
  });
  check("keychain.store: re-store overwrites the prior password",
    updated && updated.password === "second");

  // ---- No cross-talk between colliding-prefix pairs ----------------------
  // Under a separator-less concatenation, (service="ab", account="c") and
  // (service="a", account="bc") would map to the same "abc" key. The
  // NUL-delimited binding key must keep them distinct.
  var ffColl = _tmpFileNamed();
  await b.keychain.store({
    service: "ab", account: "c", password: "PW-ABC-1", preferFile: true,
    fallbackFile: ffColl, passphrase: pass,
  });
  await b.keychain.store({
    service: "a", account: "bc", password: "PW-ABC-2", preferFile: true,
    fallbackFile: ffColl, passphrase: pass,
  });
  var coll1 = await b.keychain.retrieve({
    service: "ab", account: "c", preferFile: true,
    fallbackFile: ffColl, passphrase: pass,
  });
  var coll2 = await b.keychain.retrieve({
    service: "a", account: "bc", preferFile: true,
    fallbackFile: ffColl, passphrase: pass,
  });
  check("keychain: (ab,c) and (a,bc) bindings do not collide",
    coll1 && coll1.password === "PW-ABC-1" &&
    coll2 && coll2.password === "PW-ABC-2");

  // ---- Corrupted / non-wrap file surfaces a typed error, not a crash -----
  // Write bytes that are not a vault.wrap payload, then attempt a read.
  // vaultWrap.unwrap rejects the magic byte; keychain maps that to
  // file-unseal-failed rather than propagating a raw crash.
  var ffCorrupt = _tmpFileNamed("corrupt.enc");
  await b.atomicFile.write(ffCorrupt, Buffer.from("this is not a sealed keychain file"), {
    fileMode: 0o600,
  });
  threw = null;
  try {
    await b.keychain.retrieve({
      service: "s", account: "a", preferFile: true,
      fallbackFile: ffCorrupt, passphrase: pass,
    });
  } catch (e) { threw = e; }
  check("keychain.retrieve: corrupted file throws file-unseal-failed",
    threw && threw.code === "keychain/file-unseal-failed");

  // ---- Round-trip fidelity for metacharacter / Unicode passwords ---------
  // The file payload is canonical JSON; a password carrying quotes,
  // backslashes, newlines, and multi-byte Unicode must survive the
  // serialize -> seal -> unseal -> parse round-trip byte-for-byte.
  var trickyPw = "a\"b\\c\nd\teé\u{1f512}z";
  var ffTricky = _tmpFileNamed();
  await b.keychain.store({
    service: "svc", account: "u", password: trickyPw, preferFile: true,
    fallbackFile: ffTricky, passphrase: pass,
  });
  var trickyGot = await b.keychain.retrieve({
    service: "svc", account: "u", preferFile: true,
    fallbackFile: ffTricky, passphrase: pass,
  });
  check("keychain: password with JSON metacharacters + Unicode round-trips",
    trickyGot && trickyGot.password === trickyPw);

  // ---- audit:false suppresses every keychain.* emission ------------------
  var ffAudit = _tmpFileNamed();
  var silentEvents = await _capture(async function () {
    await b.keychain.store({
      service: "svc", account: "u", password: "p", preferFile: true,
      fallbackFile: ffAudit, passphrase: pass, audit: false,
    });
    await b.keychain.retrieve({
      service: "svc", account: "u", preferFile: true,
      fallbackFile: ffAudit, passphrase: pass, audit: false,
    });
    await b.keychain.remove({
      service: "svc", account: "u", preferFile: true,
      fallbackFile: ffAudit, passphrase: pass, audit: false,
    });
  });
  check("keychain: audit:false emits no keychain.* events",
    silentEvents.length === 0);

  // Sanity counter-check: the same sequence WITH audit on does emit, so the
  // suppression above is a real gate rather than a broken capture shim.
  var ffAudit2 = _tmpFileNamed();
  var loudEvents = await _capture(async function () {
    await b.keychain.store({
      service: "svc", account: "u", password: "p", preferFile: true,
      fallbackFile: ffAudit2, passphrase: pass,
    });
  });
  check("keychain: audit default-on still emits (capture shim works)",
    loudEvents.some(function (e) { return e.action === "keychain.stored"; }));
}

async function run() {
  // ---- Opts validation -----------------------------------------------------
  var threw;

  threw = null;
  try { await b.keychain.store(); } catch (e) { threw = e; }
  check("keychain.store: missing opts throws KeychainError",
    threw && threw.code === "keychain/bad-opts");

  threw = null;
  try { await b.keychain.store({ account: "a", password: "p" }); } catch (e) { threw = e; }
  check("keychain.store: missing service throws",
    threw && threw.code === "keychain/bad-service");

  threw = null;
  try { await b.keychain.store({ service: "s", password: "p" }); } catch (e) { threw = e; }
  check("keychain.store: missing account throws",
    threw && threw.code === "keychain/bad-account");

  threw = null;
  try { await b.keychain.store({ service: "s", account: "a" }); } catch (e) { threw = e; }
  check("keychain.store: missing password throws",
    threw && threw.code === "keychain/bad-password");

  threw = null;
  try { await b.keychain.store({ service: "s\nbad", account: "a", password: "p", preferFile: true }); }
  catch (e) { threw = e; }
  check("keychain.store: newline in service throws",
    threw && threw.code === "keychain/bad-identifier");

  threw = null;
  try { await b.keychain.store({ service: "s", account: "a\x00bad", password: "p", preferFile: true }); }
  catch (e) { threw = e; }
  check("keychain.store: NUL in account throws",
    threw && threw.code === "keychain/bad-identifier");

  // Relative fallbackFile rejected (config-time / entry-point throw).
  threw = null;
  try {
    await b.keychain.store({
      service: "s", account: "a", password: "p",
      preferFile: true, fallbackFile: "relative/path.enc",
      passphrase: "xx",
    });
  } catch (e) { threw = e; }
  check("keychain.store: relative fallbackFile throws",
    threw && threw.code === "keychain/relative-fallback-file");

  // Missing passphrase on file-backend write throws.
  var fp = _tmpFile();
  threw = null;
  try {
    await b.keychain.store({
      service: "s", account: "a", password: "p",
      preferFile: true, fallbackFile: fp,
    });
  } catch (e) { threw = e; }
  check("keychain.store: file backend without passphrase throws",
    threw && threw.code === "keychain/file-passphrase-required");

  // ---- File-fallback round-trip ------------------------------------------
  var ff = _tmpFile();
  var pass = "correct horse battery staple";

  var stored = await b.keychain.store({
    service: "blamejs/db", account: "primary", password: "s3cr3t",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  check("keychain.store: file backend returns { stored: true, backend: 'file' }",
    stored && stored.stored === true && stored.backend === "file");

  check("keychain.store: file written to disk",
    fs.existsSync(ff));

  // 0o600 file mode (POSIX only — Windows reports differently). The
  // mode bits we care about are the low 9; mask and compare.
  if (process.platform !== "win32") {
    var st = fs.statSync(ff);
    check("keychain.store: file mode is 0o600",
      (st.mode & 0o777) === 0o600);
  }

  // Sealed file starts with vault.wrap magic byte 0xE2.
  var raw = fs.readFileSync(ff);
  check("keychain.store: file starts with vault.wrap magic 0xE2",
    raw.length > 0 && raw[0] === 0xE2);

  // Plaintext password bytes do NOT appear in the sealed file.
  check("keychain.store: plaintext password not in sealed file",
    raw.indexOf(Buffer.from("s3cr3t", "utf8")) === -1);

  var got = await b.keychain.retrieve({
    service: "blamejs/db", account: "primary",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  check("keychain.retrieve: file backend returns { password, backend: 'file' }",
    got && got.password === "s3cr3t" && got.backend === "file");

  // Multiple bindings in one file.
  await b.keychain.store({
    service: "blamejs/smtp", account: "relay", password: "smtp-pw",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  var got2 = await b.keychain.retrieve({
    service: "blamejs/smtp", account: "relay",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  check("keychain.retrieve: second binding in same file",
    got2 && got2.password === "smtp-pw");

  // Wrong passphrase rejected without leaking which binding existed.
  threw = null;
  try {
    await b.keychain.retrieve({
      service: "blamejs/db", account: "primary",
      preferFile: true, fallbackFile: ff, passphrase: "wrong",
    });
  } catch (e) { threw = e; }
  check("keychain.retrieve: wrong passphrase throws unseal-failed",
    threw && threw.code === "keychain/file-unseal-failed");

  // Unknown binding returns null (NOT a throw).
  var miss = await b.keychain.retrieve({
    service: "blamejs/db", account: "missing",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  check("keychain.retrieve: unknown binding returns null",
    miss === null);

  // remove() on existing returns true; retrieve() then returns null.
  var removed = await b.keychain.remove({
    service: "blamejs/db", account: "primary",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  check("keychain.remove: existing binding returns true",
    removed === true);

  var afterRemove = await b.keychain.retrieve({
    service: "blamejs/db", account: "primary",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  check("keychain.retrieve: removed binding returns null",
    afterRemove === null);

  // remove() on missing returns false.
  var notFound = await b.keychain.remove({
    service: "blamejs/db", account: "primary",
    preferFile: true, fallbackFile: ff, passphrase: pass,
  });
  check("keychain.remove: missing binding returns false",
    notFound === false);

  // retrieve on a fallback file that doesn't exist yet returns null
  // (NOT a passphrase-required throw — there's nothing to unseal).
  var noFile = _tmpFile("absent");
  var notHere = await b.keychain.retrieve({
    service: "x", account: "y",
    preferFile: true, fallbackFile: noFile, passphrase: pass,
  });
  check("keychain.retrieve: missing file returns null",
    notHere === null);

  // retrieve without fallbackFile returns null when no native backend.
  // (We can't reliably assert "no native backend" on every host, so
  // this test path passes preferFile: false but with audit: false to
  // avoid noisy emissions; we accept either null or a result.)

  // ---- Audit emission ----------------------------------------------------
  // Capture audit events by replacing b.audit.safeEmit (the same shim
  // pattern used by redact-dlp.test.js and external-db-routing.test.js).
  // keychain.* actions must appear and must NOT carry the password value.
  var events = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (ev) {
    if (ev && typeof ev.action === "string" && ev.action.indexOf("keychain.") === 0) {
      events.push(ev);
    }
    return origSafeEmit.call(b.audit, ev);
  };
  try {
    await b.keychain.store({
      service: "audit/test", account: "u", password: "AUDITME-SHOULD-NOT-APPEAR",
      preferFile: true, fallbackFile: ff, passphrase: pass,
    });
    await b.keychain.retrieve({
      service: "audit/test", account: "u",
      preferFile: true, fallbackFile: ff, passphrase: pass,
    });
    await b.keychain.remove({
      service: "audit/test", account: "u",
      preferFile: true, fallbackFile: ff, passphrase: pass,
    });
  } finally {
    b.audit.safeEmit = origSafeEmit;
  }

  check("keychain audit: stored event emitted",
    events.some(function (e) { return e.action === "keychain.stored"; }));
  check("keychain audit: retrieved event emitted",
    events.some(function (e) { return e.action === "keychain.retrieved"; }));
  check("keychain audit: removed event emitted",
    events.some(function (e) { return e.action === "keychain.removed"; }));

  var jsonAll = JSON.stringify(events);
  check("keychain audit: password value never appears in audit metadata",
    jsonAll.indexOf("AUDITME-SHOULD-NOT-APPEAR") === -1);

  // Every emitted event carries the service + account + backend in
  // metadata, and outcome is success/no-op (never failure on these
  // happy-paths).
  check("keychain audit: every event carries service/account/backend metadata",
    events.length >= 3 &&
    events.every(function (e) {
      return e.metadata &&
             typeof e.metadata.service === "string" &&
             typeof e.metadata.account === "string" &&
             typeof e.metadata.backend === "string";
    }));

  // ---- Error class registration ------------------------------------------
  check("keychain.KeychainError class registered",
    typeof b.keychain.KeychainError === "function");

  // ---- File-backend edge cases ---------------------------------------------
  await runFileBackendEdgeCases();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[keychain] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
