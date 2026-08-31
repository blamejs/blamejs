// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * BLAMEJS_NTS_REQUIRE — the boot refuses when no authenticated (RFC 8915)
 * time reading was obtained.
 *
 * Driven through b.db.init rather than through the internal boot-check helper,
 * because the refusal only matters if it reaches an operator starting the
 * framework. Both directions are asserted: the knob set refuses, and the same
 * unreachable configuration WITHOUT the knob boots. Without that control the
 * test would pass on any init that happened to fail for another reason.
 *
 * A source-grep for the error code stood in for this, which proves only that
 * the string is present.
 *
 * The other half of the contract — that an authenticated reading is ACCEPTED —
 * needs a reachable NTS-KE server and is not asserted here. What guards it is
 * `bootCheck` carrying `authenticated` through on every branch, pinned in
 * test/layer-0-primitives/ntp-check.test.js. Dropping that field left this file
 * green while the mode refused every boot, so the two tests are not
 * substitutes for one another.
 *
 * Run standalone: `node test/layer-0-primitives/db-nts-required-boot.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;

// Loopback with nothing listening: the NTS-KE connect is refused immediately
// and the plain SNTP fallback times out on the short budget. No packet leaves
// the host and no test depends on a reachable time server.
var UNREACHABLE_NTS  = "127.0.0.1:1";
var UNREACHABLE_NTP  = "127.0.0.1";
var SHORT_TIMEOUT_MS = "250";

var ENV_KEYS = [
  "BLAMEJS_SKIP_NTP_CHECK", "BLAMEJS_NTS_REQUIRE", "BLAMEJS_NTS_SERVERS",
  "BLAMEJS_NTP_SERVERS", "BLAMEJS_NTP_TIMEOUT_MS", "BLAMEJS_NTP_REQUIRE_REACHABLE",
  "BLAMEJS_NTP_DRIFT_WARN_MS", "BLAMEJS_NTP_DRIFT_FATAL_MS",
];

function snapshotEnv() {
  var saved = {};
  ENV_KEYS.forEach(function (k) { saved[k] = process.env[k]; });
  return saved;
}
function restoreEnv(saved) {
  ENV_KEYS.forEach(function (k) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  });
}

// BLAMEJS_SKIP_NTP_CHECK returns before the requirement is consulted, so the
// two settings together booted with no authenticated time and said nothing. A
// requirement any earlier return can step over is not a requirement — and the
// same early-return shape guards a checker that will not load, which shares
// this guard.
async function attemptBootWithSkip(tmpDir) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  process.env.BLAMEJS_NTS_REQUIRE    = "1";
  delete process.env.BLAMEJS_NTP_REQUIRE_REACHABLE;
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  try {
    await b.db.init({
      dataDir:             tmpDir,
      tmpDir:              path.join(tmpDir, "tmpfs"),
      allowNonTmpfsTmpDir: true,
      schema:              [{ name: "t", columns: { _id: "TEXT PRIMARY KEY" } }],
    });
    return null;
  } catch (e) {
    return e;
  }
}

async function attemptBoot(tmpDir, requireNts, ntsServers) {
  // The suite-wide skip has to come OFF for this file, or the branch under
  // test never runs.
  delete process.env.BLAMEJS_SKIP_NTP_CHECK;
  delete process.env.BLAMEJS_NTP_REQUIRE_REACHABLE;
  process.env.BLAMEJS_NTS_SERVERS    = ntsServers || UNREACHABLE_NTS;
  process.env.BLAMEJS_NTP_SERVERS    = UNREACHABLE_NTP;
  process.env.BLAMEJS_NTP_TIMEOUT_MS = SHORT_TIMEOUT_MS;
  if (requireNts) process.env.BLAMEJS_NTS_REQUIRE = "1";
  else delete process.env.BLAMEJS_NTS_REQUIRE;

  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  try {
    await b.db.init({
      dataDir:             tmpDir,
      tmpDir:              path.join(tmpDir, "tmpfs"),
      allowNonTmpfsTmpDir: true,
      schema:              [{ name: "t", columns: { _id: "TEXT PRIMARY KEY" } }],
    });
    return null;
  } catch (e) {
    return e;
  }
}

// The three numeric NTP env vars are read with parseInt and passed on without
// checking the result. "abc" parses to NaN, and NaN reaches the boot check as a
// timeout — where it now fails the opts schema, so the whole clock check is
// SKIPPED. The thresholds are worse: their setThresholds call is wrapped in a
// catch that logs at DEBUG, so a mistyped drift threshold left the registered
// value in place and said nothing at all.
//
// A typo in a numeric setting must not quietly change clock policy. Refused at
// boot, naming the variable.
async function attemptBootWithEnv(tmpDir, key, value) {
  delete process.env.BLAMEJS_SKIP_NTP_CHECK;
  delete process.env.BLAMEJS_NTS_REQUIRE;
  delete process.env.BLAMEJS_NTP_REQUIRE_REACHABLE;
  process.env.BLAMEJS_NTP_SERVERS = UNREACHABLE_NTP;
  process.env[key] = value;
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  try {
    await b.db.init({
      dataDir:             tmpDir,
      tmpDir:              path.join(tmpDir, "tmpfs"),
      allowNonTmpfsTmpDir: true,
      schema:              [{ name: "t", columns: { _id: "TEXT PRIMARY KEY" } }],
    });
    return null;
  } catch (e) {
    return e;
  } finally {
    delete process.env[key];
  }
}

async function run() {
  var saved = snapshotEnv();
  var refusedDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nts-req-"));
  var allowedDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nts-opt-"));
  var badCfgDir  = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nts-bad-"));
  var skipDir    = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nts-skip-"));
  var envDirs    = [];
  try {
    var refused = await attemptBoot(refusedDir, true);
    check("db.init refuses when authenticated time is required and none was obtained",
      refused !== null, "init resolved instead of throwing");
    check("db.init: and the refusal carries the db/nts-required code",
      refused && refused.code === "db/nts-required",
      refused && ((refused.code || "") + " :: " + (refused.message || "")));
    check("db.init: the refusal names the setting that lifts it",
      refused && /BLAMEJS_NTS_SERVERS/.test(refused.message || "") &&
        /BLAMEJS_NTS_REQUIRE/.test(refused.message || ""),
      refused && refused.message);

    // This refusal throws with the database already OPEN — the boot check runs
    // after the chain verifications, which need a live handle. So it is not
    // only a refusal, it is a failed open, and a failed open that leaves its
    // decrypted working copy behind is a plaintext database sitting in tmpDir
    // with nothing left to remove it. That exact defect shipped once.
    //
    // The cleanup belongs to db.init and is not this feature's code, which is
    // the reason to assert it here: a NEW refusal added above that wrapper, or
    // moved out from under it, would leak silently and every other check in
    // this file would still pass.
    var leftBehind = [];
    try {
      var tmpfsDir = path.join(refusedDir, "tmpfs");
      leftBehind = fs.readdirSync(tmpfsDir).filter(function (n) {
        return /\.db$/.test(n) || /\.db-wal$/.test(n) || /\.db-shm$/.test(n);
      });
    } catch (_e) { leftBehind = []; }                 // no dir at all is the cleanest pass
    check("db.init: a refused boot leaves no decrypted working copy behind",
      leftBehind.length === 0, JSON.stringify(leftBehind));

    // Control. Same unreachable servers, same everything, knob unset: an
    // unanswered time query is a warning by design, so the boot proceeds.
    // If this also threw, the assertion above would be measuring the
    // unreachable server rather than the requirement.
    try { await b.db.close(); } catch (_e) { /* the refused handle may not be open */ }
    var allowed = await attemptBoot(allowedDir, false);
    check("db.init boots on the same unreachable servers when NTS is not required",
      allowed === null,
      allowed && ((allowed.code || "") + " :: " + (allowed.message || "")));

    // A check that could not COMPLETE is not a check that succeeded. Both
    // refusals are evaluated after the boot check returns, so a throw from the
    // check itself skipped them and a deployment that had required
    // authenticated time booted without it — the requirement defeated by a
    // typo in the setting that configures it.
    try { await b.db.close(); } catch (_e) { /* may not be open */ }
    var badCfg = await attemptBoot(badCfgDir, true, "nts.example:70000");
    check("db.init still refuses when the time check threw instead of answering",
      badCfg !== null && badCfg.code === "db/nts-required",
      badCfg && ((badCfg.code || "") + " :: " + (badCfg.message || "")));
    check("db.init: and the refusal names the setting to look at",
      badCfg && /BLAMEJS_NTS_SERVERS/.test(badCfg.message || ""),
      badCfg && badCfg.message);

    // Skipping the check entirely is the other way past the requirement, and it
    // sits ABOVE it in the same function. Two settings that contradict each
    // other resolve toward the one asking for a guarantee, and say so.
    try { await b.db.close(); } catch (_e) { /* may not be open */ }
    var skipped = await attemptBootWithSkip(skipDir);
    check("db.init refuses when the check is skipped but authenticated time is required",
      skipped !== null && skipped.code === "db/nts-required",
      skipped && ((skipped.code || "") + " :: " + (skipped.message || "")));
    check("db.init: and the refusal names the setting that skipped it",
      skipped && /BLAMEJS_SKIP_NTP_CHECK/.test(skipped.message || ""),
      skipped && skipped.message);

    // A mistyped numeric setting must be refused, not absorbed. Each of these
    // parses to NaN and previously changed clock policy in silence.
    var NUMERIC_ENV = [
      "BLAMEJS_NTP_TIMEOUT_MS",
      "BLAMEJS_NTP_DRIFT_WARN_MS",
      "BLAMEJS_NTP_DRIFT_FATAL_MS",
    ];
    for (var ei = 0; ei < NUMERIC_ENV.length; ei += 1) {
      try { await b.db.close(); } catch (_e) { /* may not be open */ }
      var envDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nts-env-"));
      envDirs.push(envDir);
      var envErr = await attemptBootWithEnv(envDir, NUMERIC_ENV[ei], "abc");
      check("db.init refuses a non-numeric " + NUMERIC_ENV[ei],
        envErr !== null, "init resolved instead of throwing");
      check("db.init: and the refusal names " + NUMERIC_ENV[ei],
        envErr && new RegExp(NUMERIC_ENV[ei]).test(envErr.message || ""),
        envErr && envErr.message);
    }

    // Both values well-formed, the COMBINATION incoherent: a warn threshold
    // above the fatal one cannot be satisfied. setThresholds refuses it, and
    // that refusal used to be caught and logged at debug, leaving the
    // registered defaults in force with nothing an operator would notice.
    try { await b.db.close(); } catch (_e) { /* may not be open */ }
    var comboDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nts-combo-"));
    envDirs.push(comboDir);
    process.env.BLAMEJS_NTP_DRIFT_FATAL_MS = "1000";
    var comboErr = await attemptBootWithEnv(comboDir, "BLAMEJS_NTP_DRIFT_WARN_MS", "100000");
    delete process.env.BLAMEJS_NTP_DRIFT_FATAL_MS;
    check("db.init refuses a warn threshold above the fatal one",
      comboErr !== null && comboErr.code === "db/bad-ntp-setting",
      comboErr && ((comboErr.code || "") + " :: " + (comboErr.message || "")));
    check("db.init: and the refusal names both settings",
      comboErr && /BLAMEJS_NTP_DRIFT_WARN_MS/.test(comboErr.message || "") &&
        /BLAMEJS_NTP_DRIFT_FATAL_MS/.test(comboErr.message || ""),
      comboErr && comboErr.message);

    // The control: a well-formed value for the same variable still boots, so
    // the refusals above are about the garbage and not about the variable
    // being read at all.
    try { await b.db.close(); } catch (_e) { /* may not be open */ }
    var goodDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nts-envok-"));
    envDirs.push(goodDir);
    var goodErr = await attemptBootWithEnv(goodDir, "BLAMEJS_NTP_TIMEOUT_MS", "250");
    check("db.init boots with a well-formed BLAMEJS_NTP_TIMEOUT_MS",
      goodErr === null, goodErr && ((goodErr.code || "") + " :: " + (goodErr.message || "")));
  } finally {
    try { await b.db.close(); } catch (_e) { /* may already be closed */ }
    b.db._resetForTest();
    restoreEnv(saved);
    [refusedDir, allowedDir, badCfgDir, skipDir].concat(envDirs).forEach(function (d) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
    });
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[db-nts-required-boot] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
