// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.audit.safeEmit scrubs secrets before the tamper-evident signed chain.
 *
 * safeEmit runs in request hot paths where operators routinely pass
 * `metadata: { detail: e.message }` from a caught error — and those error
 * strings carry DB connection strings (with passwords), JWTs, AWS
 * access-key ids, PEM/private-key blocks, and SSNs. The documented
 * guarantee (lib/audit.js safeEmit + the @primitive block) is that
 * actor / reason / metadata pass through b.redact.redact() so those
 * shapes are replaced with markers BEFORE the row is hash-chained and
 * SLH-DSA-checkpointed. Once a secret lands in the append-only signed
 * chain it cannot be UPDATE/DELETE'd out — so redaction has to happen at
 * the write boundary, not after.
 *
 * The prior coverage only asserted safeEmit "never throws". This drives a
 * secret-laden record end-to-end through the REAL path — full vault wrap,
 * at-rest-encrypted db, audit hash chain — then reads the stored row back
 * through b.audit.query (which UNSEALS the sealed columns: actorUserId /
 * actorIp / reason / metadata). The unsealed plaintext is exactly what a
 * forensic reader / auditor sees, so asserting the secret SUBSTRINGS are
 * absent there (and replaced by redact markers) proves the guarantee
 * against the actual stored ciphertext, not an in-memory copy.
 *
 * The secret values are placed under NON-sensitive field names (note /
 * detail / dbDsn / personId / signingPem / accessKeyId) so the proof
 * rests on redact's VALUE-SHAPE detectors (the real claim — a leaked
 * secret is caught by its shape regardless of how the operator named the
 * field), not on a lucky field-name match. The AWS *secret* access key
 * (40-char, no value-shape) is placed under a `secret`-named field to
 * exercise the field-name pass too.
 *
 * Run standalone: `node test/layer-0-primitives/audit-safeemit-redacts-secrets.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var waitUntil      = helpers.waitUntil;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-redact-")); }

// Clearly-fake but shape-valid secrets. Each is the WHOLE value of its
// field so redact's anchored value-shape detectors fire as designed.
var SECRETS = {
  // postgres://user:pass@host/db — connection-string credential leak.
  connString: "postgres://app_user:s3cr3t-Pw0rd@db.internal.example:5432/orders",
  connPw:     "s3cr3t-Pw0rd",
  // JWS compact triplet (eyJ... . eyJ... . sig).
  jwt:        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImFkbWluIjp0cnVlfQ.c2lnbmF0dXJlLWJ5dGVz",
  // AWS access-key id shape (AKIA + 16 upper-alnum). Value-shape detector.
  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
  // AWS secret access key (40 base64-ish chars) — no value-shape; relies
  // on the `secret`-named field-name pass.
  awsSecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  // US SSN shape.
  ssn:        "123-45-6789",
  // PEM private-key block.
  pem:        "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQ\n-----END PRIVATE KEY-----",
  // Luhn-valid test card numbers and an SSN, each used as a member name.
  cardKeyA:   "4111111111111111",
  cardKeyB:   "5555555555554444",
  ssnKey:     "987-65-4321",
};

// A non-secret value that MUST survive verbatim — proves redaction is
// targeted, not a blanket wipe of the whole event surface.
var SURVIVOR = "order-shipped-to-warehouse-7";

// Read every audit_log row that carries our marker action, through the
// real unseal path. metadata/reason/actor* are sealed columns, so this
// returns decrypted plaintext — exactly what an auditor reads.
async function _storedRows(action) {
  return await b.audit.query({ action: action });
}

// Flatten an unsealed row to a single searchable string. metadata is
// stored JSON-stringified; actor*/reason come back as plain strings.
function _rowText(row) {
  return JSON.stringify(row);
}

async function testSafeEmitRedactsSecretsInSignedChain() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var ACTION = "system.error.captured";

    // Operator's hot-path emission: a caught-error payload packed with
    // secrets across actor, reason, and metadata.
    b.audit.safeEmit({
      action:  ACTION,
      outcome: "failure",
      actor:   {
        userId: "u-77",
        // An actor field carrying a leaked connection string.
        ip:     "10.0.0.5",
      },
      reason:  "db connect failed: " + SECRETS.connString,
      metadata: {
        // Non-sensitive field names → value-shape detectors must fire.
        note:        "thrown while reconnecting",
        dbDsn:       SECRETS.connString,
        // Neutral field name (NOT in the sensitive-field list — avoids
        // `bearer`/`token`/`auth`) so the JWT VALUE-SHAPE detector is
        // what fires, proving shape-based catch rather than name-based.
        compactJws:  SECRETS.jwt,
        personId:    SECRETS.ssn,
        accessKeyId: SECRETS.awsAccessKeyId,
        signingPem:  SECRETS.pem,
        // field-name pass: `secret` substring.
        awsSecretAccessKey: SECRETS.awsSecretKey,
        // Secrets used as member names: the value detectors run on names too.
        byCard:      JSON.parse('{"' + SECRETS.cardKeyA + '":"order-a","' + SECRETS.cardKeyB + '":"order-b"}'),
        byPerson:    JSON.parse('{"' + SECRETS.ssnKey + '":"person-c"}'),
        // The survivor — a plain operational breadcrumb.
        orderRef:    SURVIVOR,
      },
    });

    // Drain the AsyncHandler so the row is durably in the signed chain.
    await b.audit.flush();
    await waitUntil(async function () {
      return (await _storedRows(ACTION)).length >= 1;
    }, { timeoutMs: 5000, label: "safeEmit: secret-laden row reaches audit_log" });

    var rows = await _storedRows(ACTION);
    check("exactly one " + ACTION + " row landed in the chain", rows.length === 1);
    var row = rows[0];
    var text = _rowText(row);

    // ---- Each secret SUBSTRING must be ABSENT from the stored row. ----
    // This is read back through the real unseal path, so it is the
    // forensic/auditor view of the immutable chain — not an in-memory copy.
    check("connection-string password absent from stored chain row",
          text.indexOf(SECRETS.connPw) === -1);
    check("full connection string absent from stored chain row",
          text.indexOf(SECRETS.connString) === -1);
    check("JWT absent from stored chain row",
          text.indexOf(SECRETS.jwt) === -1);
    check("AWS access-key id absent from stored chain row",
          text.indexOf(SECRETS.awsAccessKeyId) === -1);
    check("AWS secret access key absent from stored chain row",
          text.indexOf(SECRETS.awsSecretKey) === -1);
    check("SSN absent from stored chain row",
          text.indexOf(SECRETS.ssn) === -1);
    check("PEM private-key body absent from stored chain row",
          text.indexOf("MIIBVgIBADANBgkqhkiG9w0BAQ") === -1);
    check("PEM BEGIN header absent from stored chain row",
          text.indexOf("-----BEGIN PRIVATE KEY-----") === -1);

    check("card numbers used as member names are absent from stored chain row",
          text.indexOf(SECRETS.cardKeyA) === -1 && text.indexOf(SECRETS.cardKeyB) === -1, text);
    check("SSN used as a member name is absent from stored chain row",
          text.indexOf(SECRETS.ssnKey) === -1, text);
    var storedMeta = typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata;
    check("members with redacted names keep their values under numbered markers",
          storedMeta && storedMeta.byCard && storedMeta.byCard["[REDACTED]"] === "order-a" &&
          storedMeta.byCard["[REDACTED:2]"] === "order-b" && storedMeta.byPerson["[REDACTED]"] === "person-c",
          JSON.stringify(storedMeta));

    // ---- Markers must be PRESENT (redaction happened, value wasn't just
    //      dropped/blanked into ambiguity). ----
    check("connection-string redact marker present",
          text.indexOf("[REDACTED-CONN-STRING]") !== -1);
    check("JWT redact marker present",
          text.indexOf("[REDACTED-JWT]") !== -1);
    check("AWS access-key redact marker present",
          text.indexOf("[REDACTED-AWS-KEY]") !== -1);
    check("SSN redact marker present",
          text.indexOf("[REDACTED-SSN]") !== -1);
    check("PEM redact marker present",
          text.indexOf("[REDACTED-PEM]") !== -1);
    // The 40-char AWS secret has no value-shape; the `secret`-named field
    // is replaced with the default marker.
    check("default redact marker present (field-name pass on awsSecretAccessKey)",
          text.indexOf(b.redact.MARKER) !== -1);

    // ---- The non-secret breadcrumb survives verbatim. ----
    check("non-secret orderRef survives redaction verbatim",
          text.indexOf(SURVIVOR) !== -1);

    // ---- The chain still verifies end-to-end (the redacted row is a
    //      valid, signed, hash-chained member — redaction at the write
    //      boundary didn't corrupt the chain). ----
    var v = await b.audit.verify();
    check("audit chain verifies after the redacted append", v && v.ok === true);

    // A registered value detector that throws on one input counts as a
    // match, so the redactor does not throw and safeEmit does not write
    // the original actor, reason and metadata.
    var THROW_ACTION = "system.error.detector";
    b.redact.registerValueDetector("throws-on-boom", function (s) {
      if (s === "boom") throw new Error("detector threw");
      return false;
    }, "[REDACTED-X]");
    try {
      b.audit.safeEmit({
        action:   THROW_ACTION,
        outcome:  "failure",
        reason:   "lookup failed",
        metadata: {
          boom:     1,
          cardNote: SECRETS.cardKeyA,
          byCard:   JSON.parse('{"' + SECRETS.cardKeyB + '":"order-d"}'),
          orderRef: SURVIVOR,
        },
      });
      await b.audit.flush();
      await waitUntil(async function () {
        return (await _storedRows(THROW_ACTION)).length >= 1;
      }, { timeoutMs: 5000, label: "safeEmit: row with a throwing detector reaches audit_log" });
    } finally {
      b.redact._resetForTest();
    }
    var throwRows = await _storedRows(THROW_ACTION);
    var throwText = throwRows.length === 1 ? _rowText(throwRows[0]) : "";
    check("a throwing registered detector does not let card numbers into the stored chain row",
          throwRows.length === 1 && throwText.indexOf(SECRETS.cardKeyA) === -1 &&
          throwText.indexOf(SECRETS.cardKeyB) === -1 && throwText.indexOf(SURVIVOR) !== -1, throwText);

    // When the redactor itself throws (here on a getter that throws on its
    // first read and answers afterwards), the row is still written, and it
    // carries neither the original reason nor the original metadata.
    var FAIL_ACTION = "system.error.redaction";
    var hostile = { dbDsn: SECRETS.connString };
    var reads = 0;
    Object.defineProperty(hostile, "explodes", {
      enumerable: true,
      get: function () { reads += 1; if (reads === 1) throw new Error("getter threw"); return "later"; },
    });
    b.audit.safeEmit({
      action:   FAIL_ACTION,
      outcome:  "failure",
      actor:    { userId: "u-78", ip: "10.0.0.6" },
      reason:   "db connect failed: " + SECRETS.connString,
      metadata: hostile,
    });
    await b.audit.flush();
    await waitUntil(async function () {
      return (await _storedRows(FAIL_ACTION)).length >= 1;
    }, { timeoutMs: 5000, label: "safeEmit: row whose redaction threw reaches audit_log" });
    var failRows = await _storedRows(FAIL_ACTION);
    var failText = failRows.length === 1 ? _rowText(failRows[0]) : "";
    check("a redaction that throws does not write the original reason or metadata",
          failRows.length === 1 && failText.indexOf(SECRETS.connPw) === -1, failText);
    var v2 = await b.audit.verify();
    check("audit chain verifies after the redaction-failure append", v2 && v2.ok === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testSafeEmitRedactsSecretsInSignedChain();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       // Re-throw rather than console.error the error object: a DB-setup
       // failure can carry passphrase-derived material on the error, and
       // logging it would be clear-text logging of sensitive data
       // (CWE-312). The non-zero exit + thrown stack still surface the
       // failure to the runner.
       .catch(function (e) { process.exitCode = 1; throw e; });
}
