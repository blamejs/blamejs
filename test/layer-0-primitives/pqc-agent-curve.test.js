// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.pqcAgent — ecdhCurve negotiation surface.
 *
 * Covers the framework-default outbound group preference (the three
 * ML-KEM hybrids plus the trailing classical X25519 fallback for peers
 * that support no hybrid), the narrowing path (subset of the default),
 * and the operator-supplied-group escape hatch (allowOperatorGroups:
 * true) including the audit emit on accepted non-default groups.
 *
 * Run standalone: `node test/layer-0-primitives/pqc-agent-curve.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

async function testDefaultGroupList() {
  var agent = b.pqcAgent.create();
  // The agent is built with options.ecdhCurve set to the framework
  // PQC-hybrid preference. Read it via agent.options.
  var ec = agent.options.ecdhCurve;
  check("default ecdhCurve includes SecP384r1MLKEM1024",
        ec.indexOf("SecP384r1MLKEM1024") !== -1);
  check("default ecdhCurve includes X25519MLKEM768",
        ec.indexOf("X25519MLKEM768") !== -1);
  check("default ecdhCurve includes SecP256r1MLKEM768",
        ec.indexOf("SecP256r1MLKEM768") !== -1);
  // Assert the invariant, not a transcription of the list: the agent offers
  // exactly the framework's single source of outbound group order. Pinning
  // the order here as well let the two drift apart silently.
  check("default ecdhCurve is the framework outbound group order verbatim",
        ec === b.constants.TLS_GROUP_CURVE_STR);
  // The classical X25519 fallback is the LAST group — hybrids are always
  // preferred; classical is only negotiated when the peer offers no hybrid.
  var groups = ec.split(":");
  check("default ecdhCurve ends with the classical X25519 fallback",
        groups[groups.length - 1] === "X25519");
  agent.destroy();
}

function testNarrowToFrameworkSubset() {
  // Narrowing within the framework preference list is allowed without
  // allowOperatorGroups.
  var agent = b.pqcAgent.create({ ecdhCurve: "SecP256r1MLKEM768" });
  check("narrowed ecdhCurve = SecP256r1MLKEM768",
        agent.options.ecdhCurve === "SecP256r1MLKEM768");
  agent.destroy();

  var two = b.pqcAgent.create({ ecdhCurve: "X25519MLKEM768:SecP256r1MLKEM768" });
  check("two-group narrowing accepted",
        two.options.ecdhCurve === "X25519MLKEM768:SecP256r1MLKEM768");
  two.destroy();
}

function testNarrowedSelectionSurvivesTheContextFill() {
  // The agent's options pass through network-tls's context filler, which
  // supplies the configured key shares when the base names no preference. A
  // caller who narrowed or reordered the list must not have it re-derived
  // from that ordering underneath them, or the handshake would offer key
  // shares they had deliberately dropped.
  var agent = b.pqcAgent.create();
  check("default: the group preference is a non-empty string",
        typeof agent.options.ecdhCurve === "string" &&
        agent.options.ecdhCurve.length > 0);
  agent.destroy();

  var narrowed = b.pqcAgent.create({ ecdhCurve: "SecP256r1MLKEM768" });
  check("narrowed: the context filler leaves the narrowed list alone",
        narrowed.options.ecdhCurve === "SecP256r1MLKEM768");
  narrowed.destroy();

  var reordered = b.pqcAgent.create({ ecdhCurve: "X25519:X25519MLKEM768" });
  check("reordered: the caller's ordering is preserved, not re-derived",
        reordered.options.ecdhCurve === "X25519:X25519MLKEM768");
  reordered.destroy();
}

function testRefuseUnknownGroupByDefault() {
  var threw = false;
  try {
    // secp256r1 (classical P-256) is a KNOWN_TLS_GROUPS entry but NOT in the
    // framework outbound preference (the hybrids + the X25519 fallback), so
    // it's refused without allowOperatorGroups.
    b.pqcAgent.create({ ecdhCurve: "secp256r1" });
  } catch (e) {
    threw = e instanceof TypeError &&
            e.message.indexOf("not in the framework PQC-hybrid") !== -1 &&
            e.message.indexOf("allowOperatorGroups") !== -1;
  }
  check("default refuses non-framework group with helpful error", threw);

  var threwUnknown = false;
  try {
    b.pqcAgent.create({ ecdhCurve: "NotARealGroup", allowOperatorGroups: true });
  } catch (e) {
    threwUnknown = e instanceof TypeError &&
                   e.message.indexOf("not a known IANA TLS Supported Group") !== -1;
  }
  check("allowOperatorGroups still refuses unknown group names", threwUnknown);

  var threwBadShape = false;
  try {
    b.pqcAgent.create({ ecdhCurve: "X25519:bad name", allowOperatorGroups: true });
  } catch (e) {
    threwBadShape = e instanceof TypeError &&
                    e.message.indexOf("illegal characters") !== -1;
  }
  check("operator-group entries reject illegal characters", threwBadShape);
}

async function testAllowOperatorGroupsAuditEmit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-pqcagent-"));
  try {
    await setupTestDb(tmpDir);
    // secp256r1 (classical P-256) is outside the framework preference, so it
    // exercises the operator-group escape hatch + the acceptance audit.
    var agent = b.pqcAgent.create({
      ecdhCurve:           "secp256r1",
      allowOperatorGroups: true,
    });
    check("secp256r1 accepted under allowOperatorGroups",
          agent.options.ecdhCurve === "secp256r1");
    check("operator-group: nothing re-derives over the operator's choice",
          agent.options.groups === undefined);
    agent.destroy();

    await b.audit.flush();
    var rows = await b.audit.query({ action: "pqcagent.operator_group.accepted" });
    check("audit row written for operator-group acceptance", rows.length >= 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit metadata carries group=secp256r1", meta.group === "secp256r1");
    check("audit metadata carries ecdhCurve",    meta.ecdhCurve === "secp256r1");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- What the negotiated key exchange actually was ----
//
// The post-handshake observer reads getEphemeralKeyInfo(). Node 24.19.0
// reports a post-quantum hybrid positively (`{ name, type: "TLSGroup" }`);
// before that a hybrid reported nothing, so "nothing reported" had to be
// read as "hybrid". It no longer does: per the tls docs an empty key-info
// now means the key exchange was NOT ephemeral — no forward secrecy, let
// alone post-quantum — which is the one outcome that must never be silent.
async function testKeyExchangeObservation() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-pqckx-"));
  try {
    await setupTestDb(tmpDir);
    var since = Date.now() - 1000;
    function fakeSocket(info) {
      return { getEphemeralKeyInfo: function () { return info; } };
    }
    var meta = { host: "peer.example", port: 443 };

    b.pqcAgent._auditClassicalDowngrade(
      fakeSocket({ name: "X25519MLKEM768", type: "TLSGroup" }), meta);
    b.pqcAgent._auditClassicalDowngrade(
      fakeSocket({ name: "X25519", type: "ECDH", size: 253 }), meta);
    b.pqcAgent._auditClassicalDowngrade(fakeSocket({}), meta);
    // A RESUMED session carries no new key exchange, so an empty reading says
    // nothing about its forward secrecy — it inherits the original
    // handshake's. Connection-pool churn makes resumption routine, so
    // recording those would bury the findings that matter.
    var resumed = fakeSocket({});
    resumed.isSessionReused = function () { return true; };
    b.pqcAgent._auditClassicalDowngrade(resumed, meta);

    await b.audit.flush();
    var downgrades = await b.audit.query({
      action: "tls.classical_downgrade", from: since, limit: 100 });
    var nonEphemeral = await b.audit.query({
      action: "tls.no_ephemeral_key_exchange", from: since, limit: 100 });

    check("a post-quantum hybrid is not audited as a downgrade",
          downgrades.filter(function (r) {
            var m = typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata;
            return m && /MLKEM/i.test(String(m.group));
          }).length === 0);
    check("an observed classical group is audited as a downgrade",
          downgrades.filter(function (r) {
            var m = typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata;
            return m && m.group === "X25519";
          }).length >= 1);
    check("a non-ephemeral key exchange gets its own audit action, not silence",
          nonEphemeral.length >= 1);
    check("a resumed session is not recorded as having no ephemeral key exchange",
          nonEphemeral.length === 1);
    check("the non-ephemeral audit is not conflated with a classical group",
          downgrades.filter(function (r) {
            var m = typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata;
            return !m || m.group === null || m.group === undefined;
          }).length === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

function testKnownTlsGroupsExposed() {
  check("KNOWN_TLS_GROUPS exposed as array",
        Array.isArray(b.pqcAgent.KNOWN_TLS_GROUPS));
  check("KNOWN_TLS_GROUPS includes SecP256r1MLKEM768",
        b.pqcAgent.KNOWN_TLS_GROUPS.indexOf("SecP256r1MLKEM768") !== -1);
  check("KNOWN_TLS_GROUPS includes X25519",
        b.pqcAgent.KNOWN_TLS_GROUPS.indexOf("X25519") !== -1);
}

function testReloadSurface() {
  check("b.pqcAgent.reload is fn", typeof b.pqcAgent.reload === "function");
}

function testReloadAfterBuild() {
  // Touch b.pqcAgent.agent so it lazy-builds; then b.pqcAgent.reload()
  // tears it down. Subsequent agent access rebuilds.
  var first = b.pqcAgent.agent;
  check("agent: lazy-built on first access",
        first !== null && typeof first.destroy === "function");
  var res = b.pqcAgent.reload();
  check("reload: returns object", res && typeof res.destroyed === "boolean");
  var second = b.pqcAgent.agent;
  check("agent: rebuilt after reload", second !== null);
  // Reload is idempotent (no-op when nothing built).
  b.pqcAgent.reload();   // destroys second
  var res2 = b.pqcAgent.reload();
  check("reload: idempotent — second consecutive call returns destroyed=false",
        res2.destroyed === false);
}

async function run() {
  await testDefaultGroupList();
  testNarrowToFrameworkSubset();
  testNarrowedSelectionSurvivesTheContextFill();
  testRefuseUnknownGroupByDefault();
  await testAllowOperatorGroupsAuditEmit();
  await testKeyExchangeObservation();
  testKnownTlsGroupsExposed();
  testReloadSurface();
  testReloadAfterBuild();
}

if (require.main === module) {
  run().catch(function (e) { console.error(e); process.exit(1); });
}

module.exports = { run: run };
