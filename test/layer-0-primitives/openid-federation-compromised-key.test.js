// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.openidFederation refuses a compromised key: a key anyone can hold
 * the private half of. The compromised key is the P-256 key whose private
 * scalar is 1; the controls are P-256 keys derived from labels, and every
 * refusal is paired with the same federation under control keys.
 *
 * A compromised key in any configured trust anchor's JWKS, used or not, is
 * refused by buildTrustChain before anything is fetched. An anchor key that
 * cannot be imported and is never selected does not stop resolution. A
 * compromised key in a statement's own JWKS, or in the JWKS a superior pins
 * for a subordinate (with the subordinate's own JWKS holding a control key),
 * is refused when a statement is verified against it.
 *
 * buildTrustChain records a chain_built audit row that b.audit accepts.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var ck         = require("../helpers/compromised-keys");

var BAD    = ck.ecKeyPair("prime256v1", 1n);
var ANCHOR = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs federation compromised-key anchor"));
var LEAF   = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs federation compromised-key leaf"));

var P256_GENERATOR_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
var ANCHOR_ID = "https://anchor.example";
var LEAF_ID   = "https://rogue-op.example";

function _jwk(kp, kid) {
  var j = kp.publicKey.export({ format: "jwk" });
  j.kid = kid;
  return j;
}

function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _statement(kp, kid, claims) {
  var now = Math.floor(Date.now() / 1000);
  var input = _b64uJson({ typ: "entity-statement+jwt", alg: "ES256", kid: kid }) + "." +
    _b64uJson(Object.assign({ iat: now, exp: now + 3600 }, claims));
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: kp.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

// extra.anchorKeys: more keys in the configured anchor JWKS, never selected.
// extra.otherAnchors: more { entityId: jwks } trust anchors the chain does not reach.
// extra.pinnedKp: the key the anchor pins for the leaf, when it differs from the
// key the leaf publishes in its own entity configuration.
function _federation(anchorKp, leafKp, extra) {
  extra = extra || {};
  var anchorJwks = { keys: [_jwk(anchorKp, "a")].concat(extra.anchorKeys || []) };
  var leafJwks   = { keys: [_jwk(leafKp, "l")] };
  var pinnedJwks = extra.pinnedKp ? { keys: [_jwk(extra.pinnedKp, "l")] } : leafJwks;
  var docs = {};
  docs[ANCHOR_ID + "/.well-known/openid-federation"] =
    _statement(anchorKp, "a", { iss: ANCHOR_ID, sub: ANCHOR_ID, jwks: anchorJwks });
  docs[LEAF_ID + "/.well-known/openid-federation"] = _statement(leafKp, "l", {
    iss: LEAF_ID, sub: LEAF_ID, jwks: leafJwks, authority_hints: [ANCHOR_ID],
    metadata: { openid_provider: { issuer: LEAF_ID, authorization_endpoint: LEAF_ID + "/authorize" } },
  });
  var subordinate = _statement(anchorKp, "a", { iss: ANCHOR_ID, sub: LEAF_ID, jwks: pinnedJwks });
  var fetches = { count: 0 };
  var anchors = Object.assign({}, extra.otherAnchors || {});
  anchors[ANCHOR_ID] = anchorJwks;
  return {
    fetches: fetches,
    opts: {
      leafEntityId: LEAF_ID,
      trustAnchors: anchors,
      kind:         "openid_provider",
      fetcher: async function (url) {
        fetches.count += 1;
        if (!docs[url]) throw new Error("no document at " + url);
        return docs[url];
      },
      fetchSubordinate: async function () { fetches.count += 1; return subordinate; },
    },
    subordinate: subordinate,
    anchorJwks:  anchorJwks,
  };
}

async function _err(fn) {
  try { await fn(); return null; } catch (e) { return e; }
}

function testFixtureIsTheScalarOneKey() {
  check("federation compromised key: the fixture public key is the P-256 generator",
        BAD.publicKey.export({ format: "jwk" }).x === P256_GENERATOR_X);
  check("federation compromised key control: the control public keys are not the generator",
        ANCHOR.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X &&
        LEAF.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X);
}

async function testVerifyEntityStatementRefusesCompromisedKey() {
  var good = _federation(ANCHOR, LEAF);
  var bad  = _federation(BAD, LEAF);
  check("federation compromised key control: a statement verifies under the control anchor JWKS",
        (await _err(function () {
          return b.auth.openidFederation.verifyEntityStatement(good.subordinate, good.anchorJwks);
        })) === null);
  var e = await _err(function () {
    return b.auth.openidFederation.verifyEntityStatement(bad.subordinate, bad.anchorJwks);
  });
  check("federation compromised key: a statement under a compromised JWKS key is refused",
        e !== null && e.code === "auth-openid-federation/compromised-key", e && e.code);
}

async function testTrustAnchorWithCompromisedKeyIsRefusedAtConfiguration() {
  var good = _federation(ANCHOR, LEAF);
  var resolved = null;
  try { resolved = await b.auth.openidFederation.resolveLeaf(good.opts); } catch (_e) { resolved = null; }
  check("federation compromised key control: resolveLeaf resolves the leaf under the control anchor",
        resolved !== null && resolved.trustAnchor === ANCHOR_ID &&
          resolved.effectiveMetadata.issuer === LEAF_ID);

  var bad = _federation(BAD, LEAF);
  var e = await _err(function () { return b.auth.openidFederation.buildTrustChain(bad.opts); });
  check("federation compromised key: buildTrustChain refuses a trust anchor holding a compromised key",
        e !== null && e.code === "auth-openid-federation/compromised-key", e && e.code);
  check("federation compromised key: the compromised trust anchor is refused before anything is fetched",
        bad.fetches.count === 0, bad.fetches.count);
  e = await _err(function () { return b.auth.openidFederation.resolveLeaf(_federation(BAD, LEAF).opts); });
  check("federation compromised key: resolveLeaf refuses a trust anchor holding a compromised key",
        e !== null && e.code === "auth-openid-federation/compromised-key", e && e.code);
}

async function testCompromisedLeafSelfKeyIsRefused() {
  var bad = _federation(ANCHOR, BAD);
  var e = await _err(function () { return b.auth.openidFederation.resolveLeaf(bad.opts); });
  check("federation compromised key: a leaf whose own JWKS key is compromised is refused",
        e !== null && e.code === "auth-openid-federation/compromised-key", e && e.code);
}

async function testCompromisedPinnedKeyIsRefused() {
  var control = _federation(ANCHOR, LEAF, { pinnedKp: LEAF });
  check("federation compromised key control: a leaf whose pinned key matches its own key resolves",
        (await _err(function () { return b.auth.openidFederation.resolveLeaf(control.opts); })) === null);
  var bad = _federation(ANCHOR, LEAF, { pinnedKp: BAD });
  var e = await _err(function () { return b.auth.openidFederation.resolveLeaf(bad.opts); });
  check("federation compromised key: a leaf whose superior pins a compromised key is refused",
        e !== null && e.code === "auth-openid-federation/compromised-key" &&
          /compromised key/.test(e.message), e && (e.code + " " + e.message));
}

async function testUnusedAnchorKeysThatCannotBeImportedAreIgnored() {
  var oct = { kty: "oct", k: "c2VjcmV0LXNlY3JldC1zZWNyZXQ", kid: "unused-oct" };
  var badEc = { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA", kid: "unused-ec" };
  var cases = [["an unused oct key", oct], ["an unused malformed EC key", badEc]];
  for (var i = 0; i < cases.length; i += 1) {
    var fed = _federation(ANCHOR, LEAF, { anchorKeys: [cases[i][1]] });
    var resolved = null;
    try { resolved = await b.auth.openidFederation.resolveLeaf(fed.opts); } catch (e) { resolved = e; }
    check("federation anchor JWKS: " + cases[i][0] + " in the anchor JWKS does not stop resolution",
          resolved && resolved.trustAnchor === ANCHOR_ID, resolved && (resolved.code || resolved.trustAnchor));
  }
}

async function testCompromisedKeyInAnyConfiguredAnchorIsRefused() {
  var other = { "https://other-anchor.example": { keys: [_jwk(BAD, "o")] } };
  var unusedCompromised = _federation(ANCHOR, LEAF, { anchorKeys: [_jwk(BAD, "unused")] });
  var e = await _err(function () { return b.auth.openidFederation.resolveLeaf(unusedCompromised.opts); });
  check("federation compromised key: an unused compromised key in the reached anchor's JWKS is refused",
        e !== null && e.code === "auth-openid-federation/compromised-key", e && e.code);
  var otherAnchor = _federation(ANCHOR, LEAF, { otherAnchors: other });
  e = await _err(function () { return b.auth.openidFederation.resolveLeaf(otherAnchor.opts); });
  check("federation compromised key: a compromised key in another configured anchor is refused",
        e !== null && e.code === "auth-openid-federation/compromised-key", e && e.code);
  check("federation compromised key: the configured anchors are checked before anything is fetched",
        otherAnchor.fetches.count === 0, otherAnchor.fetches.count);
}

async function testChainBuiltAuditRowIsRecorded() {
  var emitted = [];
  var original = b.audit.safeEmit;
  var refusedBefore = b.audit.refusedActions().length;
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-oidfed-audit-"));
  var rows = [];
  b.audit.safeEmit = function (event) {
    emitted.push(event && event.action);
    return original.apply(this, arguments);
  };
  try {
    await helpers.setupTestDb(tmpDir);
    await b.auth.openidFederation.buildTrustChain(_federation(ANCHOR, LEAF).opts);
    await b.audit.flush();
    rows = await b.audit.query({ action: "auth.openid_federation.chain_built" });
  } finally {
    b.audit.safeEmit = original;
    await helpers.teardownTestDb(tmpDir);
  }
  var actions = emitted.filter(function (a) { return /chain_built$/.test(String(a)); });
  check("federation audit: buildTrustChain emits a chain_built row",
        actions.length === 1, JSON.stringify(emitted));
  check("federation audit: b.audit accepts the chain_built action",
        b.audit.refusedActions().length === refusedBefore &&
          b.audit.refusedActions().every(function (r) { return !/chain_built/.test(r.action); }),
        JSON.stringify(b.audit.refusedActions()));
  var meta = rows.length === 1 && (typeof rows[0].metadata === "string" ? JSON.parse(rows[0].metadata) : rows[0].metadata);
  check("federation audit: the chain_built row is written to the audit log",
        rows.length === 1 && rows[0].outcome === "success" && meta && meta.anchor === ANCHOR_ID && meta.leaf === LEAF_ID,
        JSON.stringify(rows));
}

async function run() {
  testFixtureIsTheScalarOneKey();
  await testVerifyEntityStatementRefusesCompromisedKey();
  await testTrustAnchorWithCompromisedKeyIsRefusedAtConfiguration();
  await testCompromisedLeafSelfKeyIsRefused();
  await testCompromisedPinnedKeyIsRefused();
  await testUnusedAnchorKeysThatCannotBeImportedAreIgnored();
  await testCompromisedKeyInAnyConfiguredAnchorIsRefused();
  await testChainBuiltAuditRowIsRecorded();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
