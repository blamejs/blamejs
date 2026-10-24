// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.fidoMds3.fetch refuses a compromised key in the trust root an
 * operator passes as caCertificate and anywhere in the x5c chain of the
 * metadata BLOB, whether the compromised certificate signs the BLOB or
 * issues the certificate that does. Each refusal has a control chain that
 * differs only in the key. The shipped MDS3 root carries an ordinary key.
 *
 * The x5c chain is bounded at the toolkit's limit of ten certificates before
 * any certificate is examined. A certificate the key check cannot read is
 * refused as `fido-mds3/bad-x5c` in the chain and skipped among the roots, so
 * fetch only ever throws FidoMds3Error. A certificate whose key node cannot
 * load is still judged by the toolkit's lint, so the chain check decides it.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");
var composite  = require("../helpers/composite-key-cert");
var bCrypto    = require("../../lib/crypto");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");
var CryptoKeyError = require("../../lib/framework-error").CryptoKeyError;

var X5C_LIMIT = pki.constants.LIMITS.WEBAUTHN_X5C_MAX_CERTS;

function _scalar(label) {
  return BigInt("0x" + nodeCrypto.createHash("sha256").update(label, "utf8").digest("hex"));
}
var COMPROMISED_KEY = ck.ecKeyPair("prime256v1", 1n).privateKey;
var CONTROL_INTERMEDIATE_KEY = ck.ecKeyPair("prime256v1", _scalar("blamejs tls fixture intermediate")).privateKey;
var TLS_LEAF_KEY = ck.ecKeyPair("prime256v1", _scalar("blamejs tls fixture leaf")).privateKey;

function _b64(der) { return Buffer.from(der).toString("base64"); }

function _blob(x5cDers, signingKey) {
  var header = { alg: "ES256", typ: "JWT", x5c: x5cDers.map(_b64) };
  var payload = {
    legalHeader: "Test BLOB", no: 7,
    nextUpdate: new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),        // allow:raw-byte-literal (fixture days-out)
    entries: [{
      aaguid: "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
      metadataStatement: { description: "Forged authenticator" },
      statusReports: [{ status: "FIDO_CERTIFIED_L3_PLUS" }],
    }],
  };
  var input = Buffer.from(JSON.stringify(header)).toString("base64url") + "." +
    Buffer.from(JSON.stringify(payload)).toString("base64url");
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: signingKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

var _seq = 0;
async function _fetch(token, caCertificate) {
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(token, "ascii") };            // allow:raw-byte-literal (HTTP success)
    },
  });
  var fmPath = require.resolve("../../lib/auth/fido-mds3");
  delete require.cache[fmPath];
  var fm = require(fmPath);
  _seq += 1;
  try {
    var blob = await fm.fetch({ url: "https://mds3-compromised-" + _seq + ".test.invalid/", caCertificate: caCertificate, force: true });
    return { ok: true, blob: blob };
  } catch (e) {
    return { ok: false, code: e.code || e.message };
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }
}

async function testCaCertificateIsRefused() {
  var control = await _fetch(_blob([ck.P256_CONTROL_LEAF_DER], ck.p256AttestationLeafKey()),
    ck.certPem(ck.P256_CONTROL_CA_DER));
  check("fido mds3 compromised key control: a BLOB under an ordinary caCertificate verifies",
        control.ok === true && control.blob.entries.length === 1, JSON.stringify(control.code));
  var bad = await _fetch(_blob([ck.P256_COMPROMISED_LEAF_DER], ck.p256AttestationLeafKey()),
    ck.certPem(ck.P256_COMPROMISED_CA_DER));
  check("fido mds3 compromised key: a caCertificate whose private key is 1 is refused",
        bad.ok === false && bad.code === "fido-mds3/compromised-key", JSON.stringify(bad));
  var listed = await _fetch(_blob([ck.P256_CONTROL_LEAF_DER], ck.p256AttestationLeafKey()),
    [ck.certPem(ck.P256_CONTROL_CA_DER), ck.EDELLROOT_CERT_PEM]);
  check("fido mds3 compromised key: a caCertificate list holding the eDellRoot certificate is refused",
        listed.ok === false && listed.code === "fido-mds3/compromised-key", JSON.stringify(listed));
}

async function testCompromisedSigningCertificateIsRefused() {
  var root = ck.certPem(ck.TLS_ROOT_DER);
  var control = await _fetch(_blob([ck.TLS_CONTROL_INTERMEDIATE_DER], CONTROL_INTERMEDIATE_KEY), root);
  check("fido mds3 compromised key control: a BLOB signed by an ordinary certificate under the root verifies",
        control.ok === true, JSON.stringify(control.code));
  var bad = await _fetch(_blob([ck.TLS_COMPROMISED_INTERMEDIATE_DER], COMPROMISED_KEY), root);
  check("fido mds3 compromised key: a BLOB signed by a certificate whose private key is 1 is refused",
        bad.ok === false && bad.code === "fido-mds3/compromised-key", JSON.stringify(bad));
}

async function testCompromisedIntermediateIsRefused() {
  var root = ck.certPem(ck.TLS_ROOT_DER);
  var control = await _fetch(_blob([ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER], TLS_LEAF_KEY), root);
  check("fido mds3 compromised key control: a BLOB whose chain runs through an ordinary intermediate verifies",
        control.ok === true, JSON.stringify(control.code));
  var bad = await _fetch(_blob([ck.TLS_COMPROMISED_LEAF_DER, ck.TLS_COMPROMISED_INTERMEDIATE_DER], TLS_LEAF_KEY), root);
  check("fido mds3 compromised key: a BLOB whose chain runs through an intermediate whose private key is 1 is refused",
        bad.ok === false && bad.code === "fido-mds3/compromised-key", JSON.stringify(bad));
}

// Runs fn with b.crypto.assertNotCompromised wrapped: `onCall(label)` sees the
// label of each check and may throw in its place. Returns fn's result and the
// labels checked.
async function _withCheckSpy(onCall, fn) {
  var original = bCrypto.assertNotCompromised;
  var labels = [];
  bCrypto.assertNotCompromised = function (key, opts) {
    var label = opts && opts.label;
    labels.push(label);
    if (onCall) onCall(label);
    return original.apply(this, arguments);
  };
  try { return { result: await fn(), labels: labels }; }
  finally { bCrypto.assertNotCompromised = original; }
}

function _x5cLabels(labels) {
  return labels.filter(function (l) { return /^x5c\[/.test(String(l)); }).length;
}

async function testX5cScanIsBounded() {
  var root = ck.certPem(ck.TLS_ROOT_DER);
  var atLimit = [ck.TLS_CONTROL_LEAF_DER];
  while (atLimit.length < X5C_LIMIT) atLimit.push(ck.TLS_CONTROL_INTERMEDIATE_DER);
  var control = await _withCheckSpy(null, function () { return _fetch(_blob(atLimit, TLS_LEAF_KEY), root); });
  check("fido mds3 compromised key control: an x5c chain of " + X5C_LIMIT + " certificates is checked " +
        "certificate by certificate",
        _x5cLabels(control.labels) === X5C_LIMIT, JSON.stringify(control));
  var over = atLimit.concat([ck.TLS_CONTROL_INTERMEDIATE_DER]);
  var flood = await _withCheckSpy(null, function () { return _fetch(_blob(over, TLS_LEAF_KEY), root); });
  check("fido mds3 compromised key: an x5c chain of " + over.length + " certificates is refused before " +
        "any certificate in it is examined",
        flood.result.ok === false && flood.result.code === "fido-mds3/bad-x5c" && _x5cLabels(flood.labels) === 0,
        JSON.stringify(flood));
}

function _unreadableAt(target) {
  return function (label) {
    if (label === target) {
      throw new CryptoKeyError("crypto/bad-key", "crypto.compromisedKey: the value could not be read");
    }
  };
}

async function testAnUnreadableCertificateIsTheModulesOwnError() {
  var root = ck.certPem(ck.TLS_ROOT_DER);
  var chain = [ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER];
  var leafUnreadable = await _withCheckSpy(_unreadableAt("x5c[0]"),
    function () { return _fetch(_blob(chain, TLS_LEAF_KEY), root); });
  check("fido mds3 compromised key: an x5c certificate the key check cannot read is refused as fido-mds3/bad-x5c",
        leafUnreadable.result.ok === false && leafUnreadable.result.code === "fido-mds3/bad-x5c",
        JSON.stringify(leafUnreadable.result));
  var intermediateUnreadable = await _withCheckSpy(_unreadableAt("x5c[1]"),
    function () { return _fetch(_blob(chain, TLS_LEAF_KEY), root); });
  check("fido mds3 compromised key: an unreadable certificate later in the chain is refused the same way",
        intermediateUnreadable.result.ok === false &&
        intermediateUnreadable.result.code === "fido-mds3/bad-x5c",
        JSON.stringify(intermediateUnreadable.result));
  var rootUnreadable = await _withCheckSpy(_unreadableAt("caCertificate[0]"),
    function () { return _fetch(_blob(chain, TLS_LEAF_KEY), [ck.certPem(ck.P256_CONTROL_CA_DER), root]); });
  check("fido mds3 compromised key: a caCertificate entry the key check cannot read is skipped and another " +
        "root anchors the chain",
        rootUnreadable.result.ok === true, JSON.stringify(rootUnreadable.result));
}

async function testACertificateNodeCannotLoadKeepsTheChainVerdict() {
  var root = ck.certPem(ck.TLS_ROOT_DER);
  var chain = [ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER];
  var extra = await _fetch(_blob(chain.concat([composite.COMPOSITE_CERT_DER]), TLS_LEAF_KEY), root);
  check("fido mds3 compromised key: an extra x5c certificate whose key node cannot load is refused by the " +
        "chain check as fido-mds3/chain-broken",
        extra.ok === false && extra.code === "fido-mds3/chain-broken", JSON.stringify(extra));
  var rootList = await _fetch(_blob(chain, TLS_LEAF_KEY), [composite.COMPOSITE_CERT_PEM, root]);
  check("fido mds3 compromised key: a caCertificate entry whose key node cannot load is passed over and " +
        "another root anchors the chain",
        rootList.ok === true, JSON.stringify(rootList));
}

function testShippedRootIsNotCompromised() {
  var roots = b.auth.fidoMds3._defaultRootPems ? b.auth.fidoMds3._defaultRootPems()
    : require("../../lib/auth/fido-mds3")._defaultRootPems();
  check("fido mds3 compromised key: the shipped MDS3 root carries an ordinary key",
        roots.length === 1 && b.crypto.compromisedKey(roots[0]) === null);
}

async function run() {
  await testCaCertificateIsRefused();
  await testCompromisedSigningCertificateIsRefused();
  await testCompromisedIntermediateIsRefused();
  await testX5cScanIsBounded();
  await testAnUnreadableCertificateIsTheModulesOwnError();
  await testACertificateNodeCannotLoadKeepsTheChainVerdict();
  testShippedRootIsNotCompromised();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
