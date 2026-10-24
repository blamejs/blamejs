// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.deploy.danePublish refuses to produce a TLSA record for a
 * certificate whose private key anyone can hold, with
 * `mail-deploy/compromised-key`, for every usage and selector. The control
 * certificate differs only in the private scalar.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var composite = require("../helpers/composite-key-cert");

function _publish(certPem, usage, selector) {
  try {
    return { ok: true, value: b.mail.deploy.danePublish({ certPem: certPem, mxHost: "mx1.example.com", usage: usage, selector: selector }) };
  } catch (e) {
    return { ok: false, code: e && e.code, message: e && e.message };
  }
}

function testDanePublishRefusesACompromisedKey() {
  [3, 2, 1, 0].forEach(function (usage) {
    [1, 0].forEach(function (selector) {
      var label = "usage " + usage + " selector " + selector;
      var control = _publish(ck.certPem(ck.P256_CONTROL_CA_DER), usage, selector);
      check("mail-deploy compromised key control: danePublish " + label + " returns a record for an ordinary key",
            control.ok === true && control.value.record.indexOf(usage + " " + selector + " 1 ") === 0, JSON.stringify(control));
      var bad = _publish(ck.certPem(ck.P256_COMPROMISED_CA_DER), usage, selector);
      check("mail-deploy compromised key: danePublish " + label + " refuses a certificate whose private key is 1",
            bad.ok === false && bad.code === "mail-deploy/compromised-key", JSON.stringify(bad));
    });
  });
  var listed = _publish(ck.EDELLROOT_CERT_PEM, 3, 1);
  check("mail-deploy compromised key: danePublish refuses the listed eDellRoot certificate",
        listed.ok === false && listed.code === "mail-deploy/compromised-key" && /eDellRoot/i.test(listed.message || ""),
        JSON.stringify(listed));
}

function testDanePublishAcceptsACompositeKeyCertificate() {
  [0, 1].forEach(function (selector) {
    var r = _publish(composite.COMPOSITE_CERT_PEM, 3, selector);
    var data = selector === 0 ? composite.COMPOSITE_CERT_DER : composite.COMPOSITE_SPKI_DER;
    var want = "3 " + selector + " 1 " + nodeCrypto.createHash("sha256").update(data).digest("hex");
    check("mail-deploy composite key: danePublish 3 " + selector + " 1 hashes a composite ML-DSA certificate's " +
          (selector === 0 ? "DER" : "SubjectPublicKeyInfo"),
          r.ok === true && r.value.record === want, JSON.stringify(r));
  });
}

function testAnUnreadableKeyIsNotReportedAsCompromised() {
  var bCrypto = require("../../lib/crypto");
  var real = bCrypto.assertNotCompromised;
  var control = _publish(ck.certPem(ck.P256_CONTROL_CA_DER), 3, 1);
  var r;
  bCrypto.assertNotCompromised = function () {
    var e = new Error("crypto.compromisedKey: the value could not be read as a public key, private key or certificate");
    e.code = "crypto/bad-key";
    throw e;
  };
  try { r = _publish(ck.certPem(ck.P256_CONTROL_CA_DER), 3, 1); }
  finally { bCrypto.assertNotCompromised = real; }
  check("mail-deploy unreadable key control: danePublish returns a record when the key can be judged",
        control.ok === true, JSON.stringify(control));
  check("mail-deploy unreadable key: a certificate whose key cannot be judged throws mail-deploy/bad-cert, not mail-deploy/compromised-key",
        r.ok === false && r.code === "mail-deploy/bad-cert", JSON.stringify(r));
}

// TLS_CONTROL_LEAF_DER with its subjectPublicKeyInfo SEQUENCE length written
// in the long form 0x81 0x59 instead of 0x59, and the enclosing lengths
// adjusted. node:crypto parses it and loads its P-256 key.
function _nonMinimalSpkiLeaf() {
  var hex = ck.TLS_CONTROL_LEAF_DER.toString("hex");
  var at = hex.indexOf("3059301306072a8648ce3d0201");
  var buf = Buffer.from(hex.slice(0, at) + "308159" + hex.slice(at + 4), "hex");
  buf.writeUInt16BE(buf.readUInt16BE(2) + 1, 2);
  buf.writeUInt16BE(buf.readUInt16BE(6) + 1, 6);
  return buf;
}

function testSelectorOneHashesTheKeyNodeLoadsFromANonMinimalSpki() {
  var leaf = _nonMinimalSpkiLeaf();
  var nodeSpki = new nodeCrypto.X509Certificate(leaf).publicKey.export({ type: "spki", format: "der" });
  var want = "3 1 1 " + nodeCrypto.createHash("sha256").update(nodeSpki).digest("hex");
  var control = _publish(ck.certPem(ck.TLS_CONTROL_LEAF_DER), 3, 1);
  check("mail-deploy non-minimal SPKI control: danePublish 3 1 1 hashes the same key from the DER-encoded certificate",
        control.ok === true && control.value.record === want, JSON.stringify(control));
  var r = _publish(ck.certPem(leaf), 3, 1);
  check("mail-deploy non-minimal SPKI: danePublish 3 1 1 hashes the key node:crypto reads from the certificate",
        r.ok === true && r.value.record === want, JSON.stringify(r));
}

async function run() {
  testDanePublishRefusesACompromisedKey();
  testDanePublishAcceptsACompositeKeyCertificate();
  testAnUnreadableKeyIsNotReportedAsCompromised();
  testSelectorOneHashesTheKeyNodeLoadsFromANonMinimalSpki();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
