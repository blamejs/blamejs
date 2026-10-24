// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cert refuses a compromised ACME account key: an operator-supplied
 * acme.accountKey throws cert/compromised-key from b.cert.create, and an
 * "auto" account key read back from storage is refused by b.acme.create with
 * acme/compromised-key when the manager starts. Every refusal is paired with
 * a control key that differs only in its private scalar. A privatePem that
 * carries an ordinary certificate before or after the key is judged by its
 * key.
 */

var fs      = require("node:fs");
var os      = require("node:os");
var path    = require("node:path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var _tmpDirs = [];
function _tmp() {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cert-compromised-"));
  _tmpDirs.push(d);
  return d;
}
function _plainVault() {
  return {
    seal:   function (buf) { return Buffer.from(buf); },
    unseal: function (buf) { return Buffer.from(buf); },
  };
}
function _manager(rootDir, accountKey) {
  return b.cert.create({
    storage: { type: "sealed-disk", rootDir: rootDir, vault: _plainVault() },
    acme:    { directory: "https://acme.invalid/directory", accountKey: accountKey },
    certs:   [{ name: "main", domains: ["example.com"], challenge: {
      type: "http-01", provision: async function () {}, cleanup: async function () {},
    } }],
    ocsp:    { stapling: false },
    audit:   false,
  });
}
function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
async function _acode(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
function _pem(pair) { return pair.privateKey.export({ type: "pkcs8", format: "pem" }); }

function testOperatorAccountKeyRefused() {
  var control = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "cert control"));
  check("cert compromised key control: create accepts a control acme.accountKey { privatePem }",
        _code(function () { _manager(_tmp(), { privatePem: _pem(control) }); }) === "NO-THROW");
  check("cert compromised key control: create accepts a control acme.accountKey KeyObject",
        _code(function () { _manager(_tmp(), control.privateKey); }) === "NO-THROW");

  var bad = ck.ecKeyPair("prime256v1", 1n);
  check("cert compromised key: create refuses an acme.accountKey { privatePem } whose private scalar is 1",
        _code(function () { _manager(_tmp(), { privatePem: _pem(bad) }); }) === "cert/compromised-key");
  check("cert compromised key: create refuses an acme.accountKey KeyObject whose private scalar is 1",
        _code(function () { _manager(_tmp(), bad.privateKey); }) === "cert/compromised-key");
  check("cert compromised key: create refuses an acme.accountKey { privateKey } whose private scalar is 1",
        _code(function () { _manager(_tmp(), { privateKey: bad.privateKey }); }) === "cert/compromised-key");
}

// A key PEM and an ordinary certificate PEM in one privatePem string, in
// either order, or a key PEM followed by a certificate block that cannot be
// parsed. node:crypto reads the key block, so the key decides.
var UNREADABLE_TAIL = "-----BEGIN TRUSTED CERTIFICATE-----\n/w==\n-----END TRUSTED CERTIFICATE-----\n";

function testMixedKeyAndCertificatePem() {
  var certPem = ck.certPem(ck.P256_CONTROL_CA_DER);
  var control = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "cert control"));
  var bad = ck.ecKeyPair("prime256v1", 1n);
  [["key-first", "an ordinary certificate", function (k) { return k + certPem; }],
   ["certificate-first", "an ordinary certificate", function (k) { return certPem + k; }],
   ["key-first", "a certificate block that cannot be parsed",
    function (k) { return k + UNREADABLE_TAIL; }]].forEach(function (form) {
    check("cert mixed PEM control (" + form[0] + "): create accepts a control privatePem with " + form[1],
          _code(function () { _manager(_tmp(), { privatePem: form[2](_pem(control)) }); }) === "NO-THROW");
    check("cert mixed PEM (" + form[0] + "): create refuses a scalar-1 privatePem with " + form[1],
          _code(function () { _manager(_tmp(), { privatePem: form[2](_pem(bad)) }); }) === "cert/compromised-key");
  });
}

async function testStoredAutoAccountKeyRefused() {
  var bad = ck.ecKeyPair("prime256v1", 1n);
  var root = _tmp();
  var jwk = bad.publicKey.export({ format: "jwk" });
  jwk.privatePem = _pem(bad);
  jwk.publicPem = bad.publicKey.export({ type: "spki", format: "pem" });
  fs.mkdirSync(path.join(root, "account"), { recursive: true });
  fs.writeFileSync(path.join(root, "account", "jwk.json.sealed"), JSON.stringify(jwk));
  var mgr = _manager(root, "auto");
  try {
    check("cert compromised key: start refuses a stored auto account key whose private scalar is 1",
          (await _acode(function () { return mgr.start(); })) === "acme/compromised-key");
  } finally { await mgr.stop(); }
}

async function run() {
  try {
    testOperatorAccountKeyRefused();
    testMixedKeyAndCertificatePem();
    await testStoredAutoAccountKeyRefused();
  } finally {
    _tmpDirs.forEach(function (d) { fs.rmSync(d, { recursive: true, force: true }); });
  }
}

module.exports = {
  run:                               run,
  testOperatorAccountKeyRefused:     testOperatorAccountKeyRefused,
  testMixedKeyAndCertificatePem:     testMixedKeyAndCertificatePem,
  testStoredAutoAccountKeyRefused:   testStoredAutoAccountKeyRefused,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
