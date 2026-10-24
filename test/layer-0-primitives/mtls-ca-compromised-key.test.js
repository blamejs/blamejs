// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa refuses a CA whose key is compromised, wherever the CA enters:
 * commit() with the bundled engine or a custom one, a CA already on disk
 * (initCA, generateClientCert, generateCrl), a CA a custom engine generates
 * on first use or on rotate(), and the trust bundle (current and retained
 * root). Every refusal is paired with a control CA that differs only in its
 * private scalar.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs         = require("fs");
var os         = require("os");
var path       = require("path");
var nodeCrypto = require("node:crypto");
var engine     = require("../../lib/mtls-engine-default");
var ck         = require("../helpers/compromised-keys");

var COMPROMISED = ck.p384CompromisedCa();
var CONTROL     = ck.p384ControlCa();

var _tmpDirs = [];
function _mkTmp() {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-compromised-"));
  _tmpDirs.push(d);
  return d;
}
function _newCa(extra) {
  return b.mtlsCa.create(Object.assign({ dataDir: _mkTmp(), caKeySealedMode: "disabled" }, extra || {}));
}
function _customEngine(generateCa) {
  return {
    generateCa:     generateCa || engine.generateCa,
    signClientCert: engine.signClientCert,
    generateCrl:    engine.generateCrl,
  };
}
async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
function _writeOnDisk(ca, material) {
  fs.writeFileSync(ca.paths.caCert, material.caCertPem);
  fs.writeFileSync(ca.paths.caKey, material.caKeyPem);
}

function testFixturesCarryTheKeysTheyClaim() {
  [["compromised", COMPROMISED], ["control", CONTROL]].forEach(function (pair) {
    var certSpki = new nodeCrypto.X509Certificate(pair[1].caCertPem).publicKey
      .export({ type: "spki", format: "der" });
    var keySpki = nodeCrypto.createPublicKey(pair[1].caKeyPem).export({ type: "spki", format: "der" });
    check("mtls compromised key: the " + pair[0] + " fixture certificate carries the derived key",
          Buffer.from(certSpki).equals(Buffer.from(keySpki)));
  });
}

async function testCommitRefusesCompromisedCa() {
  var control = _newCa();
  check("mtls compromised key control: commit of the control CA succeeds",
        (await _code(function () { return control.commit(CONTROL); })) === "NO-THROW");
  check("mtls compromised key control: the committed control CA issues a client certificate",
        typeof (await control.generateClientCert({ cn: "control" })).cert === "string");

  var ca = _newCa();
  check("mtls compromised key: commit refuses a CA whose private key is 1",
        (await _code(function () { return ca.commit(COMPROMISED); })) === "mtls-ca/compromised-key");
  check("mtls compromised key: the refused commit leaves no CA on disk", ca.exists() === false);

  var customControl = _newCa({ engine: _customEngine() });
  check("mtls compromised key control: a custom-engine commit of the control CA succeeds",
        (await _code(function () { return customControl.commit(CONTROL); })) === "NO-THROW");
  var custom = _newCa({ engine: _customEngine() });
  check("mtls compromised key: a custom-engine commit refuses the compromised CA",
        (await _code(function () { return custom.commit(COMPROMISED); })) === "mtls-ca/compromised-key");
  check("mtls compromised key: the refused custom-engine commit leaves no CA on disk", custom.exists() === false);
}

async function testCaOnDiskIsRefused() {
  var control = _newCa();
  _writeOnDisk(control, CONTROL);
  check("mtls compromised key control: initCA adopts the control CA on disk",
        (await _code(function () { return control.initCA(); })) === "NO-THROW");
  check("mtls compromised key control: generateCrl signs under the control CA on disk",
        (await _code(function () { return control.generateCrl(); })) === "NO-THROW");
  var bundle = await control.loadTrustBundle();
  check("mtls compromised key control: loadTrustBundle serves the control CA on disk",
        bundle.length === 1 && bundle[0] === CONTROL.caCertPem);

  var ca = _newCa();
  _writeOnDisk(ca, COMPROMISED);
  check("mtls compromised key: initCA refuses a compromised CA on disk",
        (await _code(function () { return ca.initCA(); })) === "mtls-ca/compromised-key");
  check("mtls compromised key: generateClientCert refuses under a compromised CA on disk",
        (await _code(function () { return ca.generateClientCert({ cn: "x" }); })) === "mtls-ca/compromised-key");
  check("mtls compromised key: generateCrl refuses to sign under a compromised CA on disk",
        (await _code(function () { return ca.generateCrl(); })) === "mtls-ca/compromised-key");
  check("mtls compromised key: loadTrustBundle refuses to serve a compromised current root",
        (await _code(function () { return ca.loadTrustBundle(); })) === "mtls-ca/compromised-key");

  var custom = _newCa({ engine: _customEngine() });
  _writeOnDisk(custom, COMPROMISED);
  check("mtls compromised key: a custom-engine initCA refuses a compromised CA on disk",
        (await _code(function () { return custom.initCA(); })) === "mtls-ca/compromised-key");
}

async function testRetainedRootIsRefused() {
  var control = _newCa();
  await control.commit(CONTROL);
  fs.writeFileSync(control.paths.caCertPrev, ck.certPem(ck.P384_CONTROL_CA_DER));
  check("mtls compromised key control: loadTrustBundle serves a retained control root",
        (await _code(function () { return control.loadTrustBundle(); })) === "NO-THROW");

  var ca = _newCa();
  await ca.commit(CONTROL);
  fs.writeFileSync(ca.paths.caCertPrev, COMPROMISED.caCertPem);
  check("mtls compromised key: loadTrustBundle refuses a compromised retained root",
        (await _code(function () { return ca.loadTrustBundle(); })) === "mtls-ca/compromised-key");
}

async function testGeneratedCaIsRefused() {
  var control = _newCa({ engine: _customEngine(async function () { return CONTROL; }) });
  check("mtls compromised key control: initCA commits a control CA a custom engine generates",
        (await _code(function () { return control.initCA(); })) === "NO-THROW" && control.exists() === true);

  var ca = _newCa({ engine: _customEngine(async function () { return COMPROMISED; }) });
  check("mtls compromised key: initCA refuses a compromised CA a custom engine generates",
        (await _code(function () { return ca.initCA(); })) === "mtls-ca/compromised-key");
  check("mtls compromised key: the refused generated CA is not written to disk", ca.exists() === false);

  var calls = 0;
  var rotating = _newCa({ engine: _customEngine(async function () {
    calls += 1;
    return calls === 1 ? CONTROL : COMPROMISED;
  }) });
  await rotating.initCA();
  check("mtls compromised key: rotate refuses a compromised CA the engine generates",
        (await _code(function () { return rotating.rotate({ generation: 2 }); })) === "mtls-ca/compromised-key");
  check("mtls compromised key: the refused rotation leaves the control CA in place",
        fs.readFileSync(rotating.paths.caCert, "utf8") === CONTROL.caCertPem);
}

async function run() {
  try {
    testFixturesCarryTheKeysTheyClaim();
    await testCommitRefusesCompromisedCa();
    await testCaOnDiskIsRefused();
    await testRetainedRootIsRefused();
    await testGeneratedCaIsRefused();
  } finally {
    _tmpDirs.forEach(function (d) { fs.rmSync(d, { recursive: true, force: true }); });
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
