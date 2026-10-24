// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.selfUpdate.verify and b.selfUpdate.standaloneVerifier.verify refuse a
 * release signed under a compromised P-384 key: the standalone verifier
 * throws an error whose kind is "compromised-key", and b.selfUpdate.verify
 * throws selfupdate/compromised-key. Every refusal is paired with a control
 * key that differs only in its private scalar.
 */

var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var ck         = require("../helpers/compromised-keys");

var N384 = ck.CURVES.secp384r1[2];

function _signedRelease(dir, tag, pair) {
  var asset = path.join(dir, tag + ".bin");
  var sig = path.join(dir, tag + ".sig");
  var bytes = Buffer.from("#!/bin/sh\necho release " + tag + "\n", "utf8");
  fs.writeFileSync(asset, bytes);
  var signer = nodeCrypto.createSign("sha3-512");
  signer.update(bytes);
  fs.writeFileSync(sig, signer.sign({ key: pair.privateKey, dsaEncoding: "der" }));
  return { asset: asset, sig: sig, pubkeyPem: pair.publicKey.export({ type: "spki", format: "pem" }) };
}
function _kind(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.kind || e.code || e.message; }
}
async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

async function testCompromisedReleaseKeyRefused() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-selfupdate-compromised-"));
  try {
    var control = _signedRelease(dir, "control",
      ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "self-update control")));
    var sv = b.selfUpdate.standaloneVerifier.verify(control.asset, control.sig, control.pubkeyPem);
    check("self-update compromised key control: the standalone verifier accepts a control P-384 release",
          sv.ok === true && sv.alg === "ecdsa-p384");
    var v = await b.selfUpdate.verify({
      assetPath: control.asset, signaturePath: control.sig, pubkeyPem: control.pubkeyPem,
    });
    check("self-update compromised key control: b.selfUpdate.verify accepts a control P-384 release",
          v.verified === true);

    [["1", 1n], ["n - 1", N384 - 1n], ["255", 255n]].forEach(function (d) {
      var bad = _signedRelease(dir, "bad-" + d[1].toString(16).slice(-4),
        ck.ecKeyPair("secp384r1", d[1]));
      check("self-update compromised key: the standalone verifier refuses a P-384 release key with scalar " + d[0],
            _kind(function () {
              b.selfUpdate.standaloneVerifier.verify(bad.asset, bad.sig, bad.pubkeyPem);
            }) === "compromised-key");
    });

    var one = _signedRelease(dir, "bad-one", ck.ecKeyPair("secp384r1", 1n));
    check("self-update compromised key: b.selfUpdate.verify refuses a P-384 release key whose scalar is 1",
          (await _code(function () {
            return b.selfUpdate.verify({ assetPath: one.asset, signaturePath: one.sig, pubkeyPem: one.pubkeyPem });
          })) === "selfupdate/compromised-key");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// b.selfUpdate.verify refuses a compromised pubkeyPem before it opens the
// asset, including a pubkeyPem whose key block is followed by a certificate
// block that cannot be parsed (node:crypto still reads the key from it).
var UNREADABLE_TAIL = "-----BEGIN TRUSTED CERTIFICATE-----\n/w==\n-----END TRUSTED CERTIFICATE-----\n";

async function testCompromisedKeyRefusedBeforeTheAssetIsRead() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-selfupdate-order-"));
  try {
    var missing = { assetPath: path.join(dir, "absent.bin"), signaturePath: path.join(dir, "absent.sig") };
    var control = ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "self-update order control"));
    var bad = ck.ecKeyPair("secp384r1", 1n);
    var controlPem = control.publicKey.export({ type: "spki", format: "pem" });
    var badPem = bad.publicKey.export({ type: "spki", format: "pem" });
    var forms = [["", "a P-384 public key"],
                 [UNREADABLE_TAIL, "a P-384 public key followed by a certificate block that cannot be parsed"]];
    for (var i = 0; i < forms.length; i += 1) {
      var tail = forms[i][0];
      var label = forms[i][1];
      check("self-update order control: b.selfUpdate.verify reports the missing asset for " + label +
            " with a control scalar",
            (await _code(function () {
              return b.selfUpdate.verify({ assetPath: missing.assetPath, signaturePath: missing.signaturePath,
                pubkeyPem: controlPem + tail });
            })) === "selfupdate/read-failed");
      check("self-update order: b.selfUpdate.verify refuses " + label + " with scalar 1 before reading the asset",
            (await _code(function () {
              return b.selfUpdate.verify({ assetPath: missing.assetPath, signaturePath: missing.signaturePath,
                pubkeyPem: badPem + tail });
            })) === "selfupdate/compromised-key");
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run() {
  await testCompromisedReleaseKeyRefused();
  await testCompromisedKeyRefusedBeforeTheAssetIsRead();
}

module.exports = {
  run:                                            run,
  testCompromisedReleaseKeyRefused:               testCompromisedReleaseKeyRefused,
  testCompromisedKeyRefusedBeforeTheAssetIsRead:  testCompromisedKeyRefusedBeforeTheAssetIsRead,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
