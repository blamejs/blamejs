// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa non-breaking CA algorithm-migration primitives (issue #532):
 *   - status().algorithm / .keyType (from the stored cert's public key)
 *   - rotate({ generation, algorithm }) -> { caCertPem, previousCaCertPem }
 *   - commit({ retainPrevious }) + loadTrustBundle() + dropRetained()
 *   - engine + CA-handle canVerifyInTls() loopback probe
 *   - revokeGeneration(n) over the issuance ledger
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs       = require("fs");
var os       = require("os");
var path     = require("path");
var engine   = require("../../lib/mtls-engine-default");

var _tmpDirs = [];
function _mkTmp() { var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls532-")); _tmpDirs.push(d); return d; }
function _newCa(extra) { return b.mtlsCa.create(Object.assign({ dataDir: _mkTmp(), caKeySealedMode: "disabled" }, extra || {})); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

async function testStatusAlgorithmKeyType() {
  var ca = _newCa();
  var before = ca.status();
  check("status: no CA -> algorithm/keyType null",
        before.exists === false && before.algorithm === null && before.keyType === null);
  await ca.initCA();   // default ML-DSA-87
  var s = ca.status();
  check("status: default CA reports ML-DSA-87 / ml-dsa-87",
        s.algorithm === "ML-DSA-87" && s.keyType === "ml-dsa-87");
  var caEc = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await caEc.initCA();
  var se = caEc.status();
  check("status: classical pin reports ECDSA-P384-SHA384 / ec",
        se.algorithm === "ECDSA-P384-SHA384" && se.keyType === "ec");
}

async function testRotate() {
  var ca = _newCa();
  await ca.initCA();
  var prevCert = ca.loadCert().toString("utf8");
  check("rotate: starts on ML-DSA-87 gen 1",
        ca.status().algorithm === "ML-DSA-87" && ca.status().generation === 1);
  var rot = await ca.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });
  check("rotate: returns caCertPem + the exact previousCaCertPem",
        typeof rot.caCertPem === "string" && rot.previousCaCertPem === prevCert);
  check("rotate: reports new generation + algorithm",
        rot.generation === 2 && rot.algorithm === "ECDSA-P384-SHA384");
  var s2 = ca.status();
  check("rotate: stored CA is now gen 2 ECDSA (mismatch-free flip)",
        s2.generation === 2 && s2.algorithm === "ECDSA-P384-SHA384");
  var leaf = await ca.generateClientCert({ cn: "post-rotate" });
  check("rotate: a leaf issues cleanly under the rotated CA", typeof leaf.cert === "string");

  var caB = _newCa(); await caB.initCA(); await caB.rotate({ generation: 5 });
  check("rotate: backward/equal generation refused",
        (await code2(function () { return caB.rotate({ generation: 3 }); })) === "mtls-ca/bad-generation");

  var caC = _newCa(); await caC.initCA();
  var rc = await caC.rotate({ algorithm: "ECDSA-P384-SHA384" });
  check("rotate: default generation is current + 1", rc.generation === 2);
}

async function testTrustBundleRetention() {
  var ca = _newCa();
  await ca.initCA();
  check("loadTrustBundle: one cert before rotation", ca.loadTrustBundle().length === 1);
  var prevCert = ca.loadCert().toString("utf8");
  await ca.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });   // retainPrevious defaults on
  var bundle = ca.loadTrustBundle();
  check("loadTrustBundle: current + retained after rotate",
        bundle.length === 2 && bundle.indexOf(prevCert) !== -1);
  var d = ca.dropRetained();
  check("dropRetained: ends the window", d.dropped === true && ca.loadTrustBundle().length === 1);
  check("dropRetained: idempotent when nothing retained", ca.dropRetained().dropped === false);

  var ca2 = _newCa(); await ca2.initCA();
  await ca2.rotate({ generation: 2, retainPrevious: false });
  check("rotate({retainPrevious:false}): no retained CA", ca2.loadTrustBundle().length === 1);
}

async function testCanVerifyInTls() {
  check("engine.canVerifyInTls: ECDSA-P384-SHA384 -> true",
        (await engine.canVerifyInTls("ECDSA-P384-SHA384")) === true);
  check("engine.canVerifyInTls: unknown label -> false (fails closed)",
        (await engine.canVerifyInTls("NOT-A-REAL-ALGORITHM")) === false);
  var ca = _newCa();
  await ca.initCA();   // default ML-DSA-87 — the supported Node LTS verifies it
  check("ca.canVerifyInTls: the CA's own algorithm verifies in loopback mTLS",
        (await ca.canVerifyInTls()) === true);
}

async function testRevokeGeneration() {
  var ca = _newCa();
  await ca.initCA();
  var g1a = await ca.generateClientCert({ cn: "gen1-a" });
  var g1b = await ca.generateClientCert({ cn: "gen1-b" });
  await ca.rotate({ generation: 2 });
  var g2 = await ca.generateClientCert({ cn: "gen2-a" });
  var res = ca.revokeGeneration(2);
  check("revokeGeneration(2): revokes both gen-1 leaves", res.revoked === 2);
  check("revokeGeneration: gen-1 leaves are revoked",
        ca.isRevoked(g1a.fingerprint) && ca.isRevoked(g1b.fingerprint));
  check("revokeGeneration: the gen-2 leaf is NOT revoked", ca.isRevoked(g2.fingerprint) === false);
  check("revokeGeneration: idempotent (re-run revokes 0 new)", ca.revokeGeneration(2).revoked === 0);
  check("revokeGeneration: n=0 refused", code(function () { ca.revokeGeneration(0); }) === "mtls-ca/bad-generation");
  check("revokeGeneration: non-integer n refused", code(function () { ca.revokeGeneration(1.5); }) === "mtls-ca/bad-generation");
}

// async variant of code() for rejected promises.
async function code2(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code; } }

async function run() {
  try {
    await testStatusAlgorithmKeyType();
    await testRotate();
    await testTrustBundleRetention();
    await testCanVerifyInTls();
    await testRevokeGeneration();
  } finally {
    for (var i = 0; i < _tmpDirs.length; i++) {
      try { fs.rmSync(_tmpDirs[i], { recursive: true, force: true }); } catch (_e) { /* best-effort cleanup */ }
    }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
