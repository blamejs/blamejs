// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var fs = require("fs");
var os = require("os");
var path = require("path");
var nodeCrypto = require("crypto");

function _mockReq(opts) {
  opts = opts || {};
  return {
    url: opts.url || "/",
    method: opts.method || "GET",
    headers: opts.headers || {},
    socket: opts.socket || { authorized: !!opts.authorized,
      authorizationError: opts.authorizationError || null,
      getPeerCertificate: function () { return opts.peerCert || {}; } },
  };
}
function _mockRes() {
  var captured = { status: 0, body: null, headers: {} };
  return {
    writableEnded: false,
    writeHead: function (s, h) { captured.status = s; if (h) Object.assign(captured.headers, h); },
    end: function (b) { captured.body = b; this.writableEnded = true; },
    _captured: captured,
  };
}

// A revocationSource (a b.mtlsCa handle) makes the CA's revocation registry —
// including revokeGeneration(), whose superseded-CA CRL a peer cannot verify —
// enforced at the gate by fingerprint, and it fails closed.
async function testRevocationSourceEnforcement() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "mtls-revsrc-"));
  try {
    var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
    await ca.initCA();
    var leaf = await ca.generateClientCert({ cn: "peer-1" });
    var der = new nodeCrypto.X509Certificate(leaf.cert).raw;
    var peer = { raw: der, subject: { CN: "peer-1" } };

    var denied = null;
    var gate = b.middleware.requireMtls({
      audit: false, revocationSource: ca,
      onDeny: function (req, res, info) { denied = info; },
    });
    function _drive() {
      denied = null; var nextCalled = false;
      gate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { nextCalled = true; });
      return nextCalled;
    }

    check("revocationSource: an unrevoked peer cert is admitted", _drive() === true && denied === null);

    // Rotate, then revoke the whole gen-1 cohort — the fingerprint path the CRL can't cover.
    await ca.rotate({ generation: 2 });
    check("revokeGeneration revoked the gen-1 leaf", (await ca.revokeGeneration(2)).revoked === 1);

    var admittedAfter = _drive();
    check("revocationSource: the revoked cert is denied at the gate", admittedAfter === false);
    check("revocationSource: refusal reason is fingerprint-revoked",
          denied && denied.reason === "fingerprint-revoked");

    // Fail-closed: a source that throws refuses rather than admitting.
    var fcDenied = null;
    var fcGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { throw new Error("store down"); } },
      onDeny: function (req, res, info) { fcDenied = info; },
    });
    var fcNext = false;
    fcGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { fcNext = true; });
    check("revocationSource: a throwing source fails closed (denied, next not called)",
          fcNext === false && fcDenied && fcDenied.reason === "revocation-check-failed");

    // A non-conforming revocationSource is rejected at construction.
    var ctorErr = null;
    try { b.middleware.requireMtls({ revocationSource: {} }); } catch (e) { ctorErr = e; }
    check("revocationSource without isRevoked() refused at construction",
          ctorErr && ctorErr.code === "require-mtls/bad-revocation-source");

    // A falsy non-object (false / 0 / "") must NOT be silently coerced to "no
    // source" — invalid security config fails at construction instead.
    var falsyErr = null;
    try { b.middleware.requireMtls({ revocationSource: false }); } catch (e) { falsyErr = e; }
    check("a falsy non-object revocationSource (false) is refused at construction",
          falsyErr && falsyErr.code === "require-mtls/bad-revocation-source");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run() {
  var requireMtls = b.middleware.requireMtls({ audit: false });
  var noPeerRes = _mockRes();
  requireMtls(_mockReq({ authorized: false }), noPeerRes, function () {});
  check("requireMtls refuses unauthorized peer 401", noPeerRes._captured.status === 401);

  await testRevocationSourceEnforcement();

  console.log("OK — requireMtls tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
