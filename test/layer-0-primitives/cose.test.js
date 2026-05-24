"use strict";
/**
 * Layer 0 — b.cose COSE_Sign1 (RFC 9052) sign/verify over the in-tree
 * b.cbor codec. Classical ECDSA / EdDSA (final COSE ids, useable
 * today) + ML-DSA-87 (draft id, PQC-forward). Bounded decode +
 * crit-bypass + alg-allowlist + tamper + external-aad binding.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var EC = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
var ED = nodeCrypto.generateKeyPairSync("ed25519");
var ML = nodeCrypto.generateKeyPairSync("ml-dsa-87");

function testSurface() {
  check("b.cose.sign exposed", typeof b.cose.sign === "function");
  check("b.cose.verify exposed", typeof b.cose.verify === "function");
  check("b.cose.ALGORITHMS exposes COSE alg ids", b.cose.ALGORITHMS["ES256"] === -7 && b.cose.ALGORITHMS["ML-DSA-87"] === -50);
  check("b.cose.COSE_SIGN1_TAG is 18", b.cose.COSE_SIGN1_TAG === 18);
  check("b.cose.CborError-style CoseError exposed", typeof b.cose.CoseError === "function");
}

async function testClassicalUseableToday() {
  var s = await b.cose.sign(Buffer.from("hello"), { alg: "ES256", privateKey: EC.privateKey, kid: "k1" });
  check("ES256: output is a tagged COSE_Sign1 (tag 18 → 0xd2)", s[0] === 0xd2);
  var v = await b.cose.verify(s, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("ES256: round-trips payload + alg", v.payload.toString() === "hello" && v.alg === "ES256");
  check("ES256: kid surfaced in unprotected headers", Buffer.isBuffer(v.unprotectedHeaders.get(4)) && v.unprotectedHeaders.get(4).toString() === "k1");
  check("ES256: alg in protected header", v.protectedHeaders.get(1) === -7);

  var sed = await b.cose.sign("msg", { alg: "EdDSA", privateKey: ED.privateKey });
  check("EdDSA: round-trips (string payload → bstr)", (await b.cose.verify(sed, { algorithms: ["EdDSA"], publicKey: ED.publicKey })).payload.toString() === "msg");
}

async function testPqcForward() {
  var s = await b.cose.sign(Buffer.from("pqc"), { alg: "ML-DSA-87", privateKey: ML.privateKey });
  var v = await b.cose.verify(s, { algorithms: ["ML-DSA-87"], publicKey: ML.publicKey });
  check("ML-DSA-87: round-trips (COSE alg -50, draft)", v.payload.toString() === "pqc" && v.alg === "ML-DSA-87" && v.protectedHeaders.get(1) === -50);
}

async function testTamperAndAllowlist() {
  var s = await b.cose.sign(Buffer.from("data"), { alg: "ES256", privateKey: EC.privateKey });
  var t = Buffer.from(s); t[t.length - 1] ^= 0xff;
  var tampered = null;
  try { await b.cose.verify(t, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { tampered = e; }
  check("verify: tampered signature refused", tampered && tampered.code === "cose/bad-signature");

  var notAllowed = null;
  try { await b.cose.verify(s, { algorithms: ["EdDSA"], publicKey: EC.publicKey }); } catch (e) { notAllowed = e; }
  check("verify: alg not in allowlist refused", notAllowed && notAllowed.code === "cose/alg-not-allowed");

  // external_aad must match what was signed.
  var sa = await b.cose.sign(Buffer.from("d"), { alg: "ES256", privateKey: EC.privateKey, externalAad: Buffer.from("ctx-A") });
  var aadMismatch = null;
  try { await b.cose.verify(sa, { algorithms: ["ES256"], publicKey: EC.publicKey, externalAad: Buffer.from("ctx-B") }); } catch (e) { aadMismatch = e; }
  check("verify: external_aad mismatch refused", aadMismatch && aadMismatch.code === "cose/bad-signature");
  var aadOk = await b.cose.verify(sa, { algorithms: ["ES256"], publicKey: EC.publicKey, externalAad: Buffer.from("ctx-A") });
  check("verify: matching external_aad accepted", aadOk.payload.toString() === "d");
}

async function testCritBypassDefense() {
  // Craft a COSE_Sign1 whose protected header lists an unknown crit
  // label (99). The crit check fires before signature verification —
  // an unknown mandatory label must be refused (RFC 9052 §3.1).
  var protMap = new Map([[1, -7], [2, [99]]]);
  var protectedBstr = b.cbor.encode(protMap);
  var arr = [protectedBstr, new Map(), Buffer.from("p"), Buffer.from([0, 0])];
  var coseBytes = b.cbor.encode(new b.cbor.Tag(18, arr));
  var refused = null;
  try { await b.cose.verify(coseBytes, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { refused = e; }
  check("verify: unknown crit label refused (crit-bypass defense)", refused && refused.code === "cose/crit-unknown");
}

async function testValidation() {
  var bads = [
    [function () { return b.cose.sign(Buffer.from("x"), { alg: "SLH-DSA-SHAKE-256f", privateKey: ML.privateKey }); }, "cose/unsignable-alg"],
    [function () { return b.cose.sign(Buffer.from("x"), { alg: "ES256" }); }, "cose/no-key"],
    [function () { return b.cose.verify(Buffer.from([0x84]), { publicKey: EC.publicKey }); }, "cose/algorithms-required"],
    [function () { return b.cose.verify(Buffer.from([0x84]), { algorithms: ["ES256"] }); }, "cose/no-key"],
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { await bads[i][0](); } catch (e) { caught = e; }
    if (!caught || caught.code !== bads[i][1]) { ok = false; check("validation " + i + " expected " + bads[i][1] + " got " + (caught && caught.code), false); }
  }
  check("sign/verify: malformed args throw the right codes", ok);

  // Detached payload (nil) is explicitly unsupported in v1.
  var detached = b.cbor.encode(new b.cbor.Tag(18, [b.cbor.encode(new Map([[1, -7]])), new Map(), null, Buffer.from([0, 0])]));
  var det = null;
  try { await b.cose.verify(detached, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { det = e; }
  check("verify: detached payload refused (v1 attached-only)", det && det.code === "cose/detached-unsupported");
}

async function run() {
  testSurface();
  await testClassicalUseableToday();
  await testPqcForward();
  await testTamperAndAllowlist();
  await testCritBypassDefense();
  await testValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cose] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
