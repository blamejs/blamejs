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
  check("b.cose.encrypt0 exposed", typeof b.cose.encrypt0 === "function");
  check("b.cose.decrypt0 exposed", typeof b.cose.decrypt0 === "function");
  check("b.cose.ALGORITHMS exposes COSE alg ids", b.cose.ALGORITHMS["ES256"] === -7 && b.cose.ALGORITHMS["ML-DSA-87"] === -50);
  check("b.cose.AEAD_ALGORITHMS exposes AEAD ids", b.cose.AEAD_ALGORITHMS["ChaCha20-Poly1305"] === 24 && b.cose.AEAD_ALGORITHMS["A256GCM"] === 3);
  check("b.cose.COSE_SIGN1_TAG is 18", b.cose.COSE_SIGN1_TAG === 18);
  check("b.cose.COSE_ENCRYPT0_TAG is 16", b.cose.COSE_ENCRYPT0_TAG === 16);
  check("b.cose.CoseError exposed", typeof b.cose.CoseError === "function");
}

function testEncrypt0() {
  var key = b.crypto.generateBytes(32);
  var enc = b.cose.encrypt0(Buffer.from("secret-payload"), { alg: "ChaCha20-Poly1305", key: key });
  check("encrypt0: tagged COSE_Encrypt0 (tag 16 → 0xd0)", enc[0] === 0xd0);
  var d = b.cose.decrypt0(enc, { key: key, algorithms: ["ChaCha20-Poly1305"] });
  check("encrypt0: round-trips plaintext + alg", d.plaintext.toString() === "secret-payload" && d.alg === "ChaCha20-Poly1305");

  var wrongKey = null;
  try { b.cose.decrypt0(enc, { key: b.crypto.generateBytes(32), algorithms: ["ChaCha20-Poly1305"] }); } catch (e) { wrongKey = e; }
  check("decrypt0: wrong key refused", wrongKey && wrongKey.code === "cose/decrypt-failed");

  var t = Buffer.from(enc); t[t.length - 1] ^= 0xff;
  var tampered = null;
  try { b.cose.decrypt0(t, { key: key, algorithms: ["ChaCha20-Poly1305"] }); } catch (e) { tampered = e; }
  check("decrypt0: tampered ciphertext refused", tampered && tampered.code === "cose/decrypt-failed");

  var notAllowed = null;
  try { b.cose.decrypt0(enc, { key: key, algorithms: ["A256GCM"] }); } catch (e) { notAllowed = e; }
  check("decrypt0: alg not in allowlist refused", notAllowed && notAllowed.code === "cose/alg-not-allowed");

  // A256GCM opt-in round-trip.
  var encG = b.cose.encrypt0(Buffer.from("g"), { alg: "A256GCM", key: key });
  check("encrypt0: A256GCM round-trip", b.cose.decrypt0(encG, { key: key, algorithms: ["A256GCM"] }).plaintext.toString() === "g");

  // external_aad must match.
  var encA = b.cose.encrypt0(Buffer.from("z"), { key: key, externalAad: Buffer.from("ctx-A") });
  var aadMismatch = null;
  try { b.cose.decrypt0(encA, { key: key, algorithms: ["ChaCha20-Poly1305"], externalAad: Buffer.from("ctx-B") }); } catch (e) { aadMismatch = e; }
  check("decrypt0: external_aad mismatch refused", aadMismatch && aadMismatch.code === "cose/decrypt-failed");

  // Key-length + algorithms-required validation.
  var badKey = null;
  try { b.cose.encrypt0(Buffer.from("x"), { alg: "A128GCM", key: key }); } catch (e) { badKey = e; }   // 32-byte key for A128GCM (needs 16)
  check("encrypt0: wrong key length refused", badKey && badKey.code === "cose/bad-key");
  var noAlgs = null;
  try { b.cose.decrypt0(enc, { key: key }); } catch (e) { noAlgs = e; }
  check("decrypt0: missing algorithms refused", noAlgs && noAlgs.code === "cose/algorithms-required");
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
  var protBstr = b.cbor.encode(new Map([[1, -7]]));
  var detached = b.cbor.encode(new b.cbor.Tag(18, [protBstr, new Map(), null, Buffer.from([0, 0])]));
  var det = null;
  try { await b.cose.verify(detached, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { det = e; }
  check("verify: detached payload refused (v1 attached-only)", det && det.code === "cose/detached-unsupported");

  // Codex P2 on PR #184 — a non-byte payload (text string here) must
  // be refused, not returned as a non-Buffer.
  var textPayload = b.cbor.encode(new b.cbor.Tag(18, [protBstr, new Map(), "not-bytes", Buffer.from([0, 0])]));
  var np = null;
  try { await b.cose.verify(textPayload, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { np = e; }
  check("verify: non-byte payload refused", np && np.code === "cose/malformed");

  // Codex P2 on PR #184 — a non-map unprotected header must be refused,
  // not silently coerced to empty.
  var badUnprot = b.cbor.encode(new b.cbor.Tag(18, [protBstr, ["array-not-map"], Buffer.from("p"), Buffer.from([0, 0])]));
  var bu = null;
  try { await b.cose.verify(badUnprot, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { bu = e; }
  check("verify: non-map unprotected header refused", bu && bu.code === "cose/malformed");
}

async function run() {
  testSurface();
  testEncrypt0();
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
