// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.crypto.pgp.experimental — PQC PGP encrypt/decrypt + WKD URL
 * computation. Framework-private envelope (ML-KEM-1024 +
 * ChaCha20-Poly1305) shipped under `experimental` namespace because
 * RFC 9580bis PKESK ML-KEM codepoints haven't IANA-registered yet.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var pq = require("../../lib/pqc-software");

function testEncryptDecryptRoundtrip() {
  var kp = pq.ml_kem_1024.keygen();
  var msg = "top secret";
  var rid = Buffer.from([0x42, 0x43]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: msg,
    recipients: [{ recipientId: rid, publicKey: kp.publicKey }],
  });
  check("encrypt returns armored", typeof enc.armored === "string" && enc.armored.indexOf("BEGIN PGP MESSAGE") !== -1);
  check("encrypt returns envelope Buffer", Buffer.isBuffer(enc.envelope));
  var dec = b.mail.crypto.pgp.experimental.decrypt({
    armored: enc.armored, recipientId: rid, secretKey: kp.secretKey,
  });
  check("decrypt recovers plaintext", dec.plaintext.toString("utf8") === msg);
}

function testEncryptMultiRecipient() {
  var kp1 = pq.ml_kem_1024.keygen();
  var kp2 = pq.ml_kem_1024.keygen();
  var rid1 = Buffer.from([0x01]);
  var rid2 = Buffer.from([0x02]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: "to-both",
    recipients: [
      { recipientId: rid1, publicKey: kp1.publicKey },
      { recipientId: rid2, publicKey: kp2.publicKey },
    ],
  });
  var dec1 = b.mail.crypto.pgp.experimental.decrypt({
    envelope: enc.envelope, recipientId: rid1, secretKey: kp1.secretKey,
  });
  var dec2 = b.mail.crypto.pgp.experimental.decrypt({
    envelope: enc.envelope, recipientId: rid2, secretKey: kp2.secretKey,
  });
  check("multi-recipient: recipient 1 decrypts", dec1.plaintext.toString("utf8") === "to-both");
  check("multi-recipient: recipient 2 decrypts", dec2.plaintext.toString("utf8") === "to-both");
}

function testDecryptRefusesWrongRecipient() {
  var kp = pq.ml_kem_1024.keygen();
  var kp2 = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0xaa]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: "x", recipients: [{ recipientId: rid, publicKey: kp.publicKey }],
  });
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.decrypt({
      envelope: enc.envelope, recipientId: rid, secretKey: kp2.secretKey,
    });
  } catch (e) { threw = e.code; }
  check("wrong secret key refused at unwrap",
    threw === "mail-crypto/pgp/unwrap-failed" || threw === "mail-crypto/pgp/decap-failed");
}

function testDecryptRefusesNoMatchingRid() {
  var kp = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0x01]);
  var otherRid = Buffer.from([0x99]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: "x", recipients: [{ recipientId: rid, publicKey: kp.publicKey }],
  });
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.decrypt({
      envelope: enc.envelope, recipientId: otherRid, secretKey: kp.secretKey,
    });
  } catch (e) { threw = e.code; }
  check("non-matching recipientId refused", threw === "mail-crypto/pgp/no-matching-recipient");
}

function testDecryptRefusesBadMagic() {
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.decrypt({
      envelope: Buffer.from("not a real envelope at all"),
      recipientId: Buffer.from([0]), secretKey: new Uint8Array(3168),
    });
  } catch (e) { threw = e.code; }
  check("bad-magic envelope refused", threw === "mail-crypto/pgp/bad-magic");
}

function testEncryptRefusesNoRecipients() {
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.encrypt({ message: "x", recipients: [] });
  } catch (e) { threw = e.code; }
  check("empty recipients refused", threw === "mail-crypto/pgp/no-recipients");
}

function testWkdComputeUrlShape() {
  var urls = b.mail.crypto.pgp.experimental.wkd.computeUrl("Alice@Example.COM");
  check("WKD direct URL uses lowercased domain",
    urls.direct.indexOf("https://example.com/.well-known/openpgpkey/hu/") === 0);
  check("WKD advanced URL uses openpgpkey.<domain>",
    urls.advanced.indexOf("https://openpgpkey.example.com/.well-known/openpgpkey/example.com/hu/") === 0);
  check("WKD localLower lowercased",  urls.localLower === "alice");
  check("WKD hashed is zbase32",      /^[ybndrfg8ejkmcpqxot1uwisza345h769]+$/.test(urls.hashed));
  check("WKD includes original localpart as l= query",
    urls.direct.indexOf("?l=Alice") !== -1);
}

function testWkdAdvancedHostOverride() {
  var urls = b.mail.crypto.pgp.experimental.wkd.computeUrl("bob@example.com",
    { advancedHost: "keys.example.com" });
  check("WKD operator-supplied advancedHost honored",
    urls.advanced.indexOf("https://keys.example.com/") === 0);
}

function testWkdRefusesBadEmail() {
  var bad = ["no-at-sign", "@nolocal.com", "trailing@", ""];
  for (var i = 0; i < bad.length; i += 1) {
    var threw = null;
    try { b.mail.crypto.pgp.experimental.wkd.computeUrl(bad[i]); }
    catch (e) { threw = e.code; }
    check("WKD refuses '" + bad[i] + "'", threw === "mail-crypto/pgp/bad-email");
  }
}

// ---- b.mail.crypto.pgp.experimental.wkd.fetch ----
//
// fetch() is driven entirely through the operator-supplied
// `httpsGet(url) => Promise<{ status, body }>` — the framework never
// couples to a specific HTTP client, so these tests inject an in-memory
// stub that records the URLs requested and returns canned responses.
// NO real network is touched.

// Build a recording httpsGet stub: `responses` maps a URL → its
// { status, body } reply; any URL absent from the map answers 404.
function _wkdStub(responses, calls) {
  return function (url) {
    calls.push(url);
    var r = responses[url];
    return Promise.resolve(r || { status: 404, body: Buffer.alloc(0) });
  };
}

async function testWkdFetchDirectHit() {
  var email = "alice@example.com";
  var urls  = b.mail.crypto.pgp.experimental.wkd.computeUrl(email);
  var keyBytes = Buffer.from([0x99, 0x01, 0x02, 0x03, 0x04]);
  var calls = [];
  var responses = {};
  responses[urls.direct] = { status: 200, body: keyBytes };

  var out = await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
    httpsGet: _wkdStub(responses, calls),
  });
  check("wkd.fetch direct: source is 'direct'",       out.source === "direct");
  check("wkd.fetch direct: url is the direct URL",     out.url === urls.direct);
  check("wkd.fetch direct: keyBytes are the reply body",
    Buffer.isBuffer(out.keyBytes) && Buffer.compare(out.keyBytes, keyBytes) === 0);
  check("wkd.fetch direct: only the direct URL was requested",
    calls.length === 1 && calls[0] === urls.direct);
}

async function testWkdFetchAdvancedFallback() {
  var email = "bob@example.com";
  var urls  = b.mail.crypto.pgp.experimental.wkd.computeUrl(email);
  var keyBytes = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  var calls = [];
  var responses = {};
  // direct absent (→ 404); advanced serves the key.
  responses[urls.advanced] = { status: 200, body: keyBytes };

  var out = await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
    httpsGet: _wkdStub(responses, calls),
  });
  check("wkd.fetch fallback: source is 'advanced'",   out.source === "advanced");
  check("wkd.fetch fallback: url is the advanced URL", out.url === urls.advanced);
  check("wkd.fetch fallback: keyBytes are the reply body",
    Buffer.compare(out.keyBytes, keyBytes) === 0);
  check("wkd.fetch fallback: tried direct FIRST, then advanced",
    calls.length === 2 && calls[0] === urls.direct && calls[1] === urls.advanced);
}

async function testWkdFetchBothFail() {
  var email = "nokey@example.com";
  var calls = [];
  var threw = null;
  try {
    // Empty response map → both URLs 404.
    await b.mail.crypto.pgp.experimental.wkd.fetch(email, { httpsGet: _wkdStub({}, calls) });
  } catch (e) { threw = e; }
  check("wkd.fetch both-fail: throws wkd-not-found",
    threw && threw.code === "mail-crypto/pgp/wkd-not-found");
  check("wkd.fetch both-fail: is a MailCryptoError (facade classifier)",
    threw && b.mail.crypto.isMailCryptoError(threw) === true);
  check("wkd.fetch both-fail: both direct + advanced were attempted",
    calls.length === 2);
}

async function testWkdFetchRequiresHttpsGet() {
  var threw = null;
  try { await b.mail.crypto.pgp.experimental.wkd.fetch("alice@example.com", {}); }
  catch (e) { threw = e; }
  check("wkd.fetch: missing httpsGet throws no-https-get",
    threw && threw.code === "mail-crypto/pgp/no-https-get");

  var threwOpts = null;
  try { await b.mail.crypto.pgp.experimental.wkd.fetch("alice@example.com", null); }
  catch (e) { threwOpts = e; }
  check("wkd.fetch: null opts throws bad-opts",
    threwOpts && threwOpts.code === "mail-crypto/pgp/bad-opts");
}

async function testWkdFetchEnforcesMaxKeyBytes() {
  var email = "big@example.com";
  var urls  = b.mail.crypto.pgp.experimental.wkd.computeUrl(email);
  var calls = [];
  var responses = {};
  responses[urls.direct] = { status: 200, body: Buffer.alloc(100) };   // 100-byte reply

  var threwLarge = null;
  try {
    await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
      httpsGet: _wkdStub(responses, calls), maxKeyBytes: 10,
    });
  } catch (e) { threwLarge = e; }
  check("wkd.fetch: reply over maxKeyBytes throws wkd-too-large",
    threwLarge && threwLarge.code === "mail-crypto/pgp/wkd-too-large");

  var threwBad = null;
  try {
    await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
      httpsGet: _wkdStub(responses, []), maxKeyBytes: -1,
    });
  } catch (e) { threwBad = e; }
  check("wkd.fetch: negative maxKeyBytes throws bad-max-key-bytes",
    threwBad && threwBad.code === "mail-crypto/pgp/bad-max-key-bytes");
}

async function run() {
  testEncryptDecryptRoundtrip();
  testEncryptMultiRecipient();
  testDecryptRefusesWrongRecipient();
  testDecryptRefusesNoMatchingRid();
  testDecryptRefusesBadMagic();
  testEncryptRefusesNoRecipients();
  testWkdComputeUrlShape();
  testWkdAdvancedHostOverride();
  testWkdRefusesBadEmail();
  await testWkdFetchDirectHit();
  await testWkdFetchAdvancedFallback();
  await testWkdFetchBothFail();
  await testWkdFetchRequiresHttpsGet();
  await testWkdFetchEnforcesMaxKeyBytes();
}

if (require.main === module) {
  run().then(
    function () { console.log("[mail-crypto-pgp-experimental] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
module.exports = { run: run };
