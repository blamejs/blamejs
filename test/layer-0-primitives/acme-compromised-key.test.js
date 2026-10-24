// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.acme refuses a compromised key with acme/compromised-key wherever one
 * enters: the account key given to create() in each accepted form, the new
 * key given to accountKeyRollover() (before anything is sent to the CA), the
 * leaf key given to buildCsr(), and the subject key of a CSR passed to
 * finalize() (before anything is sent to the CA). Every refusal is paired
 * with a control key that differs only in its private scalar. finalize()
 * refuses a CSR whose subject key it cannot read with acme/bad-csr, and sends
 * nothing to the CA.
 */

var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var asn1       = require("../../lib/asn1-der");
var httpClient = require("../../lib/http-client");
var ck         = require("../helpers/compromised-keys");

var CA = "https://ca.example.test";

function _control(curve) { return ck.ecKeyPair(curve, ck.labelScalar(curve, "acme control")); }
function _bad(curve) { return ck.ecKeyPair(curve, 1n); }
function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
async function _acode(promise) {
  try { await promise; return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
function _acme(accountKey) {
  return b.acme.create({ directory: CA + "/directory", accountKey: accountKey });
}
function _resp(status, headers, body) {
  return { statusCode: status, headers: headers || {}, body: typeof body === "string" ? body : JSON.stringify(body) };
}
function _dir() {
  return {
    newNonce: CA + "/new-nonce", newAccount: CA + "/new-account", newOrder: CA + "/new-order",
    keyChange: CA + "/key-change", revokeCert: CA + "/revoke-cert",
  };
}
// Installs a fake httpClient.request that answers as an ACME CA and records
// every POST path, runs fn, and restores the real request.
async function _withCa(fn) {
  var posts = [];
  var n = 0;
  var orig = httpClient.request;
  httpClient.request = function (req) {
    n += 1;
    var h = { "replay-nonce": "nonce-" + n };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _dir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST") {
      posts.push(req.url.slice(CA.length));
      if (req.url.indexOf("/new-account") !== -1) {
        h.location = CA + "/acct/1";
        return Promise.resolve(_resp(201, h, { status: "valid" }));
      }
      if (req.url.indexOf("/key-change") !== -1) return Promise.resolve(_resp(200, h, {}));
      if (req.url.indexOf("/finalize") !== -1) return Promise.resolve(_resp(200, h, { status: "processing" }));
    }
    return Promise.resolve(_resp(404, h, ""));
  };
  try { return await fn(posts); }
  finally { httpClient.request = orig; }
}

// A PKCS#10 request for example.com carrying pair's public key, signed by
// pair's private key, assembled here so a test can hold a CSR for a key
// buildCsr refuses.
function _csrInfo(publicKey) {
  return asn1.writeSequence([
    asn1.writeInteger(Buffer.from([0])),
    asn1.writeSequence([asn1.writeSet([asn1.writeSequence([
      asn1.writeOid("2.5.4.3"), asn1.writeUtf8String("example.com"),
    ])])]),
    publicKey.export({ type: "spki", format: "der" }),
    asn1.writeContextImplicit(0, Buffer.alloc(0), { constructed: true }),
  ]);
}
function _csrDer(pair) {
  var info = _csrInfo(pair.publicKey);
  var signer = nodeCrypto.createSign("sha256");
  signer.update(info);
  return asn1.writeSequence([
    info,
    asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]),
    asn1.writeBitString(signer.sign(pair.privateKey), 0),
  ]);
}
// A CSR for a key whose private half the test does not hold: the signature
// field carries filler bytes, since finalize reads only the subject key.
function _csrWithKey(publicKey) {
  return asn1.writeSequence([
    _csrInfo(publicKey),
    asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.11"), asn1.writeNull()]),
    asn1.writeBitString(Buffer.alloc(256, 1), 0),
  ]);
}

function testCreateRefusesCompromisedAccountKey() {
  var control = _control("prime256v1");
  check("acme compromised key control: create accepts a control account KeyObject",
        typeof _acme(control.privateKey).newAccount === "function");
  check("acme compromised key control: create accepts a control account { privatePem }",
        typeof _acme({ privatePem: control.privateKey.export({ type: "pkcs8", format: "pem" }) }).newAccount ===
          "function");

  var bad = _bad("prime256v1");
  check("acme compromised key: create refuses an account KeyObject whose private scalar is 1",
        _code(function () { _acme(bad.privateKey); }) === "acme/compromised-key");
  check("acme compromised key: create refuses an account { privatePem } whose private scalar is 1",
        _code(function () { _acme({ privatePem: bad.privateKey.export({ type: "pkcs8", format: "pem" }) }); }) ===
          "acme/compromised-key");
  check("acme compromised key: create refuses an account { privateKey } whose private scalar is 1",
        _code(function () { _acme({ privateKey: bad.privateKey }); }) === "acme/compromised-key");
  var nMinus1 = ck.ecKeyPair("prime256v1", ck.CURVES.prime256v1[2] - 1n);
  check("acme compromised key: create refuses an account key whose private scalar is n - 1",
        _code(function () { _acme(nMinus1.privateKey); }) === "acme/compromised-key");
}

async function testRolloverRefusesCompromisedKey() {
  await _withCa(async function (posts) {
    var acme = _acme(_control("prime256v1").privateKey);
    await acme.newAccount();
    check("acme compromised key: accountKeyRollover refuses a new key whose private scalar is 1",
          (await _acode(acme.accountKeyRollover(_bad("prime256v1").privateKey))) === "acme/compromised-key");
    check("acme compromised key: the refused rollover sends nothing to the key-change endpoint",
          posts.indexOf("/key-change") === -1);
    var other = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "acme rollover control"));
    check("acme compromised key control: accountKeyRollover rotates to a control key",
          (await acme.accountKeyRollover(other.privateKey)) === true && posts.indexOf("/key-change") !== -1);
  });
}

function testBuildCsrRefusesCompromisedLeafKey() {
  var acme = _acme(_control("prime256v1").privateKey);
  ["prime256v1", "secp384r1"].forEach(function (curve) {
    var control = _control(curve);
    var csr = acme.buildCsr({ privateKey: control.privateKey, publicKey: control.publicKey, domains: ["example.com"] });
    check("acme compromised key control: buildCsr builds a CSR for a " + curve + " control leaf key",
          csr.indexOf("-----BEGIN CERTIFICATE REQUEST-----") === 0);
    var bad = _bad(curve);
    check("acme compromised key: buildCsr refuses a " + curve + " leaf key whose private scalar is 1",
          _code(function () {
            acme.buildCsr({ privateKey: bad.privateKey, publicKey: bad.publicKey, domains: ["example.com"] });
          }) === "acme/compromised-key");
    check("acme compromised key: buildCsr refuses a " + curve + " scalar-1 publicKey beside a control privateKey",
          _code(function () {
            acme.buildCsr({ privateKey: control.privateKey, publicKey: bad.publicKey, domains: ["example.com"] });
          }) === "acme/compromised-key");
  });
}

async function testFinalizeRefusesCompromisedCsrKey() {
  await _withCa(async function (posts) {
    var acme = _acme(_control("prime256v1").privateKey);
    await acme.fetchDirectory();
    var order = { finalize: CA + "/finalize/1", url: CA + "/order/1" };
    var good = await acme.finalize(order, _csrDer(_control("prime256v1")));
    check("acme compromised key control: finalize sends a CSR for a control key",
          good.status === "processing" && posts.indexOf("/finalize/1") !== -1);

    posts.length = 0;
    check("acme compromised key: finalize refuses a DER CSR whose subject key has private scalar 1",
          (await _acode(acme.finalize(order, _csrDer(_bad("prime256v1"))))) === "acme/compromised-key");
    var pem = "-----BEGIN CERTIFICATE REQUEST-----\n" +
      _csrDer(_bad("secp384r1")).toString("base64").match(/.{1,64}/g).join("\n") +
      "\n-----END CERTIFICATE REQUEST-----\n";
    check("acme compromised key: finalize refuses a PEM CSR whose P-384 subject key has private scalar 1",
          (await _acode(acme.finalize(order, pem))) === "acme/compromised-key");
    var eDellRoot = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).publicKey;
    check("acme compromised key: finalize refuses a CSR carrying the eDellRoot key",
          (await _acode(acme.finalize(order, _csrWithKey(eDellRoot)))) === "acme/compromised-key");
    check("acme compromised key: the refused CSRs are not sent to the CA", posts.length === 0);
  });
}

// finalize reads the subject key out of every CSR before sending it. A CSR
// whose subject key cannot be read is refused with acme/bad-csr rather than
// sent unchecked, so a scalar-1 CSR with one trailing byte is not sent either.
async function testFinalizeRefusesUnreadableCsr() {
  await _withCa(async function (posts) {
    var acme = _acme(_control("prime256v1").privateKey);
    await acme.fetchDirectory();
    var order = { finalize: CA + "/finalize/1", url: CA + "/order/1" };
    var good = await acme.finalize(order, _csrDer(_control("prime256v1")));
    check("acme unreadable CSR control: finalize sends a well-formed CSR",
          good.status === "processing" && posts.indexOf("/finalize/1") !== -1);

    posts.length = 0;
    var trailing = Buffer.concat([_csrDer(_bad("prime256v1")), Buffer.from([0])]);
    check("acme unreadable CSR: finalize refuses a scalar-1 CSR followed by a trailing byte",
          (await _acode(acme.finalize(order, trailing))) === "acme/bad-csr");
    check("acme unreadable CSR: finalize refuses bytes that are not a CSR",
          (await _acode(acme.finalize(order, Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])))) === "acme/bad-csr");
    var noKey = asn1.writeSequence([
      asn1.writeSequence([
        asn1.writeInteger(Buffer.from([0])),
        asn1.writeSequence([]),
        asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))]),
        asn1.writeContextImplicit(0, Buffer.alloc(0), { constructed: true }),
      ]),
      asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]),
      asn1.writeBitString(Buffer.alloc(64, 1), 0),
    ]);
    check("acme unreadable CSR: finalize refuses a CSR whose subject key is not a public key",
          (await _acode(acme.finalize(order, noKey))) === "acme/bad-csr");
    check("acme unreadable CSR: the refused CSRs are not sent to the CA", posts.length === 0);
  });
}

async function run() {
  testCreateRefusesCompromisedAccountKey();
  await testRolloverRefusesCompromisedKey();
  testBuildCsrRefusesCompromisedLeafKey();
  await testFinalizeRefusesCompromisedCsrKey();
  await testFinalizeRefusesUnreadableCsr();
}

module.exports = {
  run:                                      run,
  testCreateRefusesCompromisedAccountKey:   testCreateRefusesCompromisedAccountKey,
  testRolloverRefusesCompromisedKey:        testRolloverRefusesCompromisedKey,
  testBuildCsrRefusesCompromisedLeafKey:    testBuildCsrRefusesCompromisedLeafKey,
  testFinalizeRefusesCompromisedCsrKey:     testFinalizeRefusesCompromisedCsrKey,
  testFinalizeRefusesUnreadableCsr:         testFinalizeRefusesUnreadableCsr,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
