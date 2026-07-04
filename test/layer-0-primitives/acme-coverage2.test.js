// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.acme — supplementary coverage for the network-driven surface the
 * offline companion tests (acme.test.js / acme-coverage.test.js /
 * acme-failclosed.test.js) leave untouched.
 *
 * Every assertion drives the PUBLIC b.acme consumer path with the HTTP
 * transport stubbed to a loopback fake (httpClient.request swapped and
 * restored in finally). It exercises: fetchDirectory shape/status
 * guards, newAccount EAB + failure/location branches, the newOrder
 * identifier/profile guards + success, finalize/retrieveCert polling +
 * cert-download branches, the authorization flow (fetch / notify /
 * waitFor), RFC 9773 fetchAri + renewIfDue verdicts (via a hand-built
 * self-signed cert carrying an AuthorityKeyIdentifier), revoke /
 * rollover / deactivate failure paths, listProfiles, and the
 * dnsAccount01 record success path. Certs are assembled with the
 * framework's own lib/asn1-der so no external CA is contacted.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;

var nodeCrypto = require("node:crypto");
var httpClient = require("../../lib/http-client");
var asn1       = require("../../lib/asn1-der");
var C          = require("../../lib/constants");

var CA = "https://ca.example.test";

// ---- generic helpers ----------------------------------------------------

function _newKey() {
  return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
}

// AcmeError code from a rejected promise (or "NO-THROW").
async function _acode(promise) {
  try { await promise; return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("PLAIN:" + (e && e.message)); }
}

function _resp(status, headers, body) {
  return {
    statusCode: status,
    headers:    headers || {},
    body:       body === undefined ? "" : (typeof body === "string" ? body : JSON.stringify(body)),
  };
}

// Install a fake httpClient.request, run fn, always restore.
async function _withHttp(handler, fn) {
  var orig = httpClient.request;
  httpClient.request = handler;
  try { return await fn(); }
  finally { httpClient.request = orig; }
}

// A rolling replay-nonce header generator.
function _nonceState() {
  var n = 0;
  return function () { n += 1; return { "replay-nonce": "nonce-" + n }; };
}

// A capturing audit sink (audit.safeEmit shape).
function _auditSink() {
  var events = [];
  return { events: events, safeEmit: function (e) { events.push(e); } };
}

function _acme(opts) {
  var k = _newKey();
  var base = {
    directory:  CA + "/directory",
    accountKey: k.privateKey,
  };
  if (opts) { for (var key in opts) { if (Object.prototype.hasOwnProperty.call(opts, key)) base[key] = opts[key]; } }
  return b.acme.create(base);
}

// ---- self-signed cert builder (carries an AKI keyIdentifier) -----------
// Uses the framework's own DER writer so no external toolchain is needed.
// Node's X509Certificate parses structure without verifying the chain, so
// the self-signed shape is sufficient to drive AKI + serial extraction.

function _utcTime(s) { return asn1.writeNode(0x17, Buffer.from(s, "ascii")); }

function _buildCert(keyIdBytes) {
  var pair    = _newKey();
  var spkiDer = pair.publicKey.export({ type: "spki", format: "der" });
  var sigAlg  = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);   // ecdsa-with-SHA256

  var cnAttr = asn1.writeSequence([
    asn1.writeOid("2.5.4.3"),
    asn1.writePrintableString("acme-coverage-test"),
  ]);
  var name = asn1.writeSequence([asn1.writeSet([cnAttr])]);

  var validity = asn1.writeSequence([
    _utcTime("250101000000Z"),
    _utcTime("350101000000Z"),
  ]);

  var tbsChildren = [
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),          // version v3
    asn1.writeInteger(Buffer.from([0x12, 0x34, 0x56, 0x78])),                   // serialNumber
    sigAlg,
    name,
    validity,
    name,
    spkiDer,
  ];
  // A realistic cert carries several extensions; place a non-AKI one first
  // so the AKI walker exercises its "skip this extension" path before the
  // match. BasicConstraints with all-default fields is an empty SEQUENCE.
  var bcExt = asn1.writeSequence([
    asn1.writeOid("2.5.29.19"),                                                // id-ce-basicConstraints
    asn1.writeOctetString(asn1.writeSequence([])),
  ]);
  if (keyIdBytes) {
    var akiInner = asn1.writeContextImplicit(0, keyIdBytes);                    // [0] keyIdentifier
    var akiExt   = asn1.writeSequence([
      asn1.writeOid("2.5.29.35"),                                              // id-ce-authorityKeyIdentifier
      asn1.writeOctetString(asn1.writeSequence([akiInner])),
    ]);
    tbsChildren.push(asn1.writeContextExplicit(3, asn1.writeSequence([bcExt, akiExt])));
  } else {
    tbsChildren.push(asn1.writeContextExplicit(3, asn1.writeSequence([bcExt])));
  }
  var tbs = asn1.writeSequence(tbsChildren);

  var signer = nodeCrypto.createSign("SHA256");
  signer.update(tbs);
  var sig = signer.sign(pair.privateKey);

  var cert = asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(sig, 0)]);
  return "-----BEGIN CERTIFICATE-----\n" +
    cert.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

// A cert WITH an AKI keyIdentifier; built once, reused across ARI tests.
var CERT_WITH_AKI = _buildCert(Buffer.from("0102030405060708090a0b0c0d0e0f1011121314", "hex"));
var CERT_NO_AKI   = _buildCert(null);

// ---- directory shapes ---------------------------------------------------

function _fullDir() {
  return {
    newNonce:    CA + "/new-nonce",
    newAccount:  CA + "/new-account",
    newOrder:    CA + "/new-order",
    keyChange:   CA + "/key-change",
    revokeCert:  CA + "/revoke-cert",
    renewalInfo: CA + "/renewal-info",
    meta:        { profiles: { def: "Standard 90-day", short: "47-day", broken: 42 } },
  };
}

// ---- create(): provided-numeric-opt branches ---------------------------

function testCreateNumericOpts() {
  var acme = _acme({
    timeoutMs:      C.TIME.seconds(10),
    pollIntervalMs: C.TIME.seconds(1),
    pollMaxMs:      C.TIME.minutes(2),
    maxBytes:       C.BYTES.mib(1),
  });
  check("create honors explicit timeout / poll / maxBytes opts (handle still built)",
        typeof acme.newAccount === "function" && typeof acme.fetchAri === "function");
}

// ---- fetchDirectory: status + shape + JSON guards -----------------------

async function testFetchDirectoryStatusAndShape() {
  var acme = _acme();
  await _withHttp(function () { return Promise.resolve(_resp(500, {}, "")); }, async function () {
    check("fetchDirectory non-200 -> acme/directory-fetch",
          (await _acode(acme.fetchDirectory())) === "acme/directory-fetch");
  });

  var acme2 = _acme();
  await _withHttp(function () {
    return Promise.resolve(_resp(200, {}, { newNonce: CA + "/n", newAccount: CA + "/a" }));   // missing newOrder
  }, async function () {
    check("fetchDirectory missing required field -> acme/directory-shape",
          (await _acode(acme2.fetchDirectory())) === "acme/directory-shape");
  });

  var acme3 = _acme();
  await _withHttp(function () { return Promise.resolve(_resp(200, {}, "5")); }, async function () {
    check("fetchDirectory non-object JSON body -> acme/bad-json",
          (await _acode(acme3.fetchDirectory())) === "acme/bad-json");
  });

  var acme4 = _acme();
  await _withHttp(function () { return Promise.resolve(_resp(200, {}, "not json at all")); }, async function () {
    check("fetchDirectory invalid JSON body -> acme/bad-json",
          (await _acode(acme4.fetchDirectory())) === "acme/bad-json");
  });
}

async function testFetchDirectoryNetworkError() {
  var acme = _acme();
  await _withHttp(function () { return Promise.reject(new Error("ECONNREFUSED")); }, async function () {
    check("fetchDirectory transport throw -> acme/network",
          (await _acode(acme.fetchDirectory())) === "acme/network");
  });
}

async function testFetchDirectorySuccessBranches() {
  // With renewalInfo -> hasAri true; capitalized Replay-Nonce header read.
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(function () {
    return Promise.resolve(_resp(200, { "Replay-Nonce": "cap-nonce-1" }, _fullDir()));
  }, async function () {
    var dir = await acme.fetchDirectory();
    check("fetchDirectory success returns the directory body", dir && dir.newOrder === CA + "/new-order");
    check("fetchDirectory getter now returns the cached directory", acme.directory() && acme.directory().newNonce === CA + "/new-nonce");
  });
  check("fetchDirectory emits acme.directory.fetched success audit",
        sink.events.some(function (e) { return e.action === "acme.directory.fetched" && e.outcome === "success" && e.metadata.hasAri === true; }));

  // Without renewalInfo -> hasAri false. Audit sink lacking safeEmit hits
  // the _emitAudit early-return branch.
  var noAri = _fullDir(); delete noAri.renewalInfo;
  var acme2 = _acme({ audit: {} });
  await _withHttp(function () { return Promise.resolve(_resp(200, {}, noAri)); }, async function () {
    var dir = await acme2.fetchDirectory();
    check("fetchDirectory (no renewalInfo) still succeeds", dir && typeof dir.newOrder === "string");
  });
}

// ---- newAccount: EAB, failure, location branches ------------------------

function _accountHandler(dir, acctResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) {
      var merged = Object.assign(h, acctResp.headers || {});
      return Promise.resolve(_resp(acctResp.status, merged, acctResp.body === undefined ? { status: "valid" } : acctResp.body));
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testNewAccountEabValidation() {
  var acme = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { location: CA + "/acct/1" } }), async function () {
    check("newAccount EAB missing kid -> acme/eab-no-kid",
          (await _acode(acme.newAccount({ externalAccountBinding: { hmacKey: "AAAA" } }))) === "acme/eab-no-kid");
    check("newAccount EAB missing hmacKey -> acme/eab-no-hmac",
          (await _acode(acme.newAccount({ externalAccountBinding: { kid: "kid-1" } }))) === "acme/eab-no-hmac");
  });
}

async function testNewAccountEabSuccess() {
  var acme = _acme();
  var captured = { body: null };
  var handler = function (req) {
    var h = { "replay-nonce": "n" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) {
      captured.body = req.body;
      h.location = CA + "/acct/eab";
      return Promise.resolve(_resp(201, h, { status: "valid" }));
    }
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    var hmac = Buffer.from("super-secret-hmac-key").toString("base64url");
    var res = await acme.newAccount({ externalAccountBinding: { kid: "kid-xyz", hmacKey: hmac } });
    check("newAccount with EAB resolves to an account URL", res && res.accountUrl === CA + "/acct/eab");
  });
  var outer = JSON.parse(captured.body);
  var payload = JSON.parse(Buffer.from(outer.payload, "base64url").toString("utf8"));
  check("newAccount EAB embeds externalAccountBinding in the account payload",
        payload.externalAccountBinding && typeof payload.externalAccountBinding.signature === "string" &&
        typeof payload.externalAccountBinding.protected === "string");
}

async function testNewAccountFailureBranches() {
  // Failure status carrying a problem+json `type` -> extractProblemReason.
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(_accountHandler(_fullDir(), { status: 403, body: { type: "urn:ietf:params:acme:error:unauthorized" } }),
    async function () {
      check("newAccount non-2xx -> acme/newaccount",
            (await _acode(acme.newAccount())) === "acme/newaccount");
    });
  check("newAccount failure audit records the RFC 7807 type as reason",
        sink.events.some(function (e) { return e.action === "acme.account.registered" && e.outcome === "failure" &&
          e.metadata.reason === "urn:ietf:params:acme:error:unauthorized"; }));

  // 2xx but no Location header.
  var acme2 = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 200, body: { status: "valid" } }), async function () {
    check("newAccount 200 without Location -> acme/newaccount-no-location",
          (await _acode(acme2.newAccount())) === "acme/newaccount-no-location");
  });

  // Failure whose body is unparseable JSON -> _extractProblemReason swallows
  // the parse error and records reason null (the catch branch).
  var sink3 = _auditSink();
  var acme3 = _acme({ audit: sink3 });
  await _withHttp(_accountHandler(_fullDir(), { status: 500, body: "not-json-at-all" }), async function () {
    check("newAccount failure with an unparseable body still throws acme/newaccount",
          (await _acode(acme3.newAccount())) === "acme/newaccount");
  });
  check("newAccount failure audit reason is null when the body is not RFC 7807 JSON",
        sink3.events.some(function (e) { return e.action === "acme.account.registered" && e.outcome === "failure" && e.metadata.reason === null; }));
}

async function testNewAccountSuccessWithContact() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink, contact: ["mailto:ops@example.com"] });
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { "Location": CA + "/acct/9" }, body: { status: "valid" } }),
    async function () {
      var res = await acme.newAccount();
      check("newAccount success returns accountUrl + body", res.accountUrl === CA + "/acct/9" && res.body && res.body.status === "valid");
      check("accountUrl() getter now reflects the registered account", acme.accountUrl() === CA + "/acct/9");
    });
  check("newAccount success audit carries the contact list",
        sink.events.some(function (e) { return e.action === "acme.account.registered" && e.outcome === "success" &&
          Array.isArray(e.metadata.contact) && e.metadata.contact[0] === "mailto:ops@example.com"; }));
}

// ---- _newNonce: HEAD path (nonce not pre-seeded) ------------------------

function _noSeedNonceHandler(dir, headResp, revokeResp) {
  return function (req) {
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, {}, dir));   // no nonce header
    if (req.method === "HEAD") return Promise.resolve(headResp);
    if (req.method === "POST" && req.url.indexOf("/revoke-cert") !== -1) return Promise.resolve(revokeResp || _resp(200, {}, ""));
    return Promise.resolve(_resp(404, {}, ""));
  };
}

async function testNewNonceHeadBranches() {
  var der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);   // trivial DER cert bytes for revoke

  var acme1 = _acme();
  await _withHttp(_noSeedNonceHandler(_fullDir(), _resp(500, {}, "")), async function () {
    check("newNonce HEAD non-200 -> acme/newnonce-failed",
          (await _acode(acme1.revokeCert(der))) === "acme/newnonce-failed");
  });

  var acme2 = _acme();
  await _withHttp(_noSeedNonceHandler(_fullDir(), _resp(200, {}, "")), async function () {
    check("newNonce HEAD 200 without Replay-Nonce -> acme/newnonce-no-header",
          (await _acode(acme2.revokeCert(der))) === "acme/newnonce-no-header");
  });

  var acme3 = _acme();
  await _withHttp(_noSeedNonceHandler(_fullDir(), _resp(200, { "replay-nonce": "fresh-1" }, ""), _resp(200, {}, "")), async function () {
    check("newNonce HEAD 200 + Replay-Nonce feeds a successful revoke",
          (await acme3.revokeCert(der)) === true);
  });
}

// ---- newOrder: guards + success -----------------------------------------

function _orderHandler(dir, orderResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) {
      h.location = CA + "/acct/1";
      return Promise.resolve(_resp(201, h, { status: "valid" }));
    }
    if (req.method === "POST" && req.url.indexOf("/new-order") !== -1) {
      var merged = Object.assign(h, orderResp.headers || {});
      return Promise.resolve(_resp(orderResp.status, merged, orderResp.body === undefined ? { status: "pending" } : orderResp.body));
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testNewOrderGuards() {
  var acme = _acme();
  // No account yet (directory not fetched either) -> newOrder auto-fetches
  // directory, then trips the no-account guard.
  await _withHttp(_orderHandler(_fullDir(), { status: 201 }), async function () {
    check("newOrder before newAccount -> acme/no-account",
          (await _acode(acme.newOrder({ identifiers: [{ type: "dns", value: "x.com" }] }))) === "acme/no-account");
  });

  var acme2 = _acme();
  await _withHttp(_orderHandler(_fullDir(), { status: 201 }), async function () {
    await acme2.newAccount();
    check("newOrder without identifiers -> acme/bad-order",
          (await _acode(acme2.newOrder({}))) === "acme/bad-order");
    check("newOrder with empty identifiers -> acme/bad-order",
          (await _acode(acme2.newOrder({ identifiers: [] }))) === "acme/bad-order");
    check("newOrder with a malformed identifier -> acme/bad-identifier",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns" }] }))) === "acme/bad-identifier");
    check("newOrder with an over-length identifier -> acme/bad-identifier",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "a".repeat(300) }] }))) === "acme/bad-identifier");
    check("newOrder with a non-string profile -> acme/bad-profile",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "x.com" }], profile: 42 }))) === "acme/bad-profile");
    check("newOrder with an empty profile string -> acme/bad-profile",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "x.com" }], profile: "" }))) === "acme/bad-profile");
    check("newOrder with an over-length profile -> acme/bad-profile",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "x.com" }], profile: "p".repeat(80) }))) === "acme/bad-profile");
  });
}

async function testNewOrderFailureAndSuccess() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(_orderHandler(_fullDir(), { status: 400, body: { detail: "policy refused" } }), async function () {
    await acme.newAccount();
    check("newOrder non-201 -> acme/neworder",
          (await _acode(acme.newOrder({ identifiers: [{ type: "dns", value: "x.com" }] }))) === "acme/neworder");
  });
  check("newOrder failure audit extracts RFC 7807 detail",
        sink.events.some(function (e) { return e.action === "acme.order.created" && e.outcome === "failure" && e.metadata.reason === "policy refused"; }));

  var sink2 = _auditSink();
  var acme2 = _acme({ audit: sink2 });
  await _withHttp(_orderHandler(_fullDir(), { status: 201, headers: { location: CA + "/order/77" }, body: { status: "pending", finalize: CA + "/finalize/77" } }),
    async function () {
      await acme2.newAccount();
      var order = await acme2.newOrder({
        identifiers: [{ type: "dns", value: "good.com" }],
        notBefore:   "2026-01-01T00:00:00Z",
        notAfter:    "2026-04-01T00:00:00Z",
        profile:     "short",
      });
      check("newOrder success returns the order with its url", order.url === CA + "/order/77" && order.finalize === CA + "/finalize/77");
    });
  check("newOrder success emits acme.order.created success audit",
        sink2.events.some(function (e) { return e.action === "acme.order.created" && e.outcome === "success"; }));
}

// ---- finalize: network success + failure --------------------------------

function _finalizeHandler(finalizeResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/finalize") !== -1) return Promise.resolve(_resp(finalizeResp.status, h, finalizeResp.body));
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testFinalizeNetworkBranches() {
  var pair = _newKey();
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var csr  = acme.buildCsr({ privateKey: pair.privateKey, publicKey: pair.publicKey, domains: ["f.example.com"] });
  var order = { finalize: CA + "/finalize/1", url: CA + "/order/1" };

  await _withHttp(_finalizeHandler({ status: 200, body: { status: "processing" } }), async function () {
    await acme.fetchDirectory();
    var updated = await acme.finalize(order, csr);
    check("finalize success returns the updated order carrying its url", updated.url === CA + "/order/1" && updated.status === "processing");
  });
  check("finalize success emits acme.order.finalize success audit",
        sink.events.some(function (e) { return e.action === "acme.order.finalize" && e.outcome === "success"; }));

  var sink2 = _auditSink();
  var acme2 = _acme({ audit: sink2 });
  await _withHttp(_finalizeHandler({ status: 400, body: { title: "bad CSR" } }), async function () {
    await acme2.fetchDirectory();
    check("finalize non-2xx -> acme/finalize",
          (await _acode(acme2.finalize(order, Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])))) === "acme/finalize");
  });
  check("finalize failure audit extracts RFC 7807 title",
        sink2.events.some(function (e) { return e.action === "acme.order.finalize" && e.outcome === "failure" && e.metadata.reason === "bad CSR"; }));
}

// ---- retrieveCert: polling + download branches --------------------------

var PEM_CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

async function testRetrieveCertBadOrder() {
  var acme = _acme();
  check("retrieveCert without order.url -> acme/bad-order",
        (await _acode(acme.retrieveCert({}))) === "acme/bad-order");
}

async function testRetrieveCertImmediateValid() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/cert/1") !== -1) return Promise.resolve(_resp(200, h, PEM_CERT));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    var order = { url: CA + "/order/1", status: "valid", certificate: CA + "/cert/1" };
    var pem = await acme.retrieveCert(order);
    check("retrieveCert (already valid) downloads the PEM", pem.indexOf("-----BEGIN CERTIFICATE-----") === 0);
  });
  check("retrieveCert success emits acme.cert.issued success audit",
        sink.events.some(function (e) { return e.action === "acme.cert.issued" && e.outcome === "success"; }));
}

async function testRetrieveCertInvalidOrder() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  check("retrieveCert on an invalid order -> acme/order-invalid",
        (await _acode(acme.retrieveCert({ url: CA + "/order/x", status: "invalid" }))) === "acme/order-invalid");
  check("retrieveCert invalid emits acme.order.poll failure audit",
        sink.events.some(function (e) { return e.action === "acme.order.poll" && e.outcome === "failure"; }));
}

async function testRetrieveCertPollToValid() {
  var acme = _acme({ pollIntervalMs: 1, pollMaxMs: C.TIME.seconds(5) });
  var polls = 0;
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/order/poll") !== -1) {
      polls += 1;
      if (polls < 2) return Promise.resolve(_resp(200, h, { status: "pending" }));
      return Promise.resolve(_resp(200, h, { status: "valid", certificate: CA + "/cert/poll" }));
    }
    if (req.method === "POST" && req.url.indexOf("/cert/poll") !== -1) return Promise.resolve(_resp(200, h, PEM_CERT));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    var pem = await acme.retrieveCert({ url: CA + "/order/poll", status: "pending" });
    check("retrieveCert polls pending->valid then downloads", pem.indexOf("-----BEGIN CERTIFICATE-----") === 0 && polls >= 2);
  });
}

async function testRetrieveCertPollNon2xx() {
  var acme = _acme({ pollIntervalMs: 1, pollMaxMs: C.TIME.seconds(5) });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/order/pollerr") !== -1) return Promise.resolve(_resp(500, h, ""));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    check("retrieveCert poll non-2xx -> acme/order-poll",
          (await _acode(acme.retrieveCert({ url: CA + "/order/pollerr", status: "pending" }))) === "acme/order-poll");
  });
}

async function testRetrieveCertTimeout() {
  var acme = _acme({ pollIntervalMs: 5, pollMaxMs: 40 });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/order/slow") !== -1) return Promise.resolve(_resp(200, h, { status: "pending" }));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    check("retrieveCert never-valid -> acme/order-timeout",
          (await _acode(acme.retrieveCert({ url: CA + "/order/slow", status: "pending" }))) === "acme/order-timeout");
  });
}

async function testRetrieveCertDownloadBranches() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/cert/500") !== -1) return Promise.resolve(_resp(500, h, ""));
    if (req.method === "POST" && req.url.indexOf("/cert/notpem") !== -1) return Promise.resolve(_resp(200, h, "this is not a certificate"));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    check("retrieveCert download non-200 -> acme/cert-download",
          (await _acode(acme.retrieveCert({ url: CA + "/order/a", status: "valid", certificate: CA + "/cert/500" }))) === "acme/cert-download");
    check("retrieveCert download non-PEM body -> acme/bad-cert-bytes",
          (await _acode(acme.retrieveCert({ url: CA + "/order/b", status: "valid", certificate: CA + "/cert/notpem" }))) === "acme/bad-cert-bytes");
  });
  check("retrieveCert download failure emits acme.cert.issued failure audit",
        sink.events.some(function (e) { return e.action === "acme.cert.issued" && e.outcome === "failure"; }));
}

// ---- authorization flow -------------------------------------------------

function _authHandler(map) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    for (var key in map) {
      if (Object.prototype.hasOwnProperty.call(map, key) && req.url.indexOf(key) !== -1) {
        var r = map[key](req);
        return Promise.resolve(_resp(r.status, h, r.body));
      }
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testAuthorizationFlow() {
  var acme = _acme();
  await _withHttp(_authHandler({
    "/auth/ok":  function () { return { status: 200, body: { status: "pending", challenges: [{ type: "http-01", url: CA + "/chal/1", token: "tok" }] } }; },
    "/auth/err": function () { return { status: 500, body: "" }; },
    "/chal/ok":  function () { return { status: 200, body: { status: "processing" } }; },
    "/chal/err": function () { return { status: 403, body: "" }; },
  }), async function () {
    await acme.fetchDirectory();
    var auth = await acme.fetchAuthorization(CA + "/auth/ok");
    check("fetchAuthorization returns the auth object with its url", auth.url === CA + "/auth/ok" && Array.isArray(auth.challenges));
    check("fetchAuthorization non-2xx -> acme/auth-fetch",
          (await _acode(acme.fetchAuthorization(CA + "/auth/err"))) === "acme/auth-fetch");
    var updated = await acme.notifyChallengeReady(CA + "/chal/ok");
    check("notifyChallengeReady returns the updated challenge", updated.status === "processing");
    check("notifyChallengeReady non-2xx -> acme/challenge-ready",
          (await _acode(acme.notifyChallengeReady(CA + "/chal/err"))) === "acme/challenge-ready");
  });
}

async function testWaitForAuthorization() {
  // valid immediately (default interval/deadline branch).
  var acme = _acme();
  await _withHttp(_authHandler({ "/auth/valid": function () { return { status: 200, body: { status: "valid" } }; } }), async function () {
    await acme.fetchDirectory();
    var auth = await acme.waitForAuthorization(CA + "/auth/valid");
    check("waitForAuthorization returns when status is valid", auth.status === "valid");
  });

  // invalid -> throw + audit.
  var sink = _auditSink();
  var acme2 = _acme({ audit: sink });
  await _withHttp(_authHandler({ "/auth/bad": function () { return { status: 200, body: { status: "invalid", challenges: [{ error: { detail: "dns failed" } }] } }; } }),
    async function () {
      await acme2.fetchDirectory();
      check("waitForAuthorization invalid -> acme/auth-invalid",
            (await _acode(acme2.waitForAuthorization(CA + "/auth/bad"))) === "acme/auth-invalid");
    });
  check("waitForAuthorization invalid emits acme.auth.poll failure audit",
        sink.events.some(function (e) { return e.action === "acme.auth.poll" && e.outcome === "failure"; }));

  // timeout (explicit intervalMs/timeoutMs opts branch).
  var acme3 = _acme();
  await _withHttp(_authHandler({ "/auth/slow": function () { return { status: 200, body: { status: "pending" } }; } }), async function () {
    await acme3.fetchDirectory();
    check("waitForAuthorization never-valid -> acme/auth-timeout",
          (await _acode(acme3.waitForAuthorization(CA + "/auth/slow", { intervalMs: 5, timeoutMs: 30 }))) === "acme/auth-timeout");
  });
}

// ---- fetchAri + renewIfDue ----------------------------------------------

function _ariHandler(dir, ariResponder) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "GET" && req.url.indexOf("/renewal-info/") !== -1) {
      var r = ariResponder(req);
      return Promise.resolve({ statusCode: r.status, headers: Object.assign(h, r.headers || {}), body: typeof r.body === "string" ? r.body : JSON.stringify(r.body) });
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testFetchAriGuards() {
  // Directory has no renewalInfo -> acme/no-ari.
  var noAri = _fullDir(); delete noAri.renewalInfo;
  var acme = _acme();
  await _withHttp(_ariHandler(noAri, function () { return { status: 200, body: {} }; }), async function () {
    check("fetchAri when directory lacks renewalInfo -> acme/no-ari",
          (await _acode(acme.fetchAri({ certPem: CERT_WITH_AKI }))) === "acme/no-ari");
  });

  // Cert without AKI -> acme/no-aki (extraction fails before network).
  var acme2 = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () { return { status: 200, body: {} }; }), async function () {
    check("fetchAri on a cert with no AKI -> acme/no-aki",
          (await _acode(acme2.fetchAri({ certPem: CERT_NO_AKI }))) === "acme/no-aki");
  });

  // ARI GET non-200.
  var acme3 = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () { return { status: 404, body: "" }; }), async function () {
    check("fetchAri ARI GET non-200 -> acme/ari-fetch",
          (await _acode(acme3.fetchAri({ certPem: CERT_WITH_AKI }))) === "acme/ari-fetch");
  });
}

async function _assertAriShape(label, body) {
  var acme = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () { return { status: 200, body: body }; }), async function () {
    check("fetchAri " + label + " -> acme/ari-shape",
          (await _acode(acme.fetchAri({ certPem: CERT_WITH_AKI }))) === "acme/ari-shape");
  });
}

async function testFetchAriShapeGuards() {
  await _assertAriShape("missing suggestedWindow",  { foo: 1 });
  await _assertAriShape("non-string window bounds", { suggestedWindow: { start: 1, end: 2 } });
  await _assertAriShape("unparseable timestamps",   { suggestedWindow: { start: "nope", end: "also-nope" } });
  await _assertAriShape("end before start",         { suggestedWindow: { start: "2027-01-02T00:00:00Z", end: "2027-01-01T00:00:00Z" } });
}

async function testFetchAriSuccess() {
  var now = Date.now();
  var start = new Date(now - C.TIME.hours(1)).toISOString();
  var end   = new Date(now + C.TIME.hours(1)).toISOString();
  var acme = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () {
    return { status: 200, headers: { "retry-after": "21600" }, body: { suggestedWindow: { start: start, end: end }, explanationURL: "https://ca.example.test/why" } };
  }), async function () {
    var ari = await acme.fetchAri({ certPem: CERT_WITH_AKI });
    check("fetchAri returns a certId derived from AKI + serial", typeof ari.certId === "string" && ari.certId.indexOf(".") > 0);
    check("fetchAri surfaces retry-after + explanationURL", ari.retryAfter === "21600" && ari.explanationURL === "https://ca.example.test/why");
    check("fetchAri parses the window into epoch ms", isFinite(ari.suggestedWindow.startMs) && isFinite(ari.suggestedWindow.endMs));
  });

  // retry-after absent + explanationURL non-string -> both normalize to null.
  var acme2 = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () {
    return { status: 200, body: { suggestedWindow: { start: start, end: end }, explanationURL: 12345 } };
  }), async function () {
    var ari = await acme2.fetchAri({ certPem: CERT_WITH_AKI });
    check("fetchAri null retryAfter + null explanationURL when absent/non-string", ari.retryAfter === null && ari.explanationURL === null);
  });
}

function _ariWindowFake(startOffset, endOffset) {
  var now = Date.now();
  var start = new Date(now + startOffset).toISOString();
  var end   = new Date(now + endOffset).toISOString();
  return _ariHandler(_fullDir(), function () {
    return { status: 200, body: { suggestedWindow: { start: start, end: end } } };
  });
}

async function testRenewIfDueVerdicts() {
  var H = C.TIME.hours(1);

  // before-window
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(_ariWindowFake(H, 2 * H), async function () {
    var v = await acme.renewIfDue({ certPem: CERT_WITH_AKI });
    check("renewIfDue before the window -> shouldRenew false, before-window", v.shouldRenew === false && v.reason === "before-window");
  });
  check("renewIfDue before-window emits acme.cert.renew.skipped audit",
        sink.events.some(function (e) { return e.action === "acme.cert.renew.skipped"; }));

  // in-window
  var acme2 = _acme();
  await _withHttp(_ariWindowFake(-H, H), async function () {
    var v = await acme2.renewIfDue({ certPem: CERT_WITH_AKI });
    check("renewIfDue inside the window -> shouldRenew true, in-window", v.shouldRenew === true && v.reason === "in-window");
  });

  // past-window
  var acme3 = _acme();
  await _withHttp(_ariWindowFake(-2 * H, -H), async function () {
    var v = await acme3.renewIfDue({ certPem: CERT_WITH_AKI });
    check("renewIfDue past the window -> shouldRenew true, past-window", v.shouldRenew === true && v.reason === "past-window");
  });
}

async function testRenewIfDueJitter() {
  var H = C.TIME.hours(1);

  // before-window + jitter -> renewAt is an ISO string within [start, end].
  var acme = _acme();
  await _withHttp(_ariWindowFake(H, 2 * H), async function () {
    var v = await acme.renewIfDue({ certPem: CERT_WITH_AKI, jitter: true });
    check("renewIfDue before-window jitter yields an ISO renewAt", v.shouldRenew === false && typeof v.renewAt === "string" &&
          isFinite(Date.parse(v.renewAt)));
  });

  // in-window + jitter.
  var acme2 = _acme();
  await _withHttp(_ariWindowFake(-H, H), async function () {
    var v = await acme2.renewIfDue({ certPem: CERT_WITH_AKI, jitter: true });
    check("renewIfDue in-window jitter yields an ISO renewAt", v.shouldRenew === true && typeof v.renewAt === "string");
  });

  // past-window + jitter -> jHi < jLo branch (renewAt == now).
  var acme3 = _acme();
  await _withHttp(_ariWindowFake(-2 * H, -H), async function () {
    var v = await acme3.renewIfDue({ certPem: CERT_WITH_AKI, jitter: true });
    check("renewIfDue past-window jitter yields an ISO renewAt", v.shouldRenew === true && typeof v.renewAt === "string");
  });
}

// ---- revokeCert branches ------------------------------------------------

function _revokeHandler(dir, revokeResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/revoke-cert") !== -1) return Promise.resolve(_resp(revokeResp.status, h, revokeResp.body));
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testRevokeCertBranches() {
  var der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);

  // directory without revokeCert endpoint.
  var noRevoke = _fullDir(); delete noRevoke.revokeCert;
  var acme0 = _acme();
  await _withHttp(_revokeHandler(noRevoke, { status: 200, body: "" }), async function () {
    check("revokeCert when directory lacks revokeCert -> acme/revoke-not-supported",
          (await _acode(acme0.revokeCert(der))) === "acme/revoke-not-supported");
  });

  // useCertKey: true is a reserved/deferred path -> throws.
  var acme1 = _acme();
  await _withHttp(_revokeHandler(_fullDir(), { status: 200, body: "" }), async function () {
    check("revokeCert useCertKey:true -> acme/revoke-cert-key-not-implemented",
          (await _acode(acme1.revokeCert(der, { useCertKey: true }))) === "acme/revoke-cert-key-not-implemented");
  });

  // success with a reason code + Uint8Array input.
  var sink = _auditSink();
  var acme2 = _acme({ audit: sink });
  await _withHttp(_revokeHandler(_fullDir(), { status: 200, body: "" }), async function () {
    var ok = await acme2.revokeCert(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x04]), { reason: 4 });
    check("revokeCert (Uint8Array + reason) resolves true", ok === true);
  });
  check("revokeCert success emits acme.cert.revoked success audit",
        sink.events.some(function (e) { return e.action === "acme.cert.revoked" && e.outcome === "success"; }));

  // failure status with an empty body (extractProblemReason(null) branch).
  var sink2 = _auditSink();
  var acme3 = _acme({ audit: sink2 });
  await _withHttp(_revokeHandler(_fullDir(), { status: 409, body: "" }), async function () {
    check("revokeCert non-200 -> acme/revoke-failed",
          (await _acode(acme3.revokeCert(der))) === "acme/revoke-failed");
  });
  check("revokeCert failure emits acme.cert.revoked failure audit with null reason",
        sink2.events.some(function (e) { return e.action === "acme.cert.revoked" && e.outcome === "failure" && e.metadata.reason === null; }));
}

// ---- accountKeyRollover branches ----------------------------------------

async function testRolloverBranches() {
  // No account (directory fetched, but newAccount not called).
  var acme0 = _acme();
  await _withHttp(_orderHandler(_fullDir(), { status: 201 }), async function () {
    await acme0.fetchDirectory();
    check("accountKeyRollover before newAccount -> acme/no-account",
          (await _acode(acme0.accountKeyRollover(_newKey().privateKey))) === "acme/no-account");
  });

  // Account present but directory lacks keyChange.
  var noKc = _fullDir(); delete noKc.keyChange;
  var acme1 = _acme();
  await _withHttp(_accountHandler(noKc, { status: 201, headers: { location: CA + "/acct/1" } }), async function () {
    await acme1.newAccount();
    check("accountKeyRollover without keyChange endpoint -> acme/key-change-not-supported",
          (await _acode(acme1.accountKeyRollover(_newKey().privateKey))) === "acme/key-change-not-supported");
  });

  // Bad new key.
  var acme2 = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { location: CA + "/acct/1" } }), async function () {
    await acme2.newAccount();
    check("accountKeyRollover with a non-object new key -> acme/bad-new-key",
          (await _acode(acme2.accountKeyRollover("not-a-key"))) === "acme/bad-new-key");
    // An object lacking a KeyObject export() reaches _publicJwkFromKeyObject.
    check("accountKeyRollover with a bare object (no export) -> acme/bad-account-key",
          (await _acode(acme2.accountKeyRollover({}))) === "acme/bad-account-key");
  });

  // keyChange POST failure.
  var sink = _auditSink();
  var acme3 = _acme({ audit: sink });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) { h.location = CA + "/acct/1"; return Promise.resolve(_resp(201, h, { status: "valid" })); }
    if (req.method === "POST" && req.url.indexOf("/key-change") !== -1) return Promise.resolve(_resp(500, h, { detail: "rotation refused" }));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme3.newAccount();
    check("accountKeyRollover keyChange non-200 -> acme/key-change-failed",
          (await _acode(acme3.accountKeyRollover(_newKey().privateKey))) === "acme/key-change-failed");
  });
  check("accountKeyRollover failure emits acme.account.key_rotated failure audit",
        sink.events.some(function (e) { return e.action === "acme.account.key_rotated" && e.outcome === "failure"; }));
}

// ---- deactivateAccount + dnsAccount01 record success --------------------

async function testDeactivateBranches() {
  // failure.
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var handlerFail = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) { h.location = CA + "/acct/d"; return Promise.resolve(_resp(201, h, { status: "valid" })); }
    if (req.method === "POST" && req.url.indexOf("/acct/d") !== -1) return Promise.resolve(_resp(500, h, ""));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handlerFail, async function () {
    await acme.newAccount();
    check("deactivateAccount non-200 -> acme/deactivate-failed",
          (await _acode(acme.deactivateAccount())) === "acme/deactivate-failed");
  });
  check("deactivateAccount failure emits audit", sink.events.some(function (e) { return e.action === "acme.account.deactivated" && e.outcome === "failure"; }));

  // success.
  var sink2 = _auditSink();
  var acme2 = _acme({ audit: sink2 });
  var handlerOk = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) { h.location = CA + "/acct/e"; return Promise.resolve(_resp(201, h, { status: "valid" })); }
    if (req.method === "POST" && req.url.indexOf("/acct/e") !== -1) return Promise.resolve(_resp(200, h, { status: "deactivated" }));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handlerOk, async function () {
    await acme2.newAccount();
    check("deactivateAccount success resolves true", (await acme2.deactivateAccount()) === true);
  });
  check("deactivateAccount success emits audit", sink2.events.some(function (e) { return e.action === "acme.account.deactivated" && e.outcome === "success"; }));
}

async function testDnsAccount01Success() {
  var acme = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { location: CA + "/acct/dns" } }), async function () {
    await acme.newAccount();
    // ttl validation branch (after accountUrl guard).
    var threw = null;
    try { acme.dnsAccount01ChallengeRecord("tok", { identifier: "example.com", ttl: -5 }); }
    catch (e) { threw = e; }
    check("dnsAccount01ChallengeRecord rejects a negative ttl -> acme/bad-ttl", threw && threw.code === "acme/bad-ttl");
    var threw2 = null;
    try { acme.dnsAccount01ChallengeRecord("tok", { identifier: "example.com", ttl: 90000 }); }
    catch (e) { threw2 = e; }
    check("dnsAccount01ChallengeRecord rejects a ttl above 86400 -> acme/bad-ttl", threw2 && threw2.code === "acme/bad-ttl");

    var rec = acme.dnsAccount01ChallengeRecord("tok123", { identifier: "example.com" });
    check("dnsAccount01ChallengeRecord default ttl is 60", rec.ttl === 60);
    check("dnsAccount01ChallengeRecord name is _<label>._acme-challenge.<identifier>",
          /^_[a-z2-7]+\._acme-challenge\.example\.com$/.test(rec.name));
    check("dnsAccount01ChallengeRecord value is base64url", /^[A-Za-z0-9_-]+$/.test(rec.value));

    var rec2 = acme.dnsAccount01ChallengeRecord("tok123", { identifier: "example.com", ttl: 300 });
    check("dnsAccount01ChallengeRecord honors a provided ttl", rec2.ttl === 300);
  });
}

// ---- listProfiles branches ----------------------------------------------

async function testListProfiles() {
  // full map (string + non-string values).
  var acme = _acme();
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    await acme.fetchDirectory();
    var p = acme.listProfiles();
    check("listProfiles surfaces advertised profile names", p.def === "Standard 90-day" && p.short === "47-day");
    check("listProfiles coerces a non-string profile description to \"\"", p.broken === "");
  });

  // meta not an object -> {}.
  var acme2 = _acme();
  var dirMetaBad = _fullDir(); dirMetaBad.meta = "x";
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dirMetaBad));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    await acme2.fetchDirectory();
    check("listProfiles with non-object meta -> {}", Object.keys(acme2.listProfiles()).length === 0);
  });

  // profiles not an object -> {}.
  var acme3 = _acme();
  var dirProfBad = _fullDir(); dirProfBad.meta = { profiles: 5 };
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dirProfBad));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    await acme3.fetchDirectory();
    check("listProfiles with non-object profiles -> {}", Object.keys(acme3.listProfiles()).length === 0);
  });
}

// ---- audit best-effort catch --------------------------------------------

async function testAuditThrowIsSwallowed() {
  var throwing = { safeEmit: function () { throw new Error("audit sink exploded"); } };
  var acme = _acme({ audit: throwing });
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    var dir = await acme.fetchDirectory();
    check("a throwing audit sink does not break fetchDirectory (best-effort emit)", dir && typeof dir.newOrder === "string");
  });
}

async function run() {
  // acme's internal poll uses an unref'd timer (it must not pin a host
  // process). Standalone, that means the event loop can empty mid-poll and
  // Node would exit before run() resolves. A ref'd keep-alive timer holds
  // the loop open for the duration; cleared in finally so the process (and
  // the forked smoke child) exits cleanly once every check has run.
  var keepAlive = setInterval(function () {}, C.TIME.seconds(1));
  try {
    await _runAll();
  } finally {
    clearInterval(keepAlive);
  }
}

async function _runAll() {
  testCreateNumericOpts();
  await testFetchDirectoryStatusAndShape();
  await testFetchDirectoryNetworkError();
  await testFetchDirectorySuccessBranches();
  await testNewAccountEabValidation();
  await testNewAccountEabSuccess();
  await testNewAccountFailureBranches();
  await testNewAccountSuccessWithContact();
  await testNewNonceHeadBranches();
  await testNewOrderGuards();
  await testNewOrderFailureAndSuccess();
  await testFinalizeNetworkBranches();
  await testRetrieveCertBadOrder();
  await testRetrieveCertImmediateValid();
  await testRetrieveCertInvalidOrder();
  await testRetrieveCertPollToValid();
  await testRetrieveCertPollNon2xx();
  await testRetrieveCertTimeout();
  await testRetrieveCertDownloadBranches();
  await testAuthorizationFlow();
  await testWaitForAuthorization();
  await testFetchAriGuards();
  await testFetchAriShapeGuards();
  await testFetchAriSuccess();
  await testRenewIfDueVerdicts();
  await testRenewIfDueJitter();
  await testRevokeCertBranches();
  await testRolloverBranches();
  await testDeactivateBranches();
  await testDnsAccount01Success();
  await testListProfiles();
  await testAuditThrowIsSwallowed();
}

module.exports = { run: run };

// Allow direct execution: `node test/layer-0-primitives/acme-coverage2.test.js`
if (require.main === module) {
  run().then(function () {
    console.log("OK — acme-coverage2 " + helpers.getChecks() + " checks passed");
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  });
}
