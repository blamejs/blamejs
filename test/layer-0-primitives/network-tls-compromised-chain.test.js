// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The shared TLS identity wrapper refuses a server whose verified chain
 * carries a compromised key, over a real loopback handshake: a trusted root
 * issues an intermediate whose private key is 1, which issues the server's
 * leaf. OpenSSL verifies that chain, so only the key check can refuse it.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var nodeTls = require("node:tls");
var nodeCrypto = require("node:crypto");
var networkTls = require("../../lib/network-tls");
var ck      = require("../helpers/compromised-keys");
var paths   = require("../helpers/chain-path");
var anchors = require("../helpers/compromised-anchor");

function _handshake(which, identity) {
  var chain = ck.tlsChain(which);
  return new Promise(function (resolve) {
    var server = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (s) { s.end(); });
    server.listen(0, "127.0.0.1", function () {
      var settled = false;
      function done(result) {
        if (settled) return;
        settled = true;
        server.close();
        resolve(result);
      }
      var sock = nodeTls.connect({
        host: "127.0.0.1", port: server.address().port, servername: "localhost",
        ca: [chain.rootCa], checkServerIdentity: identity,
      }, function () { sock.end(); done({ ok: true, code: null }); });
      sock.on("error", function (e) { done({ ok: false, code: e.code || e.message }); });
    });
  });
}

async function testIdentityWrapperRefusesACompromisedChain() {
  var plainControl = await _handshake("control", nodeTls.checkServerIdentity);
  var plainBad = await _handshake("compromised", nodeTls.checkServerIdentity);
  check("tls compromised chain fixture: node alone accepts both chains",
        plainControl.ok === true && plainBad.ok === true, JSON.stringify({ plainControl, plainBad }));
  var wrapped = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [ck.tlsChain("control").rootCa]);
  var control = await _handshake("control", wrapped);
  check("tls compromised chain control: the wrapped check accepts the control chain",
        control.ok === true, JSON.stringify(control));
  var bad = await _handshake("compromised", wrapped);
  check("tls compromised chain: the wrapped check refuses a chain whose intermediate's private key is 1",
        bad.ok === false && bad.code === "tls/compromised-key", JSON.stringify(bad));
}

function testErrorHelperOnAPeerCertObject() {
  var leaf = { raw: ck.TLS_COMPROMISED_LEAF_DER, subject: { CN: "localhost" } };
  var inter = { raw: ck.TLS_COMPROMISED_INTERMEDIATE_DER, subject: { CN: "blamejs TLS fixture intermediate" } };
  var root = { raw: ck.TLS_ROOT_DER, subject: { CN: "blamejs TLS fixture root" } };
  leaf.issuerCertificate = inter;
  inter.issuerCertificate = root;
  root.issuerCertificate = root;
  var err = networkTls._compromisedPeerChainError(leaf);
  check("tls compromised chain: the error helper names the intermediate",
        err instanceof Error && err.code === "tls/compromised-key" && /intermediate/.test(err.message),
        err && err.message);
  check("tls compromised chain: no peer certificate yields no error from the chain check",
        networkTls._compromisedPeerChainError(null) === undefined);
}

function _peerChain(ders) {
  var nodes = ders.map(function (der) {
    var x = new nodeCrypto.X509Certificate(der);
    return { raw: der, subject: { CN: /CN=([^\n,]+)/.exec(x.subject)[1] } };
  });
  for (var i = 0; i < nodes.length; i += 1) nodes[i].issuerCertificate = nodes[i + 1] || nodes[i];
  return nodes[0];
}

function testADecoyIssuerIsRefused() {
  var control = _peerChain([ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER, ck.TLS_ROOT_DER]);
  check("tls compromised chain control: a chain whose every link verifies passes",
        networkTls._compromisedPeerChainError(control) === undefined);
  var decoy = _peerChain([ck.TLS_COMPROMISED_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER, ck.TLS_ROOT_DER]);
  var err = networkTls._compromisedPeerChainError(decoy);
  check("tls compromised chain: a leaf whose shown issuer did not sign it (a decoy for the compromised one) is refused",
        err instanceof Error && err.code === "tls/compromised-key", err && err.message);
}

// A loopback handshake against a server sending `material`, with `dialOpts`
// merged into the dial. It resolves with whether the client connected, the
// error code when it did not, and the socket's authorization state.
function _dialChain(material, dialOpts) {
  return new Promise(function (resolve) {
    var server = nodeTls.createServer({ key: material.key, cert: material.cert }, function (s) {
      s.on("error", function () { /* the client closed */ });
      s.end();
    });
    server.on("tlsClientError", function () { /* the client refused the chain */ });
    server.listen(0, "127.0.0.1", function () {
      var settled = false;
      function done(r) {
        if (settled) return;
        settled = true;
        server.close();
        resolve(r);
      }
      var sock = nodeTls.connect(Object.assign({
        host: "127.0.0.1", port: server.address().port, servername: "localhost",
      }, dialOpts), function () {
        var r = { ok: true, code: null, authorized: sock.authorized === true, error: sock.authorizationError || null };
        sock.end();
        done(r);
      });
      sock.on("error", function (e) { done({ ok: false, code: (e && (e.code || e.message)) || "error" }); });
    });
  });
}

function _withAnchors(material, identity) {
  return { ca: [material.anchor], checkServerIdentity: identity };
}

// The check walks the chain the peer shows and stops at a certificate the
// dial's ca trusts. A server that sends an expired alternate issuer and a
// self-signed decoy root ahead of the path OpenSSL verifies shows a chain that
// reaches no trust anchor, so the dial is refused. Legitimate shapes keep
// working: an expired cross-certificate carrying a root's name and key, a
// chain that leaves the root out, and a leaf the root issued directly.
async function testTheCheckFollowsTheDialAnchors() {
  var evasion = paths.evasionChain("compromised-evasion");
  var plain = await _dialChain(evasion, { ca: [evasion.anchor] });
  check("chain path premise: node alone verifies the chain that hides the compromised issuing CA",
        plain.ok === true && plain.authorized === true, JSON.stringify(plain));
  var cases = [
    ["control", paths.evasionChain("control"), null],
    ["compromised", paths.evasionChain("compromised"), "tls/compromised-key"],
    ["compromised-evasion", evasion, "tls/server-chain-unverifiable"],
    ["control-evasion", paths.evasionChain("control-evasion"), "tls/server-chain-unverifiable"],
    ["cross", paths.crossChain("cross"), null],
    ["intermediate", paths.crossChain("intermediate"), null],
    ["direct", paths.crossChain("direct"), null],
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var c = cases[i];
    var identity = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [c[1].anchor]);
    var r = await _dialChain(c[1], _withAnchors(c[1], identity));
    var expected = c[2];
    check("chain path " + c[0] + ": the dial " + (expected === null ? "connects" : "is refused with " + expected),
          expected === null ? (r.ok === true && r.authorized === true) : (r.ok === false && r.code === expected),
          JSON.stringify(r));
  }
}

// A check built without a ca, or for another ca, reads its anchors from the ca
// of the dial Node runs it on. A dial that passes a prebuilt secureContext is
// checked against the ca the check was built with.
async function testTheCheckReadsTheDialCa() {
  var unbound = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity);
  var otherCa = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [ck.certPem(paths.NEW_ROOT_DER)]);
  var control = paths.evasionChain("control");
  var evasion = paths.evasionChain("compromised-evasion");
  var cases = [
    ["a check built without a ca", unbound, control, null],
    ["a check built for another ca", otherCa, control, null],
    ["a check built without a ca", unbound, evasion, "tls/server-chain-unverifiable"],
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var c = cases[i];
    var r = await _dialChain(c[2], { ca: [c[2].anchor], checkServerIdentity: c[1] });
    var expected = c[3];
    check("chain path: " + c[0] + " on a dial with its own ca " +
          (expected === null ? "connects to the control chain" : "refuses the hidden compromised issuing CA"),
          expected === null ? (r.ok === true && r.authorized === true) : (r.ok === false && r.code === expected),
          JSON.stringify(r));
  }
  var context = nodeTls.createSecureContext({ ca: [control.anchor] });
  var boundToRoot = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [control.anchor]);
  var viaContext = await _dialChain(control, { secureContext: context, checkServerIdentity: boundToRoot });
  check("chain path: a dial with a prebuilt secureContext is checked against the ca the check was built with",
        viaContext.ok === true && viaContext.authorized === true, JSON.stringify(viaContext));
}

// rejectUnauthorized false with a chain the dial's ca does not trust: Node's
// own verification error stays on the socket.
async function testAnUntrustedChainKeepsNodesError() {
  var cross = paths.crossChain("cross");
  var identity = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [ck.certPem(ck.TLS_ROOT_DER)]);
  var r = await _dialChain(cross, { ca: [ck.certPem(ck.TLS_ROOT_DER)], checkServerIdentity: identity,
    rejectUnauthorized: false });
  check("chain path: rejectUnauthorized false with an untrusted chain keeps Node's verification error",
        r.ok === true && r.authorized === false && typeof r.error === "string" && r.error.indexOf("tls/") !== 0,
        JSON.stringify(r));
}

// A dial with no ca trusts Node's default CA store, and the check reads its
// anchors from that store.
async function testTheDefaultStoreAnchors() {
  var identity = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity);
  var evasion = paths.evasionChain("compromised-evasion");
  var control = paths.evasionChain("control");
  var cross = paths.crossChain("cross");
  var results = await anchors.withDefaultAnchor(evasion.anchor, async function () {
    return {
      control: await _dialChain(control, { checkServerIdentity: identity }),
      evasion: await _dialChain(evasion, { checkServerIdentity: identity }),
    };
  });
  var crossResult = await anchors.withDefaultAnchor(cross.anchor, function () {
    return _dialChain(cross, { checkServerIdentity: identity });
  });
  check("chain path default store control: a chain under a root added to the default store connects",
        results.control.ok === true && results.control.authorized === true, JSON.stringify(results.control));
  check("chain path default store: the chain that hides the compromised issuing CA is refused",
        results.evasion.ok === false && results.evasion.code === "tls/server-chain-unverifiable",
        JSON.stringify(results.evasion));
  check("chain path default store control: an expired cross-certificate of a default-store root connects",
        crossResult.ok === true && crossResult.authorized === true, JSON.stringify(crossResult));
}

// The same walk over peer certificate objects shaped like
// getPeerCertificate(true), so the result does not depend on how this Node
// links the chain.
function testTheWalkOverAShownChain() {
  function identity() { return undefined; }
  var root = [ck.certPem(ck.TLS_ROOT_DER)];
  var newRoot = [ck.certPem(paths.NEW_ROOT_DER)];
  function code(ders, ca) {
    var e = networkTls._withCompromisedChainCheck(identity, ca)("localhost", _peerChain(ders));
    return e ? e.code : null;
  }
  check("chain walk: leaf <- expired alternate <- fake root reaches no anchor",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_EXPIRED_ALTERNATE_DER, paths.FAKE_ROOT_DER], root) ===
          "tls/server-chain-unverifiable");
  check("chain walk control: leaf <- attacker CA <- ordinary issuing CA <- root passes",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_UNDER_CONTROL_DER, paths.ISSUING_CA_CONTROL_DER, ck.TLS_ROOT_DER],
             root) === null);
  check("chain walk: an issuing CA whose private key is 1 is refused",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_UNDER_COMPROMISED_DER, paths.ISSUING_CA_COMPROMISED_DER], root) ===
          "tls/compromised-key");
  check("chain walk control: the walk stops at an expired cross-certificate with the anchor's name and key",
        code([paths.NEW_ROOT_LEAF_DER, paths.NEW_ROOT_INTERMEDIATE_DER, paths.NEW_ROOT_CROSS_EXPIRED_DER,
              paths.OLD_ROOT_DER], newRoot) === null);
  check("chain walk control: a chain that stops below the root is completed by the anchor that issued it",
        code([paths.NEW_ROOT_LEAF_DER, paths.NEW_ROOT_INTERMEDIATE_DER], newRoot) === null);
  check("chain walk control: a leaf only, issued by the anchor, passes",
        code([paths.NEW_ROOT_DIRECT_LEAF_DER], newRoot) === null);
  check("chain walk: an expired certificate below the anchor is refused",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_EXPIRED_ALTERNATE_DER], [ck.certPem(paths.FAKE_ROOT_DER)]) ===
          "tls/server-chain-unverifiable");
  check("chain walk: a chain under a root the ca does not hold is refused",
        code([paths.NEW_ROOT_LEAF_DER, paths.NEW_ROOT_INTERMEDIATE_DER, paths.NEW_ROOT_DER], root) ===
          "tls/server-chain-unverifiable");
  check("chain walk: an anchor whose private key is 1 is refused",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_UNDER_COMPROMISED_DER],
             [ck.certPem(paths.ISSUING_CA_COMPROMISED_DER)]) === "tls/compromised-key");
}

function testCaHelperReadsEveryCertificateLabel() {
  var der = ck.P384_COMPROMISED_CA_DER;
  var b64 = der.toString("base64").match(/.{1,64}/g).join("\n");
  var trusted = Buffer.concat([der, Buffer.from("3000", "hex")]).toString("base64").match(/.{1,64}/g).join("\n");
  [["CERTIFICATE", "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n"],
   ["X509 CERTIFICATE", "-----BEGIN X509 CERTIFICATE-----\n" + b64 + "\n-----END X509 CERTIFICATE-----\n"],
   ["TRUSTED CERTIFICATE", "-----BEGIN TRUSTED CERTIFICATE-----\n" + trusted + "\n-----END TRUSTED CERTIFICATE-----\n"]]
    .forEach(function (f) {
      var code = null;
      try { networkTls._assertCaNotCompromised(f[1], { code: "x/compromised-key" }); } catch (e) { code = e.code; }
      check("tls ca helper: a compromised CA under the " + f[0] + " label is refused", code === "x/compromised-key", code);
    });
  [["a Buffer with no certificate", Buffer.from("# comments only\n")], ["an empty Buffer", Buffer.alloc(0)],
   ["a string with no certificate", "# comments only\n"], ["the control CA", ck.certPem(ck.P384_CONTROL_CA_DER)]]
    .forEach(function (f) {
      var code = null;
      try { networkTls._assertCaNotCompromised(f[1], { code: "x/compromised-key" }); } catch (e) { code = e.code; }
      check("tls ca helper control: " + f[0] + " passes", code === null, code);
    });
}

async function run() {
  await testIdentityWrapperRefusesACompromisedChain();
  testErrorHelperOnAPeerCertObject();
  testADecoyIssuerIsRefused();
  await testTheCheckFollowsTheDialAnchors();
  await testTheCheckReadsTheDialCa();
  await testAnUntrustedChainKeepsNodesError();
  await testTheDefaultStoreAnchors();
  testTheWalkOverAShownChain();
  testCaHelperReadsEveryCertificateLabel();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
