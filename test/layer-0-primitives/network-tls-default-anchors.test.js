// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A certificate that NODE_EXTRA_CA_CERTS adds to Node's default CA store is a
 * trust anchor blamejs never sees as `ca`. When its key is compromised, the
 * options b.network.tls.applyToContext and b.network.tls.buildOptions build
 * carry the default store without it, so OpenSSL cannot verify a chain through
 * it even when the caller replaces checkServerIdentity. Each case runs in a
 * child process started with NODE_EXTRA_CA_CERTS naming one anchor file: the
 * compromised anchor (private key 1) with a server that sends its leaf and a
 * decoy self-signed certificate under the anchor's name, and a control anchor
 * with an ordinary key and a server that sends its leaf and that anchor.
 */

var nodeTls = require("node:tls");
var nodeFs  = require("node:fs");
var nodeOs  = require("node:os");
var nodePath = require("node:path");
var nodeCp  = require("node:child_process");
var nodeCrypto = require("node:crypto");

function _dial(opts) {
  return new Promise(function (resolve) {
    var settled = false;
    function done(r) { if (!settled) { settled = true; resolve(r); } }
    var s = nodeTls.connect(opts, function () {
      var r = { authorized: s.authorized === true, error: s.authorizationError || null };
      s.end();
      done(r);
    });
    s.on("error", function (e) { done({ authorized: false, error: (e && (e.code || e.message)) || "error" }); });
  });
}

function _hasPem(list, pem) {
  return Array.isArray(list) && list.some(function (p) { return String(p).trim() === pem.trim(); });
}

async function _childMain(port, anchorPem) {
  var networkTls = require("../../lib/network-tls");
  var dialBase = { host: "127.0.0.1", port: port, servername: "localhost" };
  function noIdentityCheck() { return undefined; }
  var client = networkTls.applyToContext({ role: "client", base: Object.assign({}, dialBase) });
  var server = networkTls.applyToContext({ role: "server", base: { requestCert: true } });
  var built = networkTls.buildOptions({});
  var hasHelper = typeof networkTls._clientTrustAnchors === "function";
  var out = {
    defaultStoreHasAnchor: _hasPem(nodeTls.getCACertificates("default"), anchorPem),
    bundledCount:          nodeTls.rootCertificates.length,
    clientCa:   { set: client.ca !== undefined, hasAnchor: _hasPem(client.ca, anchorPem),
                  length: Array.isArray(client.ca) ? client.ca.length : 0 },
    serverCa:   { set: server.ca !== undefined, hasAnchor: _hasPem(server.ca, anchorPem) },
    builtCa:    { set: built.ca !== undefined, hasAnchor: _hasPem(built.ca, anchorPem) },
    helperCa:   { set: hasHelper && networkTls._clientTrustAnchors(undefined) !== undefined },
    explicitCa: hasHelper && networkTls._clientTrustAnchors("x") === "x",
  };
  out.plain = await _dial(Object.assign({}, dialBase));
  out.applyToContextNoIdentity = await _dial(Object.assign({}, client, { checkServerIdentity: noIdentityCheck }));
  out.buildOptionsNoIdentity = await _dial(Object.assign({}, built, dialBase, { checkServerIdentity: noIdentityCheck }));
  out.applyToContext = await _dial(client);
  process.stdout.write("RESULT " + JSON.stringify(out) + "\n");
}

// Under --use-openssl-ca the OpenSSL store is not in getCACertificates
// ("default"). The child dials a server whose chain ends at an anchor in that
// store, with Node alone, with applyToContext, and through b.network.dns over
// DNS-over-TLS (which answers one A query).
async function _opensslChildMain(port) {
  var networkTls = require("../../lib/network-tls");
  var b = require("../../index.js");
  var dialBase = { host: "127.0.0.1", port: port, servername: "localhost" };
  var out = {
    defaultStoreSize: nodeTls.getCACertificates("default").length,
    replacementCa:    networkTls._clientTrustAnchors(undefined) !== undefined,
  };
  out.plain = await _dial(Object.assign({}, dialBase));
  out.applyToContext = await _dial(networkTls.applyToContext({ role: "client", base: Object.assign({}, dialBase) }));
  b.network.dns.useDnsOverTls({ host: "127.0.0.1", port: port, servername: "localhost" });
  try {
    out.dot = { answer: await b.network.dns.resolve4("bank.example.com", { transport: "dot" }), code: null };
  } catch (e) {
    out.dot = { answer: null, code: (e && e.code) || String(e) };
  }
  process.stdout.write("RESULT " + JSON.stringify(out) + "\n");
  process.exit(0);
}

if (require.main === module && process.argv[2] === "child") {
  _childMain(Number(process.argv[3]), nodeFs.readFileSync(process.argv[4], "utf8"))
    .catch(function (e) { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });
  return;
}
if (require.main === module && process.argv[2] === "openssl-child") {
  _opensslChildMain(Number(process.argv[3]))
    .catch(function (e) { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });
  return;
}

var helpers = require("../helpers");
var check   = helpers.check;
var anchors = require("../helpers/compromised-anchor");
var ck      = require("../helpers/compromised-keys");

function _runChild(port, anchorFile) {
  return new Promise(function (resolve) {
    var child = nodeCp.spawn(process.execPath, [__filename, "child", String(port), anchorFile], {
      env: Object.assign({}, process.env, { NODE_EXTRA_CA_CERTS: anchorFile }),
      stdio: ["ignore", "pipe", "pipe"],
    });
    var so = "";
    var se = "";
    child.stdout.on("data", function (d) { so += d; });
    child.stderr.on("data", function (d) { se += d; });
    child.on("close", function (code) {
      var line = so.split("\n").filter(function (l) { return l.indexOf("RESULT ") === 0; })[0];
      var parsed = null;
      if (line) { try { parsed = JSON.parse(line.slice("RESULT ".length)); } catch (_e) { parsed = null; } }
      resolve({ code: code, result: parsed, stderr: se.slice(0, 2000) });
    });
  });
}

async function _withAnchorChild(which) {
  var chain = anchors.decoyChain(which);
  var server = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (s) {
    s.on("error", function () { /* the client closed */ });
    s.end();
  });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  var file = nodePath.join(nodeOs.tmpdir(), "blamejs-default-anchor-" + which + "-" +
    nodeCrypto.randomBytes(6).toString("hex") + ".pem");
  nodeFs.writeFileSync(file, chain.anchor);
  try {
    return await _runChild(server.address().port, file);
  } finally {
    try { nodeFs.unlinkSync(file); } catch (_e) { /* already removed */ }
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testDefaultStoreAnchorWithACompromisedKey() {
  var bad = await _withAnchorChild("compromised");
  var ok = await _withAnchorChild("control");
  var r = bad.result;
  var c = ok.result;
  check("child processes report a result", r !== null && c !== null,
        JSON.stringify({ bad: bad.stderr, ok: ok.stderr }));
  if (r === null || c === null) return;

  check("premise: NODE_EXTRA_CA_CERTS puts the compromised anchor in Node's default store",
        r.defaultStoreHasAnchor === true, JSON.stringify(r));
  check("premise: a plain node dial verifies the leaf through the compromised anchor",
        r.plain.authorized === true, JSON.stringify(r.plain));
  check("premise control: a plain node dial verifies the control leaf through the control anchor",
        c.plain.authorized === true, JSON.stringify(c.plain));

  check("applyToContext role client: ca is the default store without the compromised anchor",
        r.clientCa.set === true && r.clientCa.hasAnchor === false && r.clientCa.length === r.bundledCount,
        JSON.stringify(r.clientCa));
  check("applyToContext role server with requestCert: ca is the default store without the compromised anchor",
        r.serverCa.set === true && r.serverCa.hasAnchor === false, JSON.stringify(r.serverCa));
  check("buildOptions: ca is the default store without the compromised anchor",
        r.builtCa.set === true && r.builtCa.hasAnchor === false, JSON.stringify(r.builtCa));
  check("control: with an ordinary anchor in the default store, no ca is set",
        c.clientCa.set === false && c.serverCa.set === false && c.builtCa.set === false && c.helperCa.set === false,
        JSON.stringify([c.clientCa, c.serverCa, c.builtCa, c.helperCa]));
  check("_clientTrustAnchors returns a configured ca unchanged", r.explicitCa === true && c.explicitCa === true);

  check("applyToContext with checkServerIdentity replaced: OpenSSL does not verify through the compromised anchor",
        r.applyToContextNoIdentity.authorized === false, JSON.stringify(r.applyToContextNoIdentity));
  check("buildOptions with checkServerIdentity replaced: OpenSSL does not verify through the compromised anchor",
        r.buildOptionsNoIdentity.authorized === false, JSON.stringify(r.buildOptionsNoIdentity));
  check("applyToContext: the dial is refused",
        r.applyToContext.authorized === false, JSON.stringify(r.applyToContext));
  check("control: applyToContext with checkServerIdentity replaced verifies through the control anchor",
        c.applyToContextNoIdentity.authorized === true, JSON.stringify(c.applyToContextNoIdentity));
  check("control: buildOptions with checkServerIdentity replaced verifies through the control anchor",
        c.buildOptionsNoIdentity.authorized === true, JSON.stringify(c.buildOptionsNoIdentity));
  check("control: applyToContext verifies through the control anchor",
        c.applyToContext.authorized === true, JSON.stringify(c.applyToContext));
}

// A TLS server that sends `chain` and answers each DNS-over-TLS query with one
// A record, 192.0.2.7.
function _dotServer(chain) {
  var server = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (s) {
    s.on("error", function () { /* the client closed */ });
    var acc = Buffer.alloc(0);
    s.on("data", function (chunk) {
      acc = Buffer.concat([acc, chunk]);
      if (acc.length < 2 || acc.length < acc.readUInt16BE(0) + 2) return;
      var q = acc.subarray(2, 2 + acc.readUInt16BE(0));
      acc = Buffer.alloc(0);
      var hdr = Buffer.from(q.subarray(0, 12));
      hdr.writeUInt16BE(0x8180, 2);
      hdr.writeUInt16BE(1, 6);
      var end = 12;
      while (q[end] !== 0) end += q[end] + 1;
      end += 5;
      var answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
      var reply = Buffer.concat([hdr, q.subarray(12, end), answer]);
      var len = Buffer.alloc(2);
      len.writeUInt16BE(reply.length, 0);
      s.write(Buffer.concat([len, reply]));
    });
  });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) { server.listen(0, "127.0.0.1", function () { resolve(server); }); });
}

function _tempPem(tag, pem) {
  var file = nodePath.join(nodeOs.tmpdir(), "blamejs-openssl-ca-" + tag + "-" +
    nodeCrypto.randomBytes(6).toString("hex") + ".pem");
  nodeFs.writeFileSync(file, pem);
  return file;
}

function _runOpenSslChild(port, env) {
  return new Promise(function (resolve) {
    var childEnv = Object.assign({}, process.env, env);
    delete childEnv.NODE_OPTIONS;
    if (env.NODE_EXTRA_CA_CERTS === undefined) delete childEnv.NODE_EXTRA_CA_CERTS;
    var child = nodeCp.spawn(process.execPath, ["--use-openssl-ca", __filename, "openssl-child", String(port)], {
      env: childEnv, stdio: ["ignore", "pipe", "pipe"],
    });
    var so = "";
    var se = "";
    child.stdout.on("data", function (d) { so += d; });
    child.stderr.on("data", function (d) { se += d; });
    child.on("close", function (code) {
      var line = so.split("\n").filter(function (l) { return l.indexOf("RESULT ") === 0; })[0];
      var parsed = null;
      if (line) { try { parsed = JSON.parse(line.slice("RESULT ".length)); } catch (_e) { parsed = null; } }
      resolve({ code: code, result: parsed, stderr: se.slice(0, 2000) });
    });
  });
}

// With --use-openssl-ca, Node trusts the OpenSSL store (SSL_CERT_FILE here)
// and only NODE_EXTRA_CA_CERTS appears in getCACertificates("default"). A
// compromised certificate in NODE_EXTRA_CA_CERTS does not make the family's
// dials replace the whole store: a server under an ordinary anchor in
// SSL_CERT_FILE still answers, as it does without the extra certificate. A
// compromised anchor in SSL_CERT_FILE is still refused after the handshake.
async function testOpenSslStoreIsKept() {
  var control = anchors.decoyChain("control");
  var bad = anchors.decoyChain("compromised");
  var files = {
    ordinary:    _tempPem("ordinary", control.anchor),
    compromised: _tempPem("compromised", bad.anchor),
    extra:       _tempPem("extra", ck.certPem(ck.P384_COMPROMISED_CA_DER)),
  };
  var controlServer = await _dotServer(control);
  var badServer = await _dotServer(bad);
  try {
    var withExtra = await _runOpenSslChild(controlServer.address().port,
      { SSL_CERT_FILE: files.ordinary, NODE_EXTRA_CA_CERTS: files.extra });
    var withoutExtra = await _runOpenSslChild(controlServer.address().port, { SSL_CERT_FILE: files.ordinary });
    var compromised = await _runOpenSslChild(badServer.address().port, { SSL_CERT_FILE: files.compromised });
    var r = withExtra.result;
    var c = withoutExtra.result;
    var x = compromised.result;
    check("--use-openssl-ca children report a result", r !== null && c !== null && x !== null,
          JSON.stringify([withExtra.stderr, withoutExtra.stderr, compromised.stderr]));
    if (r === null || c === null || x === null) return;
    check("--use-openssl-ca premise: Node alone verifies the server through the SSL_CERT_FILE anchor",
          r.plain.authorized === true && c.plain.authorized === true, JSON.stringify([r.plain, c.plain]));
    check("--use-openssl-ca premise: the compromised extra certificate is the only entry in the default store",
          r.defaultStoreSize === 1 && c.defaultStoreSize === 0, JSON.stringify([r.defaultStoreSize, c.defaultStoreSize]));
    check("--use-openssl-ca control: without the extra certificate, applyToContext and DoT reach the server",
          c.applyToContext.authorized === true && Array.isArray(c.dot.answer) && c.dot.answer[0] === "192.0.2.7",
          JSON.stringify(c));
    check("--use-openssl-ca: no replacement ca is built from the default store",
          r.replacementCa === false && c.replacementCa === false, JSON.stringify([r.replacementCa, c.replacementCa]));
    check("--use-openssl-ca: with a compromised NODE_EXTRA_CA_CERTS entry, applyToContext still reaches the server",
          r.applyToContext.authorized === true, JSON.stringify(r.applyToContext));
    check("--use-openssl-ca: with a compromised NODE_EXTRA_CA_CERTS entry, b.network.dns over DoT still answers",
          Array.isArray(r.dot.answer) && r.dot.answer[0] === "192.0.2.7", JSON.stringify(r.dot));
    check("--use-openssl-ca premise: Node alone verifies a leaf through a compromised SSL_CERT_FILE anchor",
          x.plain.authorized === true, JSON.stringify(x.plain));
    check("--use-openssl-ca: applyToContext refuses a leaf issued by a compromised SSL_CERT_FILE anchor",
          x.applyToContext.authorized === false && x.applyToContext.error === "tls/compromised-key",
          JSON.stringify(x.applyToContext));
    check("--use-openssl-ca: DoT refuses a server under a compromised SSL_CERT_FILE anchor",
          x.dot.answer === null && typeof x.dot.code === "string", JSON.stringify(x.dot));
  } finally {
    Object.keys(files).forEach(function (k) { try { nodeFs.unlinkSync(files[k]); } catch (_e) { /* removed */ } });
    await new Promise(function (resolve) { controlServer.close(function () { resolve(); }); });
    await new Promise(function (resolve) { badServer.close(function () { resolve(); }); });
  }
}

var TESTS = [testDefaultStoreAnchorWithACompromisedKey, testOpenSslStoreIsKept];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
