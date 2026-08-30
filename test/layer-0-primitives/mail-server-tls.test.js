// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var nodeTls = require("node:tls");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

async function _mintTestCert() {
  // Use the framework's mtls engine to mint a self-signed cert. The
  // CA shape (caCertPem + caKeyPem) is itself a valid self-signed pair
  // that node:tls.createSecureContext accepts.
  var ca = await b.mtlsEngine.generateCa({ generation: 1 });
  return { certPem: ca.caCertPem, keyPem: ca.caKeyPem };
}

function _mkTmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mail-tls-" + label + "-"));
}

function _writeFile(p, content) {
  fs.writeFileSync(p, content);
  return p;
}

async function run() {
  var modSurface = b.mail.server.tls;
  check("surface: context is fn",            typeof modSurface.context === "function");
  check("surface: MailServerTlsError class", typeof modSurface.MailServerTlsError === "function");
  check("surface: upgradeSocket is fn",       typeof modSurface.upgradeSocket === "function");
  check("surface: upgradeLineProtocol is fn", typeof modSurface.upgradeLineProtocol === "function");

  // ---- implicitTlsWrap: one option, not two code paths ----
  // A listener passes the mode straight through, so the plaintext-upgrade port
  // gets null and hands nothing to its accept path — rather than each listener
  // writing `implicitTls ? function (raw) {...} : null` for itself, which is
  // where a TLSSocket gets constructed with an inert compression option or
  // without isServer.
  check("implicitTlsWrap: off returns null, so a plaintext port wraps nothing",
    b.mail.server.tls.implicitTlsWrap({}, false) === null &&
    b.mail.server.tls.implicitTlsWrap({}, undefined) === null);
  var wrapFn = b.mail.server.tls.implicitTlsWrap({}, true);
  check("implicitTlsWrap: on returns the wrapper the accept path calls",
    typeof wrapFn === "function" && wrapFn.length === 1);

  // ---- upgradeLineProtocol: config-time validation (§8 entry-point) ----
  var ulpBad = [];
  try { modSurface.upgradeLineProtocol(); }              catch (e) { ulpBad.push(e); }
  try { modSurface.upgradeLineProtocol({}); }            catch (e) { ulpBad.push(e); }
  try { modSurface.upgradeLineProtocol({ state: {} }); } catch (e) { ulpBad.push(e); }
  check("upgradeLineProtocol throws on missing opts",  ulpBad[0] && /opts required/.test(ulpBad[0].message));
  check("upgradeLineProtocol throws on missing state", ulpBad[1] && /state/.test(ulpBad[1].message));
  check("upgradeLineProtocol throws on missing drain", ulpBad[2] && /drain/.test(ulpBad[2].message));

  // ---- upgradeLineProtocol: the STARTTLS-injection drain runs BEFORE the
  // upgrade (CVE-2021-33515 / CVE-2021-38371). With a non-socket the inner
  // upgradeSocket throws, but the pre-handshake state MUST already be wiped.
  var injState = {
    lineBuffer:     Buffer.from("A001 LOGIN pipelined-pre-handshake\r\n"),
    pendingLiteral: { bytes: 42 },
    authPending:    "half-sasl-token",
    tls:            false,
  };
  var injThrew = null;
  try {
    modSurface.upgradeLineProtocol({
      state:         injState,
      socket:        {},               // not a net.Socket → inner upgradeSocket throws
      secureContext: {},
      idleTimeoutMs: 1000,
      clearFields:   ["pendingLiteral", "authPending"],
      drain:         function () {},
      onError:       function () {},
    });
  } catch (e) { injThrew = e; }
  check("upgradeLineProtocol rejects a non-socket (via upgradeSocket)",
    injThrew && /plainSocket/.test(injThrew.message));
  check("injection drain: lineBuffer emptied even when the upgrade fails",
    injState.lineBuffer.length === 0);
  check("injection drain: clearFields[0] (pendingLiteral) nulled", injState.pendingLiteral === null);
  check("injection drain: clearFields[1] (authPending) nulled",    injState.authPending === null);

  // ---- happy path: plain PEM files load + return a SecureContext ----
  var tmp1 = _mkTmpDir("happy");
  try {
    var pair = await _mintTestCert();
    var certFile = _writeFile(path.join(tmp1, "cert.pem"), pair.certPem);
    var keyFile  = _writeFile(path.join(tmp1, "key.pem"),  pair.keyPem);
    var tlsCtx = b.mail.server.tls.context({ certFile: certFile, keyFile: keyFile });
    check("context: returns a handle with secureContext getter",
          tlsCtx && typeof tlsCtx.secureContext === "object" &&
          tlsCtx.secureContext !== null);
    check("context: reload is fn",        typeof tlsCtx.reload === "function");
    check("context: onReload is fn",      typeof tlsCtx.onReload === "function");
    check("context: stop is fn",          typeof tlsCtx.stop === "function");
    tlsCtx.stop();

    // The mail listener's TLS context has to carry the framework's PQC-first
    // key-agreement preference, the same as the HTTP listener does. It set no
    // group list at all, so the one place the framework's hybrid-KEM policy
    // most obviously belongs — the server that speaks STARTTLS to the public
    // internet — negotiated whatever the runtime happened to default to.
    var applied = b.mail.server.tls._contextOptionsForTest(
      { certFile: certFile, keyFile: keyFile });
    check("context: the framework's key-agreement groups reach the context",
          typeof applied.ecdhCurve === "string" && applied.ecdhCurve.length > 0,
          JSON.stringify(applied.ecdhCurve));

    // And an operator's own preference is HONOURED, not silently dropped. A
    // failed attempt to set a group policy has to be distinguishable from
    // success: the option used to be accepted and ignored, so a consumer
    // pinning a curve got no policy and no error.
    var pinned = b.mail.server.tls._contextOptionsForTest(
      { certFile: certFile, keyFile: keyFile, ecdhCurve: "X25519" });
    check("context: an operator-supplied ecdhCurve is honoured",
          pinned.ecdhCurve === "X25519", JSON.stringify(pinned.ecdhCurve));

    // A malformed one is REFUSED rather than replaced with the default —
    // quietly substituting would start a listener on groups the operator did
    // not choose, with nothing said.
    var badThrew = null;
    try {
      b.mail.server.tls._contextOptionsForTest(
        { certFile: certFile, keyFile: keyFile, ecdhCurve: 42 });
    } catch (e) { badThrew = e; }
    check("context: a malformed ecdhCurve is refused, not replaced",
          badThrew !== null, badThrew && badThrew.message);
  } finally {
    fs.rmSync(tmp1, { recursive: true, force: true });
  }

  // ---- a mismatched pair says WHICH files were compared ----
  //
  // This is a boot failure with the server refusing to start, and OpenSSL's
  // own text says what is wrong without saying where. On a host mid-renewal
  // there are several candidate files and usually a symlink, and this function
  // is the only thing that knows which pair it just tried.
  //
  // Two independently minted pairs, crossed — a real `key values mismatch`
  // from OpenSSL rather than a synthesised string, so the message being
  // matched is the one an operator actually sees.
  var tmpMix = _mkTmpDir("mismatch");
  try {
    var pairA = await _mintTestCert();
    var pairB = await _mintTestCert();
    var certA = _writeFile(path.join(tmpMix, "a-cert.pem"), pairA.certPem);
    var keyB  = _writeFile(path.join(tmpMix, "b-key.pem"),  pairB.keyPem);
    var mixErr = null;
    try { b.mail.server.tls.context({ certFile: certA, keyFile: keyB }); }
    catch (e) { mixErr = e; }
    check("context: a mismatched pair is refused",
      mixErr && mixErr.code === "mail-server-tls/secure-context-failed",
      String(mixErr && mixErr.code));
    check("context: and the refusal names the certificate file",
      mixErr && mixErr.message.indexOf(certA) !== -1,
      String(mixErr && mixErr.message).slice(0, 200));
    check("context: and names the key file",
      mixErr && mixErr.message.indexOf(keyB) !== -1,
      String(mixErr && mixErr.message).slice(0, 200));
    check("context: and keeps OpenSSL's own text rather than replacing it",
      mixErr && /key values mismatch/i.test(mixErr.message),
      String(mixErr && mixErr.message).slice(0, 200));
    check("context: and says in words what the operator has to fix",
      mixErr && /different issuances/.test(mixErr.message),
      String(mixErr && mixErr.message).slice(0, 200));
    // The private key must never reach a message because a certificate failed
    // to load — paths are the diagnostic, contents are not.
    check("context: and carries no key material",
      mixErr && mixErr.message.indexOf("PRIVATE KEY") === -1 &&
      mixErr.message.indexOf(pairB.keyPem.split("\n")[1] || "@@none@@") === -1,
      String(mixErr && mixErr.message).slice(0, 200));

    // A file that is not PEM at all. Only ONE path is named here, and that is
    // the point: when the framework knows which file is wrong it says which,
    // and it is only the mismatch above — where each file is fine and the pair
    // is not — that has to name both.
    var notPem = _writeFile(path.join(tmpMix, "not-pem.key"), "this is not a PEM file\n");
    var pemErr = null;
    try { b.mail.server.tls.context({ certFile: certA, keyFile: notPem }); }
    catch (e) { pemErr = e; }
    check("context: a file holding no PEM block is refused, naming that file",
      pemErr && pemErr.code === "mail-server-tls/pem-empty" &&
      pemErr.message.indexOf(notPem) !== -1,
      String(pemErr && (pemErr.code + " " + pemErr.message)).slice(0, 200));
    check("context: and says what that usually is",
      pemErr && /interrupted renewal/.test(pemErr.message),
      String(pemErr && pemErr.message).slice(0, 200));
    // An empty file is the same class and the same advice — an interrupted
    // renewal leaves exactly this, and OpenSSL reports it identically.
    var emptyKey = _writeFile(path.join(tmpMix, "empty.key"), "");
    var emptyErr = null;
    try { b.mail.server.tls.context({ certFile: certA, keyFile: emptyKey }); }
    catch (e) { emptyErr = e; }
    check("context: an empty key file is refused at startup, naming it",
      emptyErr && emptyErr.code === "mail-server-tls/pem-empty" &&
      emptyErr.message.indexOf(emptyKey) !== -1,
      String(emptyErr && (emptyErr.code + " " + emptyErr.message)).slice(0, 200));

    // The dangerous half: createSecureContext does NOT refuse an empty
    // certificate — a context without one is what a TLS client uses, and it is
    // perfectly legal. So the server used to start, advertise STARTTLS, and
    // fail every handshake at runtime, which is the same interrupted renewal
    // reported where it is hardest to trace.
    var emptyCert = _writeFile(path.join(tmpMix, "empty-cert.pem"), "");
    var emptyCertErr = null;
    try { b.mail.server.tls.context({ certFile: emptyCert, keyFile: keyB }); }
    catch (e) { emptyCertErr = e; }
    check("context: an empty certificate is refused rather than silently accepted",
      emptyCertErr && emptyCertErr.code === "mail-server-tls/pem-empty" &&
      emptyCertErr.message.indexOf(emptyCert) !== -1,
      String(emptyCertErr && (emptyCertErr.code + " " + emptyCertErr.message)).slice(0, 200));
  } finally {
    fs.rmSync(tmpMix, { recursive: true, force: true });
  }

  // ---- bad-input refusals ----
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label,
      threw && threw.code && threw.code.indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses missing opts",
    function () { b.mail.server.tls.context(); },
    "mail-server-tls/bad-opts");
  expectThrow("refuses missing certFile",
    function () { b.mail.server.tls.context({ keyFile: "/x" }); },
    "mail-server-tls/bad-cert-file");
  expectThrow("refuses missing keyFile",
    function () { b.mail.server.tls.context({ certFile: "/x" }); },
    "mail-server-tls/bad-key-file");
  expectThrow("refuses non-vault-shaped vault",
    function () { b.mail.server.tls.context({ certFile: "/x", keyFile: "/y", vault: {} }); },
    "mail-server-tls/bad-vault");
  expectThrow("refuses non-boolean watch",
    function () { b.mail.server.tls.context({ certFile: "/x", keyFile: "/y", watch: "yes" }); },
    "mail-server-tls/bad-watch");
  expectThrow("refuses pollMs below 1000",
    function () { b.mail.server.tls.context({ certFile: "/x", keyFile: "/y", pollMs: 100 }); },
    "mail-server-tls/bad-poll-ms");

  // ---- file-not-found surfaces typed error ----
  expectThrow("refuses unreadable certFile",
    function () { b.mail.server.tls.context({
      certFile: "/this/path/does/not/exist.pem",
      keyFile:  "/this/path/also/does/not/exist.pem",
    }); },
    "mail-server-tls/cert-unreadable");

  // ---- reload() rebuilds the context + fires onReload listeners ----
  var tmp3 = _mkTmpDir("reload");
  try {
    var pair1 = await _mintTestCert();
    var certFile3 = _writeFile(path.join(tmp3, "cert.pem"), pair1.certPem);
    var keyFile3  = _writeFile(path.join(tmp3, "key.pem"),  pair1.keyPem);
    var tlsCtx3 = b.mail.server.tls.context({ certFile: certFile3, keyFile: keyFile3 });
    var firstCtx = tlsCtx3.secureContext;
    var listenerCalls = 0;
    var lastSeenCtx = null;
    tlsCtx3.onReload(function (newCtx) { listenerCalls += 1; lastSeenCtx = newCtx; });

    // Simulate cert rotation — overwrite both files with a fresh pair
    var pair2 = await _mintTestCert();
    fs.writeFileSync(certFile3, pair2.certPem);
    fs.writeFileSync(keyFile3,  pair2.keyPem);
    var reloadedCtx = tlsCtx3.reload();

    check("reload: returns a fresh SecureContext",
      reloadedCtx && reloadedCtx !== firstCtx);
    check("reload: secureContext getter now returns the fresh one",
      tlsCtx3.secureContext === reloadedCtx);
    check("reload: fires onReload listeners",
      listenerCalls === 1);
    check("reload: listener receives the fresh context",
      lastSeenCtx === reloadedCtx);
    tlsCtx3.stop();
  } finally {
    fs.rmSync(tmp3, { recursive: true, force: true });
  }

  // ---- onReload rejects non-function ----
  var tmp4 = _mkTmpDir("badlistener");
  try {
    var pair4 = await _mintTestCert();
    var certFile4 = _writeFile(path.join(tmp4, "cert.pem"), pair4.certPem);
    var keyFile4  = _writeFile(path.join(tmp4, "key.pem"),  pair4.keyPem);
    var tlsCtx4 = b.mail.server.tls.context({ certFile: certFile4, keyFile: keyFile4 });
    var threw = null;
    try { tlsCtx4.onReload("not a fn"); } catch (e) { threw = e; }
    check("onReload: refuses non-function",
      threw && threw.code === "mail-server-tls/bad-listener");
    tlsCtx4.stop();
  } finally {
    fs.rmSync(tmp4, { recursive: true, force: true });
  }

  // ---- MX listener's no-tls-context error message points at this primitive ----
  var threwNoTls = null;
  try { b.mail.server.mx.create({ }); } catch (e) { threwNoTls = e; }
  check("MX no-tls-context error: points at b.mail.server.tls.context",
    threwNoTls && /b\.mail\.server\.tls\.context/.test(threwNoTls.message));
  check("MX no-tls-context error: points at b.acme for provisioning",
    threwNoTls && /b\.acme/.test(threwNoTls.message));
  await testServerContextAcceptsEveryRegisteredEcdheCurve();
  await testStarttlsUpgradeCompressesTheCertificateChain();
}

// The release advertises RFC 8879 certificate compression on every TLS
// connection the framework makes or accepts, and a mail listener builds its
// own secure context rather than handing options to tls.createServer.
//
// Assert the EFFECT, not the plumbing. The first version of this test checked
// that `certificateCompression` appeared in the options handed to TLSSocket —
// which it did, while doing nothing at all: a TLSSocket given a pre-built
// secureContext uses that context as-is and ignores context options passed
// beside it. The test passed and the feature did not work. Bytes on the wire
// cannot be fooled that way, so count them: a compressed chain is several
// times smaller than an uncompressed one.
// A listener's group list is an ACCEPT SET, not an offer order.
//
// The outbound preference is a flat colon-separated list, which is the right
// shape for a client: node sends a key share for the first entry and takes the
// first mutually-supported group. OpenSSL 3.5 reads that same flat string on a
// SERVER as the set of groups it will accept at all, and only tuples separated
// by `/` express order. Applying the client list to a listener therefore
// refused every registered curve it did not name — including secp256r1, which
// RFC 8446 §9.1 makes mandatory to implement — and on an SMTP listener a
// refused handshake is mail that stays queued until it bounces.
async function testServerContextAcceptsEveryRegisteredEcdheCurve() {
  // The client verifies the chain against the same self-signed pair the server
  // presents. Turning verification off would run this test with the
  // interesting half of the handshake switched off, and what is being asserted
  // — which group the two sides agree on — has to be reached under a verified
  // chain to mean anything.
  var pair = helpers.selfSignedPair();
  var dir = _mkTmpDir("groups");
  var certFile = _writeFile(path.join(dir, "cert.pem"), pair.cert);
  var keyFile  = _writeFile(path.join(dir, "key.pem"),  pair.key);

  // Wrapped the way the listeners wrap it — a net socket upgraded with the
  // built context — rather than handed to tls.createServer, which takes its
  // certificate from its own options and would not exercise the context this
  // primitive produces at all.
  var net = require("node:net");
  var built = b.mail.server.tls.context({ certFile: certFile, keyFile: keyFile });
  var srv = net.createServer(function (sock) {
    var t = new nodeTls.TLSSocket(sock, {
      isServer: true, secureContext: built.secureContext,
    });
    t.on("error", function () { /* client tears down after the handshake */ });
    t.on("secure", function () { try { t.end(); } catch (_e) { /* closing */ } });
  });
  await new Promise(function (r) { srv.listen(0, "127.0.0.1", r); });
  var port = srv.address().port;

  function handshake(curve) {
    return new Promise(function (resolve) {
      var c = nodeTls.connect({
        port: port, host: "127.0.0.1", servername: "localhost",
        ca: [pair.cert], ecdhCurve: curve,
      }, function () {
        var info = null;
        try { info = c.getEphemeralKeyInfo(); } catch (_e) { info = null; }
        try { c.destroy(); } catch (_e) { /* closing */ }
        resolve({ ok: true, group: (info && (info.name || info.type)) || null });
      });
      c.on("error", function (e) {
        resolve({ ok: false, err: (e && (e.code || e.message)) || "error" });
      });
    });
  }

  try {
    // Every curve RFC 8446 §4.2.7 registers for ECDHE. A listener that speaks
    // to strangers has no business refusing any of them.
    var registered = ["prime256v1", "secp384r1", "secp521r1", "X448", "X25519"];
    for (var i = 0; i < registered.length; i += 1) {
      var r = await handshake(registered[i]);
      check("mail tls: a server context accepts " + registered[i],
        r.ok === true, registered[i] + " -> " + JSON.stringify(r));
    }

    // And the PQC preference still wins where the peer offers one. Applying the
    // flat list actively lost this: a peer offering both was served X25519,
    // where a context with no list at all was pulled up to the hybrid by a
    // HelloRetryRequest.
    var hybrid = await handshake("X25519:X25519MLKEM768");
    check("mail tls: a peer offering the hybrid still negotiates the hybrid",
      hybrid.ok === true && /MLKEM/i.test(String(hybrid.group || "")),
      JSON.stringify(hybrid));

    // The hybrid the runtime's own server default refuses is still accepted,
    // which is what applying a list at all is for.
    var p256Hybrid = await handshake("SecP256r1MLKEM768");
    check("mail tls: SecP256r1MLKEM768 is accepted, which the runtime default refuses",
      p256Hybrid.ok === true, JSON.stringify(p256Hybrid));
  } finally {
    await new Promise(function (r) { srv.close(r); });
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function testStarttlsUpgradeCompressesTheCertificateChain() {
  var nodeTls = require("node:tls");
  var net = require("node:net");
  var expected = b.constants.TLS_CERT_COMPRESSION();
  if (expected.length === 0) {
    check("runtime without RFC 8879 support — nothing to assert", true);
    return;
  }
  var pair = helpers.selfSignedPair();
  // Repeat the certificate so the chain is big enough for the difference to
  // be unambiguous rather than lost in handshake overhead.
  var fatCert = new Array(24).join(pair.cert) + pair.cert;

  // Measure the server->client handshake bytes through a counting relay, so
  // the number is read off a socket the test owns.
  async function handshakeBytes(ctx) {
    // Every socket this opens is tracked and destroyed at the end. server.close()
    // stops the listener ACCEPTING; it does not touch connections already
    // established, so the relay's two sockets and the upgraded server socket
    // outlived each measurement and kept the event loop alive — the file
    // printed its OK line and then never exited.
    var open = [];
    var srv = net.createServer(function (sock) {
      open.push(sock);
      var t = new nodeTls.TLSSocket(sock, { isServer: true, secureContext: ctx });
      open.push(t);
      t.on("error", function () { /* client tears down after the handshake */ });
    });
    await new Promise(function (r) { srv.listen(0, "127.0.0.1", r); });
    var seen = 0;
    var relay = net.createServer(function (down) {
      open.push(down);
      var up = net.connect({ host: "127.0.0.1", port: srv.address().port });
      open.push(up);
      up.on("data", function (c) { seen += c.length; down.write(c); });
      down.on("data", function (c) { up.write(c); });
      up.on("error", function () {}); down.on("error", function () {});
    });
    await new Promise(function (r) { relay.listen(0, "127.0.0.1", r); });
    // A FAILED handshake also writes bytes, so resolving on 'error' would let
    // this measure a broken connection and still return a number — the two
    // measurements would then be compared against each other meaninglessly.
    // Require the handshake to have completed.
    var completed = false;
    var failure = null;
    await new Promise(function (resolve) {
      var c = nodeTls.connect({
        host: "127.0.0.1", port: relay.address().port, servername: "localhost",
        ca: [pair.cert], certificateCompression: expected,
      });
      c.on("secureConnect", function () { completed = true; c.destroy(); resolve(); });
      c.on("error", function (e) { failure = (e && e.message) || String(e); resolve(); });
    });
    await helpers.waitUntil(function () { return seen > 0; },
      { timeoutMs: 5000, label: "mail-server-tls: handshake bytes observed" });
    relay.close(); srv.close();
    open.forEach(function (s) { try { s.destroy(); } catch (_e) { /* already gone */ } });
    if (!completed) {
      throw new Error("mail-server-tls: handshake did not complete, so its byte " +
                      "count means nothing" + (failure ? " (" + failure + ")" : ""));
    }
    return seen;
  }

  var plainCtx = nodeTls.createSecureContext({ cert: fatCert, key: pair.key });
  var uncompressed = await handshakeBytes(plainCtx);

  // The context the framework builds, via the shipped primitive.
  var fs2 = require("node:fs");
  var os2 = require("node:os");
  var path2 = require("node:path");
  var dir = fs2.mkdtempSync(path2.join(os2.tmpdir(), "mailtls-"));
  var certFile = path2.join(dir, "cert.pem");
  var keyFile = path2.join(dir, "key.pem");
  fs2.writeFileSync(certFile, fatCert);
  fs2.writeFileSync(keyFile, pair.key);
  // context() returns a handle that owns the SecureContext plus its reload
  // machinery; the socket wants the context itself.
  var handle = b.mail.server.tls.context({ certFile: certFile, keyFile: keyFile });
  var compressed = await handshakeBytes(handle.secureContext);
  if (handle && typeof handle.stop === "function") {
    try { handle.stop(); } catch (_e) { /* best-effort */ }
  }
  try { fs2.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }

  check("the mail secure context compresses the certificate chain on the wire " +
        "(" + compressed + " bytes vs " + uncompressed + " uncompressed)",
    compressed > 0 && uncompressed > 0 && compressed < uncompressed * 0.9);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-tls] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
