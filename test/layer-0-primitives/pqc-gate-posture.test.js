// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.pqcGate in front of a real TLS listener built from the live
 * b.network.tls posture. A connection the gate passes must negotiate a
 * post-quantum group with the listener; one that would negotiate a classical
 * group must be refused at the gate.
 *
 * Run standalone: `node test/layer-0-primitives/pqc-gate-posture.test.js`
 */

var fs      = require("node:fs");
var net     = require("node:net");
var os      = require("node:os");
var path    = require("node:path");
var nodeTls = require("node:tls");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

async function _startTlsBackend(backendOpts) {
  var backend = nodeTls.createServer(backendOpts, function (sock) {
    sock.on("error", function () { /* client hang-up */ });
    sock.end("ok");
  });
  backend.on("tlsClientError", function () { /* a refused client */ });
  await new Promise(function (r) { backend.listen(0, "127.0.0.1", r); });
  return backend;
}

// Stand up listener + gate, dial the gate with `clientCurves`, and report what
// happened. The listener is `listener.startBackend(pair)` when given, a
// node:tls server on `listener.backendOpts(pair)` when that is given, and
// otherwise a node:tls server on `listener.backendCurves` or the current
// posture; `listener.groups` is passed to the gate, and the client trusts
// `listener.clientCa` when given and dials with `listener.clientMinVersion`
// (default TLSv1.3). A gate that refuses its configuration is reported as
// `threw`.
async function _dialThroughGate(clientCurves, listener) {
  listener = listener || {};
  var pair = helpers.selfSignedPair();
  var backend;
  if (typeof listener.startBackend === "function") {
    backend = await listener.startBackend(pair);
  } else {
    backend = await _startTlsBackend(typeof listener.backendOpts === "function"
      ? listener.backendOpts(pair)
      : {
        key: pair.key, cert: pair.cert, minVersion: "TLSv1.3",
        ecdhCurve: listener.backendCurves || b.network.tls.serverKeyAgreementGroups(),
      });
  }
  var gateOpts = { internalPort: backend.address().port, bypass: [], log: { warn: function () {} } };
  var groups = typeof listener.groups === "function" ? listener.groups(backend) : listener.groups;
  if (groups !== undefined) gateOpts.groups = groups;
  var gate;
  try { gate = b.pqcGate.create(gateOpts); }
  catch (e) {
    backend.close();
    return { connected: false, info: null, error: null, threw: e };
  }
  await new Promise(function (r) { gate.listen(0, "127.0.0.1", r); });

  var outcome = { connected: false, info: null, error: null, threw: null };
  try {
    await new Promise(function (resolve) {
      var sock = nodeTls.connect({
        host: "127.0.0.1", port: gate.address().port, servername: "localhost",
        ca: [listener.clientCa || pair.cert], ecdhCurve: clientCurves,
        minVersion: listener.clientMinVersion || "TLSv1.3",
      }, function () {
        outcome.connected = true;
        outcome.info = sock.getEphemeralKeyInfo();
        sock.end();
        resolve();
      });
      sock.on("error", function (e) { outcome.error = e; resolve(); });
      sock.on("close", function () { resolve(); });
    });
  } finally {
    gate.close();
    backend.close();
  }
  return outcome;
}

async function testGateMatchesTheListener() {
  try {
    b.network.tls.preferredGroups.reset();
    var defaultMixed = await _dialThroughGate("MLKEM1024:X25519");
    check("default posture: MLKEM1024:X25519 never negotiates classical through the gate",
          !defaultMixed.connected || (defaultMixed.info && defaultMixed.info.type === "TLSGroup"),
          JSON.stringify(defaultMixed.info));
    var defaultHybrid = await _dialThroughGate("X25519MLKEM768");
    check("default posture: an X25519MLKEM768 client is passed and negotiates it",
          defaultHybrid.connected && defaultHybrid.info && defaultHybrid.info.name === "X25519MLKEM768",
          (defaultHybrid.error && defaultHybrid.error.message) || JSON.stringify(defaultHybrid.info));

    b.network.tls.preferredGroups.set(["X25519MLKEM768", "X25519"]);
    var narrowed = await _dialThroughGate("SecP384r1MLKEM1024:X25519");
    check("narrowed posture: SecP384r1MLKEM1024:X25519 is refused rather than negotiating X25519",
          !narrowed.connected || (narrowed.info && narrowed.info.type === "TLSGroup"),
          JSON.stringify(narrowed.info));

    b.network.tls.preferredGroups.set(["MLKEM1024", "X25519MLKEM768"]);
    var pure = await _dialThroughGate("MLKEM1024");
    check("posture listing MLKEM1024: an MLKEM1024-only client is passed and negotiates it",
          pure.connected && pure.info && pure.info.name === "MLKEM1024",
          (pure.error && pure.error.message) || JSON.stringify(pure.info));

    // The listener picks from its first tuple that shares a group with the
    // client, so a classical tuple ahead of the post-quantum one wins for a
    // client offering both.
    b.network.tls.preferredGroups.set(["X25519", "X25519MLKEM768"]);
    var classicalTupleFirst = await _dialThroughGate("X25519MLKEM768:X25519");
    check("posture with a classical tuple first: a client offering both is refused rather than negotiating X25519",
          !classicalTupleFirst.connected ||
            (classicalTupleFirst.info && classicalTupleFirst.info.type === "TLSGroup"),
          JSON.stringify(classicalTupleFirst.info));
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// A listener configured with an explicit OpenSSL group string. Within one
// colon-separated tuple the client's key share decides, so a flat list that
// mixes a classical group with a post-quantum one cannot be gated.
async function testExplicitGroupsMatchTheListener() {
  var flat = await _dialThroughGate("X25519:X25519MLKEM768",
    { backendCurves: "X25519MLKEM768:X25519", groups: "X25519MLKEM768:X25519" });
  check("flat listener groups: create() refuses them with TypeError",
        flat.threw instanceof TypeError,
        flat.threw ? flat.threw.message : JSON.stringify(flat.info));
  check("flat listener groups: a classical-first client never negotiates X25519 through the gate",
        !flat.connected || (flat.info && flat.info.type === "TLSGroup"),
        JSON.stringify(flat.info));

  var tupled = await _dialThroughGate("X25519:X25519MLKEM768",
    { backendCurves: "X25519MLKEM768/X25519", groups: "X25519MLKEM768/X25519" });
  check("tuple listener groups: a classical-first client is passed and negotiates X25519MLKEM768",
        tupled.connected && tupled.info && tupled.info.name === "X25519MLKEM768",
        (tupled.threw && tupled.threw.message) || (tupled.error && tupled.error.message) ||
          JSON.stringify(tupled.info));

  var prefixed = await _dialThroughGate("X25519MLKEM768",
    { backendCurves: "*X25519MLKEM768/X25519", groups: "*X25519MLKEM768/X25519" });
  check("listener groups with an OpenSSL key-share prefix: the prefixed group is counted",
        prefixed.connected && prefixed.info && prefixed.info.name === "X25519MLKEM768",
        (prefixed.threw && prefixed.threw.message) || (prefixed.error && prefixed.error.message) ||
          JSON.stringify(prefixed.info));
}

function _negotiatedPqc(outcome) {
  return !!(outcome.info && Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, outcome.info.name));
}

function _describe(outcome) {
  return (outcome.threw && outcome.threw.message) || (outcome.error && outcome.error.message) ||
    JSON.stringify(outcome.info);
}

// Each client lists a classical group first and sends its key share, then one
// post-quantum group the default gate counts. A listener whose groups are one
// flat list takes the client's key share, so it negotiates X25519.
var CLASSICAL_FIRST_CLIENTS = [
  "X25519:X25519MLKEM768",
  "X25519:SecP256r1MLKEM768",
  "X25519:SecP384r1MLKEM1024",
  "secp256r1:SecP384r1MLKEM1024",
];

async function _assertListenerGated(label, listener) {
  for (var i = 0; i < CLASSICAL_FIRST_CLIENTS.length; i++) {
    var outcome = await _dialThroughGate(CLASSICAL_FIRST_CLIENTS[i], listener);
    check(label + ": a " + CLASSICAL_FIRST_CLIENTS[i] + " client negotiates a post-quantum group through the default gate",
          outcome.connected && _negotiatedPqc(outcome), _describe(outcome));
  }
  var classicalOnly = await _dialThroughGate("X25519", listener);
  check(label + ": an X25519-only client is refused at the gate",
        !classicalOnly.connected, _describe(classicalOnly));
}

async function testFrameworkBuiltListenersAreGated() {
  try {
    b.network.tls.preferredGroups.reset();
    await _assertListenerGated("applyToContext listener", {
      backendOpts: function (pair) {
        return b.network.tls.applyToContext({ base: { key: pair.key, cert: pair.cert, minVersion: "TLSv1.3" } });
      },
    });
    await _assertListenerGated("applyToContext listener with role server", {
      backendOpts: function (pair) {
        return b.network.tls.applyToContext({
          base: { key: pair.key, cert: pair.cert, minVersion: "TLSv1.3" }, role: "server",
        });
      },
    });
    b.network.tls.preferredGroups.set(["X25519MLKEM768", "SecP384r1MLKEM1024", "X25519"]);
    var narrowed = await _dialThroughGate("X25519:SecP384r1MLKEM1024", {
      backendOpts: function (pair) {
        return b.network.tls.applyToContext({ base: { key: pair.key, cert: pair.cert, minVersion: "TLSv1.3" } });
      },
    });
    check("applyToContext listener under a narrowed posture: a classical-first client negotiates SecP384r1MLKEM1024",
          narrowed.connected && narrowed.info && narrowed.info.name === "SecP384r1MLKEM1024", _describe(narrowed));
    b.network.tls.preferredGroups.reset();

    var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-gate-mail-tls-"));
    var mailTls = null;
    try {
      var pair = helpers.selfSignedPair();
      fs.writeFileSync(path.join(dir, "cert.pem"), pair.cert);
      fs.writeFileSync(path.join(dir, "key.pem"), pair.key);
      mailTls = b.mail.server.tls.context({
        certFile: path.join(dir, "cert.pem"), keyFile: path.join(dir, "key.pem"),
      });
      var mailCtx = mailTls.secureContext;
      // The mail listeners wrap the accepted socket the same way.
      var mailOutcome = await _dialThroughGate("X25519:SecP256r1MLKEM768", {
        startBackend: async function () {
          var server = net.createServer(function (raw) {
            var tlsSock = new nodeTls.TLSSocket(raw, { isServer: true, secureContext: mailCtx });
            tlsSock.on("error", function () { /* a refused client */ });
            tlsSock.on("secure", function () { tlsSock.end("ok"); });
          });
          await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
          return server;
        },
        clientCa: pair.cert,
      });
      check("b.mail.server.tls.context listener: a classical-first client negotiates a post-quantum group",
            mailOutcome.connected && _negotiatedPqc(mailOutcome), _describe(mailOutcome));
    } finally {
      if (mailTls) mailTls.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// A b.router TLS listener on `tlsOptions(pair)` (default: the pair alone).
function _routerBackend(tlsOptions) {
  return async function (pair) {
    var r = b.router.create();
    r.get("/", function (req, res) { res.json({ ok: 1 }); });
    var opts = typeof tlsOptions === "function" ? tlsOptions(pair) : { key: pair.key, cert: pair.cert };
    var server = await new Promise(function (resolve) {
      var s = r.listen(0, function () { resolve(s); }, opts, "127.0.0.1");
    });
    server.on("tlsClientError", function () { /* a refused client */ });
    return server;
  };
}

// Dial a listener `startBackend(pair)` builds directly, with no gate in front.
// `clientExtra` overrides the client's TLS options (default minVersion TLSv1.3).
async function _dialDirect(clientCurves, startBackend, clientExtra) {
  var pair = helpers.selfSignedPair();
  var backend = await startBackend(pair);
  var outcome = { connected: false, info: null, protocol: null, error: null, threw: null };
  try {
    await new Promise(function (resolve) {
      var sock = nodeTls.connect(Object.assign({
        host: "127.0.0.1", port: backend.address().port, servername: "localhost",
        ca: [pair.cert], ecdhCurve: clientCurves, minVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"],
      }, clientExtra || {}), function () {
        outcome.connected = true;
        outcome.info = sock.getEphemeralKeyInfo();
        outcome.protocol = sock.getProtocol();
        sock.destroy();
        resolve();
      });
      sock.on("error", function (e) { outcome.error = e; resolve(); });
      sock.on("close", function () { resolve(); });
    });
  } finally {
    backend.close();
  }
  return outcome;
}

// b.router builds its TLS listener itself, from the operator's tlsOptions.
async function testRouterListenerIsGated() {
  try {
    b.network.tls.preferredGroups.reset();
    await _assertListenerGated("b.router TLS listener", { startBackend: _routerBackend() });

    // An SNICallback context carries no groups of its own; the listener's
    // initial context decides.
    var sniCalls = 0;
    await _assertListenerGated("b.router TLS listener with an SNICallback", {
      startBackend: _routerBackend(function (pair) {
        var sniCtx = nodeTls.createSecureContext({ key: pair.key, cert: pair.cert });
        return {
          key: pair.key, cert: pair.cert,
          SNICallback: function (name, cb) { sniCalls += 1; cb(null, sniCtx); },
        };
      }),
    });
    check("b.router TLS listener with an SNICallback: the callback ran for every client the gate passed",
          sniCalls === CLASSICAL_FIRST_CLIENTS.length, "SNICallback calls: " + sniCalls);

    var own = await _dialDirect("X25519MLKEM768:X25519", _routerBackend(function (pair) {
      return { key: pair.key, cert: pair.cert, ecdhCurve: "X25519" };
    }));
    check("b.router TLS listener keeps an operator ecdhCurve: an X25519-only listener negotiates X25519",
          own.connected && own.info && own.info.name === "X25519", _describe(own));
    var unset = await _dialDirect("X25519:SecP256r1MLKEM768", _routerBackend(function (pair) {
      return { key: pair.key, cert: pair.cert, ecdhCurve: undefined };
    }));
    check("b.router TLS listener given ecdhCurve: undefined writes the server groups",
          unset.connected && unset.info && unset.info.name === "SecP256r1MLKEM768", _describe(unset));

    b.network.tls.preferredGroups.set(["SecP384r1MLKEM1024"]);
    var narrowed = await _dialDirect("SecP384r1MLKEM1024", _routerBackend());
    check("b.router TLS listener under a SecP384r1MLKEM1024-only posture accepts a client offering only that group",
          narrowed.connected && narrowed.info && narrowed.info.name === "SecP384r1MLKEM1024", _describe(narrowed));
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// A b.router TLS listener given its own tlsOptions.ecdhCurve negotiates from
// that string, which the default gate does not read. The listener reports the
// string it set as server.keyAgreementGroups, and a gate built with it as
// `groups` refuses a client the listener would answer with a classical group.
async function testRouterOwnEcdhCurveGatedThroughItsGroups() {
  try {
    b.network.tls.preferredGroups.reset();
    var fromServer = function (backend) { return backend.keyAgreementGroups; };
    var pqFirst = _routerBackend(function (pair) {
      return { key: pair.key, cert: pair.cert, ecdhCurve: "MLKEM1024/X25519" };
    });
    var pqFirstOutcome = await _dialThroughGate("X25519:X25519MLKEM768", { startBackend: pqFirst, groups: fromServer });
    check("b.router listener on MLKEM1024/X25519 behind a gate given its keyAgreementGroups: " +
          "an X25519:X25519MLKEM768 client is refused rather than negotiating X25519",
          !pqFirstOutcome.connected && pqFirstOutcome.threw === null, _describe(pqFirstOutcome));
    var pqFirstPq = await _dialThroughGate("X25519:MLKEM1024", { startBackend: pqFirst, groups: fromServer });
    check("b.router listener on MLKEM1024/X25519 behind a gate given its keyAgreementGroups: " +
          "an X25519:MLKEM1024 client negotiates MLKEM1024",
          pqFirstPq.connected && pqFirstPq.info && pqFirstPq.info.name === "MLKEM1024", _describe(pqFirstPq));

    var classicalFirst = _routerBackend(function (pair) {
      return { key: pair.key, cert: pair.cert, ecdhCurve: "X25519:X25519MLKEM768" };
    });
    var classicalOutcome = await _dialThroughGate("X25519:X25519MLKEM768",
      { startBackend: classicalFirst, groups: fromServer });
    check("b.router listener on X25519:X25519MLKEM768 behind a gate given its keyAgreementGroups: " +
          "the gate refuses the configuration rather than passing a client that negotiates X25519",
          classicalOutcome.threw instanceof TypeError && !classicalOutcome.connected, _describe(classicalOutcome));

    var defaultOutcome = await _dialThroughGate("X25519:X25519MLKEM768",
      { startBackend: _routerBackend(), groups: fromServer });
    check("default b.router listener behind a gate given its keyAgreementGroups: " +
          "an X25519:X25519MLKEM768 client negotiates a post-quantum group",
          defaultOutcome.connected && _negotiatedPqc(defaultOutcome), _describe(defaultOutcome));

    var pair = helpers.selfSignedPair();
    var tlsServer = await _routerBackend()(pair);
    var ownServer = await _routerBackend(function (p) {
      return { key: p.key, cert: p.cert, ecdhCurve: "MLKEM1024/X25519" };
    })(pair);
    var plainRouter = b.router.create();
    var plainServer = await new Promise(function (resolve) {
      var s = plainRouter.listen(0, function () { resolve(s); }, undefined, "127.0.0.1");
    });
    var reassigned = null;
    try { tlsServer.keyAgreementGroups = "X25519"; } catch (e) { reassigned = e; }
    try {
      check("a default b.router TLS listener reports the server groups it set",
            tlsServer.keyAgreementGroups === b.network.tls.serverKeyAgreementGroups(),
            String(tlsServer.keyAgreementGroups));
      check("a b.router TLS listener given an ecdhCurve reports that string",
            ownServer.keyAgreementGroups === "MLKEM1024/X25519", String(ownServer.keyAgreementGroups));
      check("server.keyAgreementGroups is read-only",
            reassigned instanceof TypeError && tlsServer.keyAgreementGroups === b.network.tls.serverKeyAgreementGroups(),
            String(tlsServer.keyAgreementGroups));
      check("a b.router HTTP listener reports keyAgreementGroups as null",
            plainServer.keyAgreementGroups === null, String(plainServer.keyAgreementGroups));
    } finally {
      tlsServer.close(); ownServer.close(); plainServer.close();
    }
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// Call b.router's listen() with `tlsOptions` and report whether it threw.
// A listener that did start is closed straight away.
function _routerListenThrows(tlsOptions) {
  var r = b.router.create();
  r.get("/", function (req, res) { res.json({ ok: 1 }); });
  try {
    var s = r.listen(0, function () { s.close(); }, tlsOptions, "127.0.0.1");
    s.on("error", function () { /* bind failure is not under test */ });
    return null;
  } catch (e) {
    return e;
  }
}

// An internalHost written as a bracketed IPv6 literal ("[::1]") reaches the
// internal listener, as the bare form does. A loopback client is in the
// default bypass list, so the gate pipes it to the listener without reading
// a ClientHello.
async function testInternalHostBracketedIpv6() {
  var backend = net.createServer(function (sock) {
    sock.on("error", function () { /* client hang-up */ });
    sock.end("ok");
  });
  var listenErr = await new Promise(function (r) {
    backend.once("error", r);
    backend.listen(0, "::1", function () { r(null); });
  });
  if (listenErr) {
    helpers.unavailable("pqcGate internalHost [::1]", "cannot listen on ::1: " + listenErr.code);
    return;
  }
  try {
    var hosts = [["bare", "::1"], ["bracketed", "[::1]"]];
    for (var i = 0; i < hosts.length; i += 1) {
      var gate = b.pqcGate.create({ internalPort: backend.address().port, internalHost: hosts[i][1] });
      await new Promise(function (r) { gate.listen(0, "127.0.0.1", r); });
      var got = await new Promise(function (resolve) {
        var data = "";
        var c = net.connect({ host: "127.0.0.1", port: gate.address().port });
        c.setEncoding("utf8");
        c.on("data", function (d) { data += d; });
        c.on("error", function () { /* reported through the data read */ });
        c.on("close", function () { resolve(data); });
      });
      await new Promise(function (r) { gate.close(function () { r(); }); });
      check("b.pqcGate pipes to a " + hosts[i][0] + " IPv6 internalHost (" + hosts[i][1] + ")",
        got === "ok", JSON.stringify(got));
    }
  } finally {
    backend.close();
  }
}

// A bypass entry names a peer, so every spelling of that peer is bypassed:
// a dual-stack gate on :: reports the IPv4 client 127.0.0.1 as
// ::ffff:127.0.0.1, and an entry written ::ffff:7f00:1 names 127.0.0.1.
async function testBypassMatchesEverySpellingOfThePeer() {
  var backend = net.createServer(function (sock) {
    sock.on("error", function () { /* client hang-up */ });
    sock.end("ok");
  });
  await new Promise(function (r) { backend.listen(0, "127.0.0.1", r); });
  function _dial(gate) {
    return new Promise(function (resolve) {
      var data = "";
      var c = net.connect({ host: "127.0.0.1", port: gate.address().port });
      c.setEncoding("utf8");
      c.on("data", function (d) { data += d; });
      c.on("error", function () { /* reported through the data read */ });
      c.on("close", function () { resolve(data); });
    });
  }
  try {
    var cases = [
      ["::ffff:7f00:1", "127.0.0.1"],
      ["::FFFF:127.0.0.1", "127.0.0.1"],
      ["127.0.0.1", "::"],
      ["127.0.0.0/8", "127.0.0.1"],
      ["127.0.0.0/8", "::"],
      ["::ffff:127.0.0.0/104", "127.0.0.1"],
    ];
    for (var i = 0; i < cases.length; i += 1) {
      var gate = b.pqcGate.create({
        internalPort: backend.address().port, bypass: [cases[i][0]],
        clientHelloTimeoutMs: 300, log: { warn: function () {} },
      });
      var listenErr = await new Promise(function (r) {
        gate.once("error", r);
        gate.listen(0, cases[i][1], function () { r(null); });
      });
      if (listenErr) {
        helpers.unavailable("pqcGate bypass on " + cases[i][1], "cannot listen: " + listenErr.code);
        continue;
      }
      var got = await _dial(gate);
      await new Promise(function (r) { gate.close(function () { r(); }); });
      check("b.pqcGate bypass " + JSON.stringify(cases[i][0]) + " pipes the client 127.0.0.1 on a " +
        cases[i][1] + " listener", got === "ok", JSON.stringify(got));
    }
    var outside = b.pqcGate.create({
      internalPort: backend.address().port, bypass: ["10.0.0.0/8"],
      clientHelloTimeoutMs: 300, log: { warn: function () {} },
    });
    await new Promise(function (r) { outside.listen(0, "127.0.0.1", r); });
    var notBypassed = await _dial(outside);
    await new Promise(function (r) { outside.close(function () { r(); }); });
    check("b.pqcGate bypass [\"10.0.0.0/8\"] does not pipe the client 127.0.0.1",
      notBypassed === "", JSON.stringify(notBypassed));
  } finally {
    backend.close();
  }
}

// A bypass entry that is not an IP address or a CIDR never matched a peer,
// so the gate ran the check on the peers the operator meant to exempt, and a
// bypass that was not an array was replaced by the default loopback list.
function testBypassRefusesEntriesThatAreNotAddresses() {
  var badEntries = ["localhost", "example.com", "", 5, null, "10.0.0.0/33", "10.0.0/8",
    "010.0.0.0/8", "10.0.0.0/8x", "::/129", "[127.0.0.1]"];
  for (var i = 0; i < badEntries.length; i += 1) {
    var err = null;
    try { b.pqcGate.create({ internalPort: 8443, bypass: [badEntries[i]] }); } catch (e) { err = e; }
    check("b.pqcGate.create refuses the bypass entry " + JSON.stringify(badEntries[i]),
      err instanceof TypeError && /bypass/.test(err.message), err ? err.message : "no throw");
  }
  var badLists = ["127.0.0.1", {}, 5];
  for (var j = 0; j < badLists.length; j += 1) {
    var lErr = null;
    try { b.pqcGate.create({ internalPort: 8443, bypass: badLists[j] }); } catch (e) { lErr = e; }
    check("b.pqcGate.create refuses bypass " + JSON.stringify(badLists[j]) + " (not an array)",
      lErr instanceof TypeError && /bypass/.test(lErr.message), lErr ? lErr.message : "no throw");
  }
  var good = [undefined, null, [], ["10.0.0.5"], ["10.0.0.0/8", "::1", "[::1]", "fd00::/8"]];
  for (var k = 0; k < good.length; k += 1) {
    var gErr = null;
    try { b.pqcGate.create({ internalPort: 8443, bypass: good[k] }); } catch (e) { gErr = e; }
    check("b.pqcGate.create accepts bypass " + JSON.stringify(good[k]), gErr === null, gErr && gErr.message);
  }
}

// An internalHost that is not a string, is empty, or brackets anything but
// an IPv6 address throws at create(). Dialing "" or "[]" connects to
// localhost, so the gate would proxy a typo to whatever listens there.
function testInternalHostRefusesBadValues() {
  var bad = [5, true, {}, "", "[]", "[localhost]", "[127.0.0.1]", "[::1", "::1]"];
  for (var i = 0; i < bad.length; i += 1) {
    var err = null;
    try { b.pqcGate.create({ internalPort: 8443, internalHost: bad[i] }); } catch (e) { err = e; }
    check("b.pqcGate.create refuses internalHost " + JSON.stringify(bad[i]),
      err !== null && /internalHost/.test(err.message), err ? err.message : "no throw");
  }
  var good = [undefined, null, "127.0.0.1", "localhost", "::1", "[::1]", "[fe80::1]"];
  for (var j = 0; j < good.length; j += 1) {
    var gErr = null;
    try { b.pqcGate.create({ internalPort: 8443, internalHost: good[j] }); } catch (e) { gErr = e; }
    check("b.pqcGate.create accepts internalHost " + JSON.stringify(good[j]), gErr === null, gErr && gErr.message);
  }
}

// The version and group cases the b.router.create block describes.
async function testRouterListenerVersionAndGroupEdges() {
  var TLS12_CLIENT = { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" };
  try {
    b.network.tls.preferredGroups.reset();
    var ffdheOnly = await _dialDirect("ffdhe2048", _routerBackend());
    check("b.router TLS listener refuses a TLS 1.3 client that offers only ffdhe2048",
          !ffdheOnly.connected, _describe(ffdheOnly));
    var ffdheControl = await _dialDirect("ffdhe2048", _routerBackend(function (pair) {
      return { key: pair.key, cert: pair.cert, ecdhCurve: "X25519:ffdhe2048" };
    }));
    check("control: the same ffdhe2048 client connects to a listener whose ecdhCurve names ffdhe2048",
          ffdheControl.connected && ffdheControl.info && ffdheControl.info.type === "DH" &&
            ffdheControl.info.size === 2048, _describe(ffdheControl));

    var tls12 = await _dialDirect("X25519:secp256r1", _routerBackend(function (pair) {
      return { key: pair.key, cert: pair.cert, minVersion: "TLSv1.2" };
    }), TLS12_CLIENT);
    check("b.router TLS listener with minVersion TLSv1.2 negotiates TLS 1.2 with classical ECDHE",
          tls12.connected && tls12.protocol === "TLSv1.2" && !_negotiatedPqc(tls12),
          tls12.protocol + " " + _describe(tls12));

    var maxOnly = await _dialDirect("X25519:secp256r1", _routerBackend(function (pair) {
      return { key: pair.key, cert: pair.cert, maxVersion: "TLSv1.2" };
    }), TLS12_CLIENT);
    check("b.router TLS listener with maxVersion TLSv1.2 and no minVersion completes no handshake",
          !maxOnly.connected, _describe(maxOnly));

    var pair = helpers.selfSignedPair();
    var spDefault = _routerListenThrows({ key: pair.key, cert: pair.cert, secureProtocol: "TLSv1_2_method" });
    check("b.router TLS listen() with secureProtocol throws ERR_TLS_PROTOCOL_VERSION_CONFLICT",
          spDefault && spDefault.code === "ERR_TLS_PROTOCOL_VERSION_CONFLICT", spDefault && spDefault.message);
    var spWithMin = _routerListenThrows({
      key: pair.key, cert: pair.cert, secureProtocol: "TLSv1_2_method", minVersion: "TLSv1.2",
    });
    check("b.router TLS listen() with secureProtocol and minVersion TLSv1.2 throws ERR_TLS_PROTOCOL_VERSION_CONFLICT",
          spWithMin && spWithMin.code === "ERR_TLS_PROTOCOL_VERSION_CONFLICT", spWithMin && spWithMin.message);

    b.network.tls.preferredGroups.set(["X25519MLKEM768"]);
    var pqOnly12 = await _dialDirect("X25519:secp256r1", _routerBackend(function (pair2) {
      return { key: pair2.key, cert: pair2.cert, minVersion: "TLSv1.2" };
    }), TLS12_CLIENT);
    check("b.router TLS listener with minVersion TLSv1.2 under an X25519MLKEM768-only posture completes no TLS 1.2 handshake",
          !pqOnly12.connected, _describe(pqOnly12));
    b.network.tls.preferredGroups.reset();

    // A posture name the runtime cannot set is refused at preferredGroups.set,
    // naming the group, and a listener built afterwards uses the posture that
    // was in force.
    var setErr = null;
    try { b.network.tls.preferredGroups.set(["NotAGroup"]); } catch (e) { setErr = e; }
    check("a preferredGroups name the runtime cannot set throws tls/bad-key-share at set()",
          setErr !== null && setErr.code === "tls/bad-key-share" &&
          setErr.message.indexOf("'NotAGroup'") !== -1,
          setErr && (setErr.code + " " + setErr.message));
    var listenAfter = _routerListenThrows({ key: pair.key, cert: pair.cert });
    check("b.router's listen() after the refused set() starts on the posture in force",
          listenAfter === null, listenAfter && listenAfter.message);
    var curveErr = _routerListenThrows({ key: pair.key, cert: pair.cert, ecdhCurve: "NotAGroup" });
    check("a tlsOptions.ecdhCurve the runtime cannot set makes b.router's listen() throw ERR_CRYPTO_OPERATION_FAILED",
          curveErr !== null && curveErr.code === "ERR_CRYPTO_OPERATION_FAILED",
          curveErr && (curveErr.code + " " + curveErr.message));

    // OpenSSL can set secp256k1 and brainpoolP256r1, but TLS 1.3 defines
    // neither, so a listener on only those completes no TLS 1.3 handshake.
    // preferredGroups.set refuses them, naming the group.
    var notTls13 = ["secp256k1", "brainpoolP256r1"];
    for (var ni = 0; ni < notTls13.length; ni += 1) {
      var n13Err = null;
      try { b.network.tls.preferredGroups.set([notTls13[ni]]); } catch (e) { n13Err = e; }
      check("preferredGroups.set refuses " + notTls13[ni] + ", which TLS 1.3 does not define, with tls/bad-key-share",
            n13Err !== null && n13Err.code === "tls/bad-key-share" &&
            n13Err.message.indexOf("'" + notTls13[ni] + "'") !== -1,
            n13Err ? (n13Err.code + " " + n13Err.message) : "no throw; posture " + b.network.tls.preferredGroups.get().join(":"));
      b.network.tls.preferredGroups.reset();
    }

    // Every group name preferredGroups.set accepts is one b.pqcGate reads as a
    // TLS group, so a gate given the listener string explicitly (behind a
    // post-quantum tuple, which the gate requires) does not throw.
    var accepted = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768",
      "MLKEM1024", "X25519", "X448", "secp256r1", "prime256v1", "secp384r1", "secp521r1",
      "brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13",
      "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"];
    for (var ai = 0; ai < accepted.length; ai += 1) {
      var aSetErr = null;
      var aGateErr = null;
      try { b.network.tls.preferredGroups.set([accepted[ai]]); } catch (e) { aSetErr = e; }
      try { b.pqcGate.acceptedGroupIds("X25519MLKEM768/" + b.network.tls.serverKeyAgreementGroups()); } catch (e) { aGateErr = e; }
      check("preferredGroups.set accepts " + accepted[ai] + " and b.pqcGate reads the resulting listener string",
            aSetErr === null && aGateErr === null,
            (aSetErr && aSetErr.message) || (aGateErr && aGateErr.message));
      b.network.tls.preferredGroups.reset();
    }

    // Under a preference that names an FFDHE group, the same FFDHE-only client
    // connects.
    b.network.tls.preferredGroups.set(["X25519MLKEM768", "ffdhe2048"]);
    var ffdheConfigured = await _dialDirect("ffdhe2048", _routerBackend());
    check("b.router TLS listener under a preference naming ffdhe2048 accepts a client that offers only ffdhe2048",
          ffdheConfigured.connected && ffdheConfigured.info && ffdheConfigured.info.type === "DH" &&
            ffdheConfigured.info.size === 2048, _describe(ffdheConfigured));
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// A node:tls listener reads its groups from its initial context, not from
// the context its SNICallback returns (Node 24.21 and 26.9, OpenSSL 3.5.8).
// b.cert's sniCallback returns a context without groups and relies on this.
async function testSniContextGroupsAreNotRead() {
  try {
    b.network.tls.preferredGroups.reset();
    var sniCalls = 0;
    function _sniBackend(initialCurve, sniCurve) {
      return async function (pair) {
        var sniCtx = nodeTls.createSecureContext({ key: pair.key, cert: pair.cert, ecdhCurve: sniCurve });
        var initial = {
          key: pair.key, cert: pair.cert, minVersion: "TLSv1.3",
          SNICallback: function (name, cb) { sniCalls += 1; cb(null, sniCtx); },
        };
        if (initialCurve) initial.ecdhCurve = initialCurve;
        return _startTlsBackend(initial);
      };
    }
    var restricted = await _dialDirect("X25519MLKEM768",
      _sniBackend(b.network.tls.serverKeyAgreementGroups(), "X25519"));
    check("an SNI context limited to X25519: the SNICallback ran", sniCalls === 1, "SNICallback calls: " + sniCalls);
    check("an SNI context limited to X25519 does not stop the initial context's X25519MLKEM768",
          restricted.connected && restricted.info && restricted.info.name === "X25519MLKEM768", _describe(restricted));
    sniCalls = 0;
    var widened = await _dialDirect("X25519:SecP256r1MLKEM768", _sniBackend(null, "SecP256r1MLKEM768/X25519"));
    check("an SNI context's tuple list: the SNICallback ran", sniCalls === 1, "SNICallback calls: " + sniCalls);
    check("an SNI context's tuple list does not reach a listener on the default list",
          widened.connected && widened.info && widened.info.name === "X25519", _describe(widened));
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// b.mtlsEngine.canVerifyInTls runs a loopback handshake whose client offers
// the outbound posture, so its listener must accept the same groups.
async function testMtlsTlsProbeFollowsThePosture() {
  var postures = [["SecP384r1MLKEM1024"], ["SecP256r1MLKEM768"], ["MLKEM1024"]];
  try {
    for (var i = 0; i < postures.length; i++) {
      b.network.tls.preferredGroups.reset();
      b.network.tls.preferredGroups.set(postures[i]);
      check("b.mtlsEngine.canVerifyInTls verifies ECDSA-P384-SHA384 under a " + postures[i][0] + "-only posture",
            (await b.mtlsEngine.canVerifyInTls("ECDSA-P384-SHA384")) === true);
    }
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// The role option chooses which of the two group strings is written.
function testApplyToContextRole() {
  try {
    b.network.tls.preferredGroups.reset();
    var server = b.network.tls.applyToContext({ base: {} });
    check("applyToContext writes the server tuple form by default",
          server.ecdhCurve === b.network.tls.serverKeyAgreementGroups(), server.ecdhCurve);
    var client = b.network.tls.applyToContext({ base: {}, role: "client" });
    check("applyToContext role client writes the outbound offer order",
          client.ecdhCurve === b.network.tls.outboundPosture().ecdhCurve, client.ecdhCurve);
    var override = b.network.tls.applyToContext({ base: { ecdhCurve: "X25519MLKEM768/X25519" }, role: "server" });
    check("applyToContext keeps an operator ecdhCurve under role server",
          override.ecdhCurve === "X25519MLKEM768/X25519", override.ecdhCurve);
    ["listener", "", 1, null].forEach(function (bad) {
      var threw = null;
      try { b.network.tls.applyToContext({ base: {}, role: bad }); } catch (e) { threw = e; }
      check("applyToContext refuses role " + JSON.stringify(bad),
            threw !== null && threw.code === "tls/bad-role", threw ? threw.code + " " + threw.message : "returned");
    });
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// The default group strings, written out, and every place the docs quote them.
var DEFAULT_SERVER_GROUPS =
  "X25519MLKEM768/SecP256r1MLKEM768/SecP384r1MLKEM1024/X25519/X448:secp256r1:secp384r1:secp521r1";
var DEFAULT_CLIENT_GROUPS = "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519";

function testDefaultGroupStringsMatchTheDocs() {
  try {
    b.network.tls.preferredGroups.reset();
    var server = b.network.tls.serverKeyAgreementGroups();
    check("serverKeyAgreementGroups() writes each default group in a tuple of its own, then the fallback curves",
          server === DEFAULT_SERVER_GROUPS, server);
    var client = b.network.tls.outboundPosture().ecdhCurve;
    check("outboundPosture().ecdhCurve is the flat default offer order",
          client === DEFAULT_CLIENT_GROUPS, client);
    var root = path.resolve(__dirname, "..", "..");
    ["lib/network-tls.js", "lib/pqc-gate.js"].forEach(function (rel) {
      var src = fs.readFileSync(path.join(root, rel), "utf8");
      var quoted = src.match(/"X25519MLKEM768[/:][^"\r\n]*secp521r1"/g) || [];
      quoted.forEach(function (q) {
        check(rel + " quotes the default listener string as the code writes it: " + q,
              q === JSON.stringify(server), "code writes " + server);
      });
    });
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

// A ClientHello record carrying exactly `extensions`, each `[type, body]`.
function _clientHelloWith(extensions) {
  var ext = Buffer.concat(extensions.map(function (e) {
    var head = Buffer.alloc(4);
    head.writeUInt16BE(e[0], 0);
    head.writeUInt16BE(e[1].length, 2);
    return Buffer.concat([head, e[1]]);
  }));
  var extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(ext.length, 0);
  var body = Buffer.concat([
    Buffer.from([0x03, 0x03]), Buffer.alloc(32, 0xAA), Buffer.from([0x00]),
    Buffer.from([0x00, 0x02, 0x13, 0x01]), Buffer.from([0x01, 0x00]), extLen, ext,
  ]);
  var hs = Buffer.alloc(4);
  hs[0] = 0x01;
  hs.writeUIntBE(body.length, 1, 3);
  var rec = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x00]);
  rec.writeUInt16BE(hs.length + body.length, 3);
  return Buffer.concat([rec, hs, body]);
}

function _supportedGroupsExt(ids) {
  var body = Buffer.alloc(2 + ids.length * 2);
  body.writeUInt16BE(ids.length * 2, 0);
  ids.forEach(function (id, i) { body.writeUInt16BE(id, 2 + i * 2); });
  return [0x000A, body];
}

function _supportedVersionsExt(versions) {
  var body = Buffer.alloc(1 + versions.length * 2);
  body[0] = versions.length * 2;
  versions.forEach(function (v, i) { body.writeUInt16BE(v, 1 + i * 2); });
  return [0x002B, body];
}

// The offset of extension `type`'s body in a ClientHello record, or -1.
function _extensionBodyAt(buf, type) {
  var off = 5 + 4 + 2 + 32;
  off += 1 + buf[off];
  off += 2 + buf.readUInt16BE(off);
  off += 1 + buf[off];
  var end = off + 2 + buf.readUInt16BE(off);
  off += 2;
  while (off + 4 <= end) {
    var t = buf.readUInt16BE(off);
    var len = buf.readUInt16BE(off + 2);
    if (t === type) return off + 4;
    off += 4 + len;
  }
  return -1;
}

// The first ClientHello record a node:tls client with `clientOpts` sends.
function _captureClientHello(clientOpts) {
  return new Promise(function (resolve) {
    var acc = Buffer.alloc(0);
    var client = null;
    var srv = net.createServer(function (s) {
      s.on("error", function () { /* the client is torn down below */ });
      s.on("data", function (d) {
        acc = Buffer.concat([acc, d]);
        if (acc.length >= 5 && acc.length >= 5 + acc.readUInt16BE(3)) {
          s.destroy();
          srv.close();
          if (client) client.destroy();
          resolve(acc.subarray(0, 5 + acc.readUInt16BE(3)));
        }
      });
    });
    srv.listen(0, "127.0.0.1", function () {
      client = nodeTls.connect(Object.assign({
        host: "127.0.0.1", port: srv.address().port, servername: "localhost",
      }, clientOpts));
      client.on("error", function () { /* the capture server hangs up */ });
    });
  });
}

// The first bytes the gate answers `hello` with, in front of a listener on
// `backendOpts`, or with `direct` the bytes the listener itself answers.
async function _gateReplyTo(hello, backendOpts, direct) {
  var backend = await _startTlsBackend(backendOpts);
  var gate = b.pqcGate.create({ internalPort: backend.address().port, bypass: [], log: { warn: function () {} } });
  await new Promise(function (r) { gate.listen(0, "127.0.0.1", r); });
  var port = direct === true ? backend.address().port : gate.address().port;
  try {
    return await new Promise(function (resolve) {
      var s = net.connect(port, "127.0.0.1", function () { s.write(hello); });
      s.on("data", function (d) { s.destroy(); resolve(d); });
      s.on("error", function () { resolve(Buffer.alloc(0)); });
      s.on("close", function () { resolve(Buffer.alloc(0)); });
    });
  } finally {
    gate.close();
    backend.close();
  }
}

function _describeReply(reply) {
  if (reply.length === 0) return "no bytes";
  if (reply[0] === 0x15) return "alert " + reply.subarray(0, 7).toString("hex");
  if (reply[0] === 0x16 && reply[5] === 0x02) return "ServerHello 0x" + reply.readUInt16BE(9).toString(16);
  return "record " + reply.subarray(0, 8).toString("hex");
}

// The post-quantum groups exist only in TLS 1.3. A ClientHello that cannot
// reach TLS 1.3 negotiates classical ECDHE with any listener that allows
// TLS 1.2, whatever its supported_groups extension names.
async function testGateRequiresATls13Offer() {
  var X25519MLKEM768 = b.constants.PQC_GROUPS.X25519MLKEM768;
  var pair = helpers.selfSignedPair();
  var tls12Listener = b.network.tls.applyToContext({
    base: { key: pair.key, cert: pair.cert, minVersion: "TLSv1.2" },
  });

  var tls12 = await _captureClientHello({ ecdhCurve: "X25519:P-256", minVersion: "TLSv1.2", maxVersion: "TLSv1.2" });
  var groupsAt = _extensionBodyAt(tls12, 0x000A);
  check("the captured TLS 1.2 ClientHello has a supported_groups extension and no supported_versions",
        groupsAt !== -1 && _extensionBodyAt(tls12, 0x002B) === -1);
  // X25519 becomes X25519MLKEM768 and P-256 stays, which the listener's
  // P-256 certificate needs under TLS 1.2.
  var patched = Buffer.from(tls12);
  patched.writeUInt16BE(X25519MLKEM768, groupsAt + 2);
  var direct = await _gateReplyTo(patched, tls12Listener, true);
  check("control: the listener answers that ClientHello with a TLS 1.2 ServerHello",
        direct.length > 10 && direct[0] === 0x16 && direct[5] === 0x02 && direct.readUInt16BE(9) === 0x0303,
        _describeReply(direct));
  check("a TLS 1.2-only ClientHello naming X25519MLKEM768 does not count as a post-quantum offer",
        b.pqcGate.clientHelloHasPQC(patched) === false);
  var reply = await _gateReplyTo(patched, tls12Listener);
  check("a TLS 1.2-only ClientHello naming X25519MLKEM768 is answered with an alert at the gate",
        reply.length > 0 && reply[0] === 0x15, _describeReply(reply));

  var tls13 = await _captureClientHello({ ecdhCurve: "X25519MLKEM768", minVersion: "TLSv1.3" });
  check("control: a TLS 1.3 ClientHello offering X25519MLKEM768 counts",
        b.pqcGate.clientHelloHasPQC(tls13) === true);
  var versionsAt = _extensionBodyAt(tls13, 0x002B);
  var downgraded = Buffer.from(tls13);
  for (var v = versionsAt + 1; v + 2 <= versionsAt + 1 + downgraded[versionsAt]; v += 2) {
    if (downgraded.readUInt16BE(v) === 0x0304) downgraded.writeUInt16BE(0x0303, v);
  }
  check("a ClientHello whose supported_versions lists no TLS 1.3 does not count",
        versionsAt !== -1 && b.pqcGate.clientHelloHasPQC(downgraded) === false);

  var groups = _supportedGroupsExt([X25519MLKEM768, 0x001D]);
  var v13 = _supportedVersionsExt([0x0304, 0x0303]);
  check("supported_groups then supported_versions with TLS 1.3 counts",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([groups, v13])) === true);
  check("supported_versions then supported_groups with TLS 1.3 counts",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([v13, groups])) === true);
  check("supported_groups with no supported_versions does not count",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([groups])) === false);
  check("supported_versions listing only TLS 1.2 does not count",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([groups, _supportedVersionsExt([0x0303])])) === false);
  check("a second supported_groups extension does not count",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([groups, v13, _supportedGroupsExt([0x001D])])) === false);
  check("a second supported_versions extension does not count",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([groups, v13, _supportedVersionsExt([0x0303])])) === false);
  check("a supported_versions list longer than its extension does not count",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([groups, [0x002B, Buffer.from([0x04, 0x03, 0x04])]])) === false);
  check("a supported_groups list longer than its extension does not count",
        b.pqcGate.clientHelloHasPQC(_clientHelloWith([[0x000A, Buffer.from([0x00, 0x04, 0x11, 0xEC])], v13])) === false);
  var groupsCut = _clientHelloWith([v13, groups]);
  check("a ClientHello cut off inside supported_groups does not count",
        b.pqcGate.clientHelloHasPQC(groupsCut.subarray(0, groupsCut.length - 2)) === false);

  var mixed = await _dialThroughGate("X25519:X25519MLKEM768", {
    backendOpts: function (p) {
      return b.network.tls.applyToContext({ base: { key: p.key, cert: p.cert, minVersion: "TLSv1.2" } });
    },
    clientMinVersion: "TLSv1.2",
  });
  check("a client offering TLS 1.2 and 1.3 to a listener allowing both negotiates a post-quantum group",
        mixed.connected && _negotiatedPqc(mixed), _describe(mixed));
}

// IANA TLS Supported Groups: MLKEM1024 514, X25519MLKEM768 4588,
// SecP256r1MLKEM768 4587, SecP384r1MLKEM1024 4589.
function testAcceptedGroupIds() {
  var explicit = b.pqcGate.acceptedGroupIds("MLKEM1024/X25519MLKEM768/X25519");
  check("acceptedGroupIds counts the post-quantum tuples of an explicit list",
        explicit instanceof Set && explicit.size === 2 && explicit.has(514) && explicit.has(4588));
  var shared = b.pqcGate.acceptedGroupIds("X25519MLKEM768:SecP256r1MLKEM768/X25519");
  check("acceptedGroupIds counts every member of a post-quantum-only tuple",
        shared.size === 2 && shared.has(4588) && shared.has(4587));
  var lower = b.pqcGate.acceptedGroupIds("x25519mlkem768/secp256r1");
  check("acceptedGroupIds matches group names case-insensitively",
        lower.size === 1 && lower.has(4588));
  var prefixed = b.pqcGate.acceptedGroupIds("?*X25519MLKEM768:*?MLKEM1024/?X25519");
  check("acceptedGroupIds reads the OpenSSL ? and * prefixes",
        prefixed.size === 2 && prefixed.has(4588) && prefixed.has(514));
  var arr = b.pqcGate.acceptedGroupIds(["X25519MLKEM768", "MLKEM1024"]);
  check("acceptedGroupIds reads an array as one tuple",
        arr.size === 2 && arr.has(4588) && arr.has(514));
  try {
    b.network.tls.preferredGroups.reset();
    var dflt = b.pqcGate.acceptedGroupIds();
    check("acceptedGroupIds() reads the default server posture",
          dflt.size === 3 && dflt.has(4587) && dflt.has(4588) && dflt.has(4589));
    b.network.tls.preferredGroups.set(["X25519", "X25519MLKEM768"]);
    var behind = b.pqcGate.acceptedGroupIds();
    check("acceptedGroupIds() does not count a post-quantum tuple behind a classical one",
          behind.size === 0, JSON.stringify(Array.from(behind)));
    check("PQC_GROUP_IDS follows the same posture reading", b.pqcGate.PQC_GROUP_IDS.size === 0);
  } finally {
    b.network.tls.preferredGroups.reset();
  }

  var refused = [
    [42,                                "a value that is not a string or array"],
    [[""],                              "an empty group name"],
    ["",                                "an empty string"],
    ["X25519MLKEM768:X25519",           "a tuple mixing a post-quantum and a classical group"],
    [["X25519MLKEM768", "secp256r1"],   "an array mixing a post-quantum and a classical group"],
    ["X25519/X25519MLKEM768",           "a post-quantum tuple behind a classical one"],
    ["X25519MLKEM768/X25519/MLKEM1024", "a post-quantum tuple after a classical one"],
    ["X25519",                          "a list with no post-quantum group"],
    ["X25519MLKEM786/X25519",           "a group name that is not a TLS group"],
    ["X25519MLKEM768,X25519",           "a comma-separated list"],
    ["DEFAULT",                         "the OpenSSL DEFAULT keyword"],
    ["X25519MLKEM768/X25519:-X448",     "an OpenSSL removal entry"],
    ["X25519MLKEM768//X25519",          "an empty tuple"],
  ];
  for (var i = 0; i < refused.length; i++) {
    var threwIds = null;
    try { b.pqcGate.acceptedGroupIds(refused[i][0]); } catch (e) { threwIds = e; }
    check("acceptedGroupIds refuses " + refused[i][1] + " with TypeError", threwIds instanceof TypeError,
          threwIds ? threwIds.message : "returned");
    var threwCreate = null;
    try { b.pqcGate.create({ internalPort: 8443, groups: refused[i][0] }); } catch (e2) { threwCreate = e2; }
    check("pqcGate.create refuses " + refused[i][1] + " with TypeError", threwCreate instanceof TypeError,
          threwCreate ? threwCreate.message : "returned a gate");
  }
}

async function run() {
  testAcceptedGroupIds();
  await testGateMatchesTheListener();
  await testExplicitGroupsMatchTheListener();
  await testFrameworkBuiltListenersAreGated();
  testApplyToContextRole();
  testDefaultGroupStringsMatchTheDocs();
  await testGateRequiresATls13Offer();
  await testSniContextGroupsAreNotRead();
  await testMtlsTlsProbeFollowsThePosture();
  await testRouterListenerIsGated();
  await testRouterOwnEcdhCurveGatedThroughItsGroups();
  await testRouterListenerVersionAndGroupEdges();
  await testInternalHostBracketedIpv6();
  testBypassRefusesEntriesThatAreNotAddresses();
  await testBypassMatchesEverySpellingOfThePeer();
  testInternalHostRefusesBadValues();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[pqc-gate-posture] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
