// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.constants runtime patch-level predicates and the certificate
 * compression list built from them.
 *
 * Covers: the Brotli decoder fix table (CVE-2026-111497), the OpenSSL
 * relative CRLDP fix table (CVE-2026-35189), fail-closed parsing of
 * unknown and malformed version strings, and the TLS_CERT_COMPRESSION
 * list dropping "brotli" on a runtime whose decoder is not fixed.
 *
 * Run standalone: `node test/layer-0-primitives/constants.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeTls = require("node:tls");
var C       = b.constants;

function testBrotliDecoderTable() {
  check("C._brotliDecoderPatched is a function",
        typeof C._brotliDecoderPatched === "function");
  if (typeof C._brotliDecoderPatched !== "function") return;
  var unpatched = ["24.21.0", "24.22.0", "26.12.0", "26.0.0", "22.23.3",
    "22.0.0", "25.9.0", "23.11.1", "20.19.5", "garbage", "", "24", "24.22",
    "v24.21.0", "-24.22.1", "24.x.1"];
  unpatched.forEach(function (v) {
    check("brotli decoder: " + JSON.stringify(v) + " is not fixed",
          C._brotliDecoderPatched(v) === false);
  });
  [undefined, null, 24, {}].forEach(function (v) {
    check("brotli decoder: non-string " + String(v) + " is not fixed",
          C._brotliDecoderPatched(v) === false);
  });
  var patched = ["24.22.1", "24.22.2", "24.23.0", "26.12.1", "26.13.0",
    "22.23.4", "22.24.0", "27.0.0", "28.1.0", "v24.22.1", "24.22.1+build.7"];
  patched.forEach(function (v) {
    check("brotli decoder: " + JSON.stringify(v) + " is fixed",
          C._brotliDecoderPatched(v) === true);
  });
}

// A prerelease build carries the version it is heading toward, so a build
// reporting 24.22.1-pre can predate the fix that 24.22.1 ships. At or below
// a floor any "-" suffix is unfixed; above the floor the release it leads up
// to already carries the fix.
function testPrereleaseAtTheFloorIsUnfixed() {
  if (typeof C._brotliDecoderPatched !== "function") return;
  ["24.22.1-pre", "26.12.1-rc.1", "22.23.4-pre", "27.0.0-pre",
   "27.0.0-nightly20260101abc", "v24.22.1-pre", "24.22.0-pre", "24.22.1-"]
    .forEach(function (v) {
      check("brotli decoder: prerelease " + JSON.stringify(v) + " is not fixed",
            C._brotliDecoderPatched(v) === false);
    });
  ["24.22.2-pre", "26.12.2-rc.1", "27.0.1-pre", "28.0.0-nightly2026"]
    .forEach(function (v) {
      check("brotli decoder: prerelease " + JSON.stringify(v) + " above the floor is fixed",
            C._brotliDecoderPatched(v) === true);
    });
  ["3.5.9-dev", "3.6.5-alpha1", "4.0.3-beta2", "4.1.0-dev", "3.4.8-"]
    .forEach(function (v) {
      check("openssl crldp: prerelease " + JSON.stringify(v) + " is not fixed",
            C._opensslCrldpPatched(v) === false);
    });
  ["3.5.10-dev", "4.1.1-dev"].forEach(function (v) {
    check("openssl crldp: prerelease " + JSON.stringify(v) + " above the floor is fixed",
          C._opensslCrldpPatched(v) === true);
  });
  check("cert compression: brotli is dropped on 24.22.1-pre",
        C._certCompressionFor(["zlib", "brotli"], "24.22.1-pre").join(",") === "zlib");
}

function testOpensslPrefixedVersion() {
  if (typeof C._opensslCrldpPatched !== "function") return;
  check("openssl crldp: \"OpenSSL 3.5.9\" is fixed",
        C._opensslCrldpPatched("OpenSSL 3.5.9") === true);
  check("openssl crldp: \"OpenSSL 3.5.9 1 Jul 2026\" is fixed",
        C._opensslCrldpPatched("OpenSSL 3.5.9 1 Jul 2026") === true);
  check("openssl crldp: \"OpenSSL 3.5.8\" is not fixed",
        C._opensslCrldpPatched("OpenSSL 3.5.8") === false);
  check("openssl crldp: \"OpenSSL 3.5.9-dev\" is not fixed",
        C._opensslCrldpPatched("OpenSSL 3.5.9-dev") === false);
  check("openssl crldp: \"OpenSSL\" alone is not fixed",
        C._opensslCrldpPatched("OpenSSL") === false);
  check("brotli decoder: an OpenSSL prefix does not parse as a Node version",
        C._brotliDecoderPatched("OpenSSL 24.22.1") === false);
}

function testVersionParsers() {
  check("C._parseNodeVersion and C._parseOpensslVersion are functions",
        typeof C._parseNodeVersion === "function" &&
        typeof C._parseOpensslVersion === "function");
  if (typeof C._parseNodeVersion !== "function" ||
      typeof C._parseOpensslVersion !== "function") return;
  var n = C._parseNodeVersion("v24.22.1-pre");
  check("node parse: v24.22.1-pre reads as 24.22.1, prerelease",
        n !== null && n.major === 24 && n.minor === 22 && n.patch === 1 &&
        n.prerelease === true && n.text === "v24.22.1-pre");
  check("node parse: garbage is null", C._parseNodeVersion("garbage") === null);
  check("node parse: a non-string is null", C._parseNodeVersion(24) === null);
  var s = C._parseOpensslVersion("OpenSSL 3.5.8");
  check("openssl parse: \"OpenSSL 3.5.8\" reads as 3.5.8 with text 3.5.8",
        s !== null && s.major === 3 && s.minor === 5 && s.patch === 8 &&
        s.prerelease === false && s.text === "3.5.8");
  check("openssl parse: \"3.5.9+quic\" is a release",
        C._parseOpensslVersion("3.5.9+quic").prerelease === false);
  check("openssl parse: garbage is null", C._parseOpensslVersion("OpenSSL x") === null);
}

function testOpensslCrldpTable() {
  check("C._opensslCrldpPatched is a function",
        typeof C._opensslCrldpPatched === "function");
  if (typeof C._opensslCrldpPatched !== "function") return;
  ["3.5.8", "3.5.0", "3.6.4", "3.4.7", "4.0.2", "3.0.15", "3.3.9",
   "1.1.1w", "garbage", ""].forEach(function (v) {
    check("openssl crldp: " + JSON.stringify(v) + " is not fixed",
          C._opensslCrldpPatched(v) === false);
  });
  ["3.5.9", "3.5.10", "3.6.5", "3.4.8", "4.0.3", "4.1.0", "5.0.0",
   "3.5.9+quic"].forEach(function (v) {
    check("openssl crldp: " + JSON.stringify(v) + " is fixed",
          C._opensslCrldpPatched(v) === true);
  });
}

function testCertCompressionFor() {
  check("C._certCompressionFor is a function",
        typeof C._certCompressionFor === "function");
  if (typeof C._certCompressionFor !== "function") return;
  var all = ["zlib", "brotli", "zstd"];
  var old = C._certCompressionFor(all, "24.21.0");
  check("unfixed runtime: brotli is dropped from the offer",
        old.join(",") === "zlib,zstd");
  check("unfixed runtime: the result is frozen", Object.isFrozen(old));
  check("unparsable version: brotli is dropped from the offer",
        C._certCompressionFor(all, "garbage").join(",") === "zlib,zstd");
  check("fixed runtime: the reported list is kept",
        C._certCompressionFor(all, "24.22.1").join(",") === "zlib,brotli,zstd");
  check("the input list is not mutated", all.join(",") === "zlib,brotli,zstd");
}

function testTlsCertCompressionFollowsRuntime() {
  if (typeof C._certCompressionFor !== "function") {
    check("TLS_CERT_COMPRESSION has a version filter to compare against", false);
    return;
  }
  var reported = typeof nodeTls.getCertificateCompressionAlgorithms === "function"
    ? nodeTls.getCertificateCompressionAlgorithms() : [];
  var expected = C._certCompressionFor(reported, process.versions.node);
  var got = C.TLS_CERT_COMPRESSION();
  check("TLS_CERT_COMPRESSION equals the runtime list filtered for " +
        process.versions.node + " (got " + got.join(",") + ")",
        got.join(",") === expected.join(","));
  if (!C._brotliDecoderPatched(process.versions.node)) {
    check("TLS_CERT_COMPRESSION omits brotli on Node " + process.versions.node,
          got.indexOf("brotli") === -1);
  }
}

// Server -> client handshake bytes for one dial, counted on a relay the test
// owns. The server compresses its certificate with brotli only, so the count
// shows whether the client's offer let the server send a brotli-compressed
// Certificate message.
async function _handshakeBytes(pair, fatCert, clientCompression) {
  var net = require("node:net");
  var open = [];
  var ctx = nodeTls.createSecureContext({
    cert: fatCert, key: pair.key, certificateCompression: ["brotli"],
  });
  var srv = net.createServer(function (sock) {
    open.push(sock);
    var t = new nodeTls.TLSSocket(sock, { isServer: true, secureContext: ctx });
    open.push(t);
    t.on("error", function () { /* the client closes after the handshake */ });
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
  var completed = false;
  var failure = null;
  await new Promise(function (resolve) {
    var o = Object.assign({
      host: "127.0.0.1", port: relay.address().port, servername: "localhost",
      ca: [pair.cert],
    }, b.network.tls.outboundPosture());
    if (clientCompression !== undefined) o.certificateCompression = clientCompression;
    var c = nodeTls.connect(o);
    c.on("secureConnect", function () { completed = true; c.destroy(); resolve(); });
    c.on("error", function (e) { failure = (e && e.message) || String(e); resolve(); });
  });
  await helpers.waitUntil(function () { return seen > 0; },
    { timeoutMs: 5000, label: "constants: handshake bytes observed" });
  relay.close(); srv.close();
  open.forEach(function (s) { try { s.destroy(); } catch (_e) { /* already closed */ } });
  if (!completed) {
    throw new Error("constants: handshake did not complete" +
                    (failure ? " (" + failure + ")" : ""));
  }
  return seen;
}

async function testOutboundPostureBrotliOfferOnTheWire() {
  var reported = typeof nodeTls.getCertificateCompressionAlgorithms === "function"
    ? nodeTls.getCertificateCompressionAlgorithms() : [];
  if (reported.indexOf("brotli") === -1) {
    check("runtime without brotli certificate compression: nothing to measure", true);
    return;
  }
  var pair = helpers.selfSignedPair();
  var fatCert = new Array(24).join(pair.cert) + pair.cert;
  var control = await _handshakeBytes(pair, fatCert, []);
  var posture = await _handshakeBytes(pair, fatCert, undefined);
  var fixed = C._brotliDecoderPatched(process.versions.node);
  if (fixed) {
    check("Node " + process.versions.node + ": outboundPosture() negotiates brotli " +
          "certificate compression (" + posture + " vs " + control + " bytes uncompressed)",
          posture < control * 0.8);
  } else {
    check("Node " + process.versions.node + ": outboundPosture() does not offer brotli, " +
          "so the certificate arrives uncompressed (" + posture + " vs " + control + " bytes)",
          Math.abs(posture - control) < control * 0.05);
  }
}

async function run() {
  testBrotliDecoderTable();
  testOpensslCrldpTable();
  testPrereleaseAtTheFloorIsUnfixed();
  testOpensslPrefixedVersion();
  testVersionParsers();
  testCertCompressionFor();
  testTlsCertCompressionFollowsRuntime();
  await testOutboundPostureBrotliOfferOnTheWire();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
