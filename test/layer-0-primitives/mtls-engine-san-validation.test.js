// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which subject alternative names `b.mtlsEngine.signClientCert` accepts.
 *
 * Every entry that was not recognized as an IP address became a `dNSName`
 * verbatim, so `"not a host !!!"` was written into a certificate and issuance
 * succeeded. Only a value explicitly prefixed `IP:` was ever refused. A
 * certificate carrying a name no peer can match fails at the handshake, where
 * the cause is far from the call that created it.
 *
 * Run standalone: `node test/layer-0-primitives/mtls-engine-san-validation.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

async function run() {
  var ca = await b.mtlsEngine.generateCa({ name: "san-validation-ca" });

  async function refusal(opts) {
    try {
      await b.mtlsEngine.signClientCert(Object.assign(
        { cn: "worker-7", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem }, opts));
      return null;
    } catch (e) { return e; }
  }

  var accepted = [
    ["a plain hostname",            ["api.example.com"]],
    ["a single label",              ["localhost"]],
    ["a wildcard",                  ["*.example.com"]],
    ["an underscore label",         ["my_service.internal"]],
    ["a hyphen inside a label",     ["edge-01.example.com"]],
    ["a DNS: prefix",               ["DNS:api.example.com"]],
    ["an IPv4 address",             ["10.1.2.3"]],
    ["an IPv6 address",             ["2001:db8::1"]],
    ["an IP: prefixed address",     ["IP:10.1.2.3"]],
    ["a 63-octet label",            ["a".repeat(63) + ".example.com"]],
    ["a mixed list",                ["api.example.com", "10.1.2.3", "DNS:*.edge.example.com"]],
  ];
  for (var i = 0; i < accepted.length; i++) {
    var err = await refusal({ sans: accepted[i][1] });
    check("signClientCert accepts " + accepted[i][0], err === null,
      err && (err.code + " " + err.message));
  }

  var refused = [
    ["a name with spaces",              ["not a host !!!"]],
    ["a name with an exclamation mark", ["host!.example.com"]],
    ["an empty label",                  ["api..example.com"]],
    ["a leading dot",                   [".example.com"]],
    ["a trailing dot",                  ["example.com."]],
    ["a label starting with a hyphen",  ["-api.example.com"]],
    ["a label ending with a hyphen",    ["api-.example.com"]],
    ["a 64-octet label",                ["a".repeat(64) + ".example.com"]],
    ["a name over 253 octets",          [("a".repeat(63) + ".").repeat(4) + "com"]],
    ["a wildcard that is not a label",  ["*api.example.com"]],
    ["a wildcard with nothing behind",  ["*"]],
    ["an empty entry",                  [""]],
    ["a DNS: prefix with a bad name",   ["DNS:not a host"]],
    ["a bad name beside a good one",    ["api.example.com", "not a host"]],
    // A configuration placeholder reaching the list used to be coerced with
    // String(), so null became the DNS name "null" and a port number became
    // "8443". Both are valid LDH labels, so the rule alone would accept them.
    ["a null entry",                    [null]],
    ["an undefined entry",              [undefined]],
    ["a number",                        [8443]],
    ["a boolean",                       [true]],
    ["an object",                       [{ dNSName: "api.example.com" }]],
    ["an array",                        [["api.example.com"]]],
    ["a null beside a good name",       ["api.example.com", null]],
  ];
  for (var j = 0; j < refused.length; j++) {
    var e2 = await refusal({ sans: refused[j][1] });
    check("signClientCert refuses " + refused[j][0],
      !!e2 && e2.code === "mtls-engine/bad-san",
      "got " + (e2 ? e2.code : "no refusal"));
  }

  // `sans` itself: a non-array was refused but `null` was exempted, so the
  // placeholder shape read as no sans at all. A server certificate then fell
  // back to the CN and a client certificate was issued with none, both for an
  // identity other than the one configured.
  var containers = [
    ["a bare string",  "api.example.com"],
    ["a number",       8443],
    ["an object",      { dNSName: "api.example.com" }],
    ["null",           null],
  ];
  for (var c = 0; c < containers.length; c++) {
    var e3 = await refusal({ sans: containers[c][1] });
    check("signClientCert refuses a sans container that is " + containers[c][0],
      !!e3 && e3.code === "mtls-engine/bad-san",
      "got " + (e3 ? e3.code : "no refusal"));
  }
  // Absent is still absent: omitting sans is how a client certificate is asked
  // for without one, and the refusal above must not take that away.
  var absent = await refusal({ cn: "worker_7", usage: "client" });
  check("and omitting sans entirely still issues", absent === null,
    absent && absent.message);

  // The sibling public primitive had the same shape and a worse consequence:
  // `generateCrl` coerced a non-array `revocations` to the empty list and
  // returned a correctly signed CRL asserting that nothing is revoked, which a
  // relying party caches until nextUpdate and keeps accepting every revoked
  // certificate on. There was no code for it at all. Its dates were unchecked
  // too, so an epoch number, the shape a config file or an HTTP body carries,
  // raised an uncoded TypeError out of a documented API.
  var crlBad = [
    ["null",                     { revocations: null }],
    ["a string",                 { revocations: "01" }],
    ["one unwrapped entry",      { revocations: { serialNumber: "01" } }],
    ["a JSON string of a list",  { revocations: "[{\"serialNumber\":\"01\"}]" }],
  ];
  for (var k = 0; k < crlBad.length; k++) {
    var crlErr = null;
    try {
      await b.mtlsEngine.generateCrl(Object.assign(
        { caCertPem: "x", caKeyPem: "y", crlNumber: 1 }, crlBad[k][1]));
    } catch (e) { crlErr = e; }
    check("generateCrl refuses revocations given " + crlBad[k][0],
      !!crlErr && crlErr.code === "mtls-engine/bad-revocations",
      "got " + (crlErr ? crlErr.code : "no refusal"));
  }
  var crlDates = [["thisUpdate", "thisUpdate"], ["nextUpdate", "nextUpdate"]];
  for (var d = 0; d < crlDates.length; d++) {
    var dOpts = { caCertPem: "x", caKeyPem: "y", crlNumber: 1 };
    dOpts[crlDates[d][1]] = 1767225600000;
    var dErr = null;
    try { await b.mtlsEngine.generateCrl(dOpts); } catch (e) { dErr = e; }
    check("generateCrl refuses a non-Date " + crlDates[d][0],
      !!dErr && dErr.code === "mtls-engine/bad-crl-date",
      "got " + (dErr ? dErr.code : "no refusal"));
  }

  // usage and algorithm carried the same null-as-absent reading: a placeholder
  // issued a clientAuth-only certificate, or selected an algorithm by
  // capability instead of the configured pin.
  var usageErr = await refusal({ usage: null });
  check("signClientCert refuses a usage that is present and not a string",
    !!usageErr && usageErr.code === "mtls-engine/bad-usage",
    "got " + (usageErr ? usageErr.code : "no refusal"));
  var algErr = await refusal({ algorithm: null });
  check("and refuses an algorithm pin that is present and not a label",
    !!algErr && algErr.code === "mtls-engine/unknown-algorithm",
    "got " + (algErr ? algErr.code : "no refusal"));

  // The CN-derived default goes through the same rule, so a server certificate
  // cannot carry a dNSName the operator-supplied list would have been refused
  // for. `_normaliseCn` strips a CN to [A-Za-z0-9_.-], which still leaves a
  // name made only of dots.
  check("a server cert with no sans and a dotted-only cn is refused",
    ((await refusal({ cn: "....", usage: "server", sans: undefined })) || {}).code ===
      "mtls-engine/bad-san");
  var serverOk = await refusal({ cn: "api.example.com", usage: "server" });
  check("and a server cert whose cn is a hostname still issues", serverOk === null,
    serverOk && serverOk.message);

  // A client certificate takes no SAN from the CN, so a CN that is not a
  // hostname is still a valid client identity.
  var clientOk = await refusal({ cn: "worker_7", usage: "client" });
  check("a client cert keeps a cn that is not a hostname", clientOk === null,
    clientOk && clientOk.message);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mtls-engine-san-validation] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
