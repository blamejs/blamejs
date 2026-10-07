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
  ];
  for (var j = 0; j < refused.length; j++) {
    var e2 = await refusal({ sans: refused[j][1] });
    check("signClientCert refuses " + refused[j][0],
      !!e2 && e2.code === "mtls-engine/bad-san",
      "got " + (e2 ? e2.code : "no refusal"));
  }

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
