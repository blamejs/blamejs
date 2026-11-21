// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live SSRF guard test against the docker-compose Caddy fixture.
 * Exercises lib/ssrf-guard.js classification + checkUrl on a mix of
 * URLs (legitimate caddy target, loopback, link-local, private, cloud-
 * metadata) — and ensures the framework's http-client integration
 * trips the guard when an internal target is requested without
 * allowInternal.
 */
var fs = require("node:fs");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var caddy = await services.requireService("caddy");
  if (!caddy.ok) throw new Error("caddy unreachable: " + caddy.reason);

  // ---- classify static cases (returns string label or null) ----
  check("classify: 127.0.0.1 → 'loopback'",
        b.ssrfGuard.classify("127.0.0.1") === "loopback");
  check("classify: ::1 → 'loopback'",
        b.ssrfGuard.classify("::1") === "loopback");
  check("classify: 169.254.169.254 → 'cloud-metadata'",
        b.ssrfGuard.classify("169.254.169.254") === "cloud-metadata");
  check("classify: 10.0.0.1 → 'private'",
        b.ssrfGuard.classify("10.0.0.1") === "private");
  check("classify: 192.168.1.1 → 'private'",
        b.ssrfGuard.classify("192.168.1.1") === "private");
  check("classify: 8.8.8.8 → null (public)",
        b.ssrfGuard.classify("8.8.8.8") === null);
  check("classify: fe80::1 → 'link-local'",
        b.ssrfGuard.classify("fe80::1") === "link-local");

  check("isLoopback: 127.0.0.1 yes", b.ssrfGuard.isLoopback("127.0.0.1") === true);
  check("isLoopback: 8.8.8.8 no",     b.ssrfGuard.isLoopback("8.8.8.8") === false);
  check("isCloudMetadata: 169.254.169.254 yes",
        b.ssrfGuard.isCloudMetadata("169.254.169.254") === true);
  check("isCloudMetadata: 8.8.8.8 no",
        b.ssrfGuard.isCloudMetadata("8.8.8.8") === false);

  // ---- cidrContains ----
  check("cidrContains: 10.0.0.5 in 10.0.0.0/8",
        b.ssrfGuard.cidrContains("10.0.0.0/8", "10.0.0.5") === true);
  check("cidrContains: 11.0.0.5 NOT in 10.0.0.0/8",
        b.ssrfGuard.cidrContains("10.0.0.0/8", "11.0.0.5") === false);

  // ---- checkUrl: end-to-end DNS lookup + classification ----
  // The lookup goes through b.network.dns, pointed at the stack's CoreDNS DoH.
  var dnsSvc = await services.requireService("dns");
  if (!dnsSvc.ok) throw new Error("coredns unreachable: " + dnsSvc.reason);
  var caPem = fs.readFileSync(await services.exportCaCert(), "utf8");
  b.network.dns._resetForTest();
  b.network.dns.useDnsOverHttps({ url: "https://localhost:8053/dns-query", method: "POST", ca: caPem });
  var pub;
  try {
    pub = await b.ssrfGuard.checkUrl("https://example.com/").catch(function (e) { return { _err: e }; });
  } finally {
    b.network.dns._resetForTest();
  }
  check("checkUrl: public hostname does NOT throw",
        !pub._err, pub._err && (pub._err.code + " " + pub._err.message));

  // Internal target should throw without allowInternal.
  var threwInternal = null;
  try { await b.ssrfGuard.checkUrl("http://127.0.0.1:8080/healthz"); }
  catch (e) { threwInternal = e; }
  check("checkUrl: 127.0.0.1 throws SsrfError by default",
        threwInternal && threwInternal.code &&
        /loopback|internal|ssrf/i.test(threwInternal.code + " " + threwInternal.message));

  // Same target with allowInternal: true should pass.
  var allowed = await b.ssrfGuard.checkUrl("http://127.0.0.1:8080/healthz", { allowInternal: true })
    .catch(function (e) { return { _err: e }; });
  check("checkUrl: 127.0.0.1 with allowInternal=true passes",
        !allowed._err);

  // Cloud metadata IP must always throw, even with allowInternal.
  var threwMeta = null;
  try { await b.ssrfGuard.checkUrl("http://169.254.169.254/latest/meta-data/", { allowInternal: true }); }
  catch (e) { threwMeta = e; }
  check("checkUrl: cloud-metadata IP throws even with allowInternal=true",
        threwMeta && threwMeta.code &&
        /metadata|ssrf/i.test(threwMeta.code + " " + threwMeta.message));

  // ---- end-to-end via http-client: caddy is internal, must trip ----
  var clientThrew = null;
  try {
    await b.httpClient.request({
      method:           "GET",
      url:              "http://127.0.0.1:8080/healthz",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      // allowInternal NOT set — should trip the guard
    });
  } catch (e) { clientThrew = e; }
  check("http-client: rejects internal URL without allowInternal",
        clientThrew && clientThrew.code &&
        /ssrf|loopback|internal|host_disallowed/i.test(clientThrew.code + " " + clientThrew.message));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
