"use strict";
/**
 * b.network.smtp.policy — MTA-STS + DANE + TLS-RPT outbound SMTP gates.
 *
 * Gmail and Microsoft 365 now penalize senders without MTA-STS / DANE
 * policies. This primitive is the framework's outbound-SMTP policy
 * surface — operators wire it into `b.mail` to enforce the recipient
 * domain's published policy before opening the SMTP socket.
 *
 *   var policy = b.network.smtp.policy;
 *   var sts = await policy.mtaSts.fetch("example.com");
 *   if (sts && sts.mode === "enforce") {
 *     // Verify the MX hostname matches an entry in sts.mx[*]
 *     // (wildcards allowed per RFC 8461 §3.2).
 *     var ok = policy.mtaSts.matchMx(mxHost, sts.mx);
 *     if (!ok) throw new SmtpPolicyError("smtp/mta-sts-mx-mismatch", ...);
 *   }
 *
 *   var tlsa = await policy.dane.tlsa("example.com", 25);
 *   // → [{ usage, selector, mtype, dataHex }, ...] from DNS TYPE 52
 *
 *   policy.tlsRpt.recordShape({
 *     organization: "example.com",
 *     reportingMta: "mx1.example.com",
 *     ...
 *   }) → { ... RFC 8460 TLS-RPT JSON shape ... }
 *
 * Surface:
 *   - mtaSts.fetch(domain)               — HTTPS-fetch + parse + cache
 *   - mtaSts.matchMx(mxHost, mxList)     — wildcard-aware match
 *   - dane.tlsa(domain, port)            — DNS TYPE 52 lookup
 *   - dane.recordShape(buffer)           — TLSA RR field decode
 *   - tlsRpt.recordShape(opts)           — RFC 8460 JSON shape generator
 *   - tlsRpt.fetchPolicy(domain)         — RFC 8460 §3 _smtp._tls TXT
 *                                          parse → { version, rua: [] }
 *   - tlsRpt.submit(report, { rua })     — gzip + POST to https rua
 *                                          endpoints; mailto entries
 *                                          surface a prepared body so
 *                                          operators hand it to b.mail
 *
 * Out of scope (deferred):
 *   - Full DANE certificate-chain verification per RFC 6698 (needs
 *     ASN.1 cert parsing). Operators today verify policy presence +
 *     match the leaf SHA-256 themselves.
 *   - DNSSEC-validated DANE lookups (node:dns doesn't expose
 *     DNSSEC ad-bit; operators pin to a DNSSEC-validating resolver
 *     externally).
 */

var dns = require("node:dns");
var dnsPromises = dns.promises;
var zlib = require("node:zlib");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var crypto = require("./crypto");
var safeUrl = require("./safe-url");
var C = require("./constants");
var { SmtpPolicyError } = require("./framework-error");

var httpClient = lazyRequire(function () { return require("./http-client"); });
var cache = lazyRequire(function () { return require("./cache"); });

var DEFAULT_POLICY_CACHE_MS = C.TIME.minutes(60);
var MAX_POLICY_BYTES = C.BYTES.kib(64);

// ---- per-process cache for fetched MTA-STS policies ----

var _stsCache = null;
function _getStsCache() {
  if (_stsCache) return _stsCache;
  _stsCache = cache().create({
    namespace: "smtp-policy.mta-sts",
    ttlMs:     DEFAULT_POLICY_CACHE_MS,
  });
  return _stsCache;
}

// ---- MTA-STS (RFC 8461) ----

// Parse an MTA-STS policy text (key: value lines, MX lines may repeat).
function _parseStsPolicy(text) {
  if (typeof text !== "string" || text.length === 0) {
    throw new SmtpPolicyError("smtp/mta-sts-empty",
      "MTA-STS policy text is empty");
  }
  var policy = { version: null, mode: null, mx: [], max_age: null };
  var lines = text.split(/\r?\n/);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i].trim();
    if (line.length === 0) continue;
    var colonAt = line.indexOf(":");
    if (colonAt === -1) continue;
    var key = line.slice(0, colonAt).trim().toLowerCase();
    var val = line.slice(colonAt + 1).trim();
    if (key === "version") policy.version = val;
    else if (key === "mode") policy.mode = val.toLowerCase();
    else if (key === "mx") policy.mx.push(val.toLowerCase());
    else if (key === "max_age") policy.max_age = parseInt(val, 10);
  }
  if (policy.version !== "STSv1") {
    throw new SmtpPolicyError("smtp/mta-sts-bad-version",
      "MTA-STS policy version must be STSv1, got " +
      JSON.stringify(policy.version));
  }
  if (["enforce", "testing", "none"].indexOf(policy.mode) === -1) {
    throw new SmtpPolicyError("smtp/mta-sts-bad-mode",
      "MTA-STS policy mode must be enforce|testing|none, got " +
      JSON.stringify(policy.mode));
  }
  return policy;
}

async function mtaStsFetch(domain) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/bad-domain",
      "mtaSts.fetch: domain must be a non-empty string");
  }
  var lcDomain = domain.toLowerCase();
  return await _getStsCache().wrap(lcDomain, async function () {
    var url = "https://mta-sts." + lcDomain + "/.well-known/mta-sts.txt";
    safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
    var res;
    try {
      res = await httpClient().request({
        method:    "GET",
        url:       url,
        maxBytes:  MAX_POLICY_BYTES,
        timeoutMs: C.TIME.seconds(10),
      });
    } catch (_e) {
      // Domain doesn't publish MTA-STS — return null (not an error;
      // operators decide policy via their own gate).
      return null;
    }
    if (res.statusCode === 404) return null;                                     // allow:raw-byte-literal — HTTP 404
    if (res.statusCode < 200 || res.statusCode >= 300) {                         // allow:raw-byte-literal — HTTP 2xx range
      throw new SmtpPolicyError("smtp/mta-sts-fetch-failed",
        "MTA-STS fetch returned " + res.statusCode + " for " + url);
    }
    return _parseStsPolicy(res.body.toString("utf8"));
  });
}

// MX matching per RFC 8461 §3.2 — exact host or single-label wildcard
// (e.g. `*.example.com` matches `mx1.example.com` but not
// `example.com` or `a.b.example.com`).
function mtaStsMatchMx(mxHost, mxList) {
  if (typeof mxHost !== "string" || !Array.isArray(mxList)) return false;
  var lc = mxHost.toLowerCase();
  for (var i = 0; i < mxList.length; i += 1) {
    var entry = String(mxList[i]).toLowerCase();
    if (entry === lc) return true;
    if (entry.length > 2 && entry.slice(0, 2) === "*.") {
      var suffix = entry.slice(1);   // ".example.com"
      var dotAt = lc.indexOf(".");
      if (dotAt === -1) continue;
      if (lc.slice(dotAt) === suffix) return true;
    }
  }
  return false;
}

// ---- DANE TLSA (RFC 6698) ----

async function daneTlsa(domain, port) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/bad-domain",
      "dane.tlsa: domain must be a non-empty string");
  }
  var p = typeof port === "number" ? port : 25;                                  // allow:raw-byte-literal — IANA SMTP port
  var qname = "_" + p + "._tcp." + domain.toLowerCase();
  // node:dns has resolveTlsa() since Node 18.16.0.
  if (typeof dnsPromises.resolveTlsa !== "function") {
    throw new SmtpPolicyError("smtp/dane-unavailable",
      "node:dns.resolveTlsa is not available on this runtime");
  }
  var records;
  try { records = await dnsPromises.resolveTlsa(qname); }
  catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return [];
    throw new SmtpPolicyError("smtp/dane-lookup-failed",
      "TLSA lookup for " + qname + " failed: " + ((e && e.message) || String(e)));
  }
  // Normalize node's response shape to { usage, selector, mtype, dataHex }.
  return (records || []).map(function (r) {
    return {
      usage:    r.certUsage,
      selector: r.selector,
      mtype:    r.match,
      dataHex:  Buffer.isBuffer(r.data) ? r.data.toString("hex") : String(r.data),
    };
  });
}

function daneRecordShape(rec) {
  if (!rec || typeof rec !== "object") {
    throw new SmtpPolicyError("smtp/dane-bad-record",
      "dane.recordShape: input must be a record object");
  }
  return {
    usage:    rec.usage,
    selector: rec.selector,
    mtype:    rec.mtype,
    dataHex:  rec.dataHex,
    // Human-readable label per RFC 6698:
    usageLabel:    rec.usage === 0 ? "PKIX-TA" :
                   rec.usage === 1 ? "PKIX-EE" :
                   rec.usage === 2 ? "DANE-TA" :
                   rec.usage === 3 ? "DANE-EE" : "unknown",
    selectorLabel: rec.selector === 0 ? "Cert" :
                   rec.selector === 1 ? "SPKI" : "unknown",
    mtypeLabel:    rec.mtype === 0 ? "Full" :
                   rec.mtype === 1 ? "SHA-256" :
                   rec.mtype === 2 ? "SHA-512" : "unknown",
  };
}

// ---- TLS-RPT (RFC 8460) report shape ----

function tlsRptRecordShape(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "organization", "reportingMta", "contact",
    "datestart", "dateend", "policies",
  ], "tlsRpt.recordShape");

  if (typeof opts.organization !== "string") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-organization",
      "tlsRpt.recordShape: organization must be a string");
  }
  if (!Array.isArray(opts.policies)) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-policies",
      "tlsRpt.recordShape: policies must be an array");
  }

  // RFC 8460 §4.4 JSON report format.
  return {
    "organization-name":       opts.organization,
    "date-range": {
      "start-datetime": opts.datestart || new Date().toISOString(),
      "end-datetime":   opts.dateend   || new Date().toISOString(),
    },
    "contact-info":            opts.contact || null,
    "report-id":               opts.reportId || _genReportId(),
    "policies": opts.policies.map(function (p) {
      return {
        "policy": {
          "policy-type":   p.type || "sts",
          "policy-string": p.policyString || [],
          "policy-domain": p.domain,
          "mx-host":       p.mxHosts || [],
        },
        "summary": {
          "total-successful-session-count": p.successCount || 0,
          "total-failure-session-count":    p.failureCount || 0,
        },
        "failure-details": p.failures || [],
      };
    }),
  };
}

function _genReportId() {
  // RFC 8460 §4.4 requires uniqueness — use timestamp + random token.
  return Date.now() + "-" + crypto.generateToken(C.BYTES.bytes(8));
}

// ---- TLS-RPT policy fetch (RFC 8460 §3) ----
//
// Reports are sent to the rua endpoints published at
// `_smtp._tls.<domain>` TXT. Format: `v=TLSRPTv1; rua=https://...,mailto:...`.
// rua is a comma-separated list of report URIs.

async function tlsRptFetchPolicy(domain, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-domain",
      "tlsRpt.fetchPolicy: domain must be a non-empty string");
  }
  opts = opts || {};
  var qname = "_smtp._tls." + domain;
  var records;
  try {
    if (opts.dnsLookup) {
      records = await opts.dnsLookup(qname, "TXT");
    } else {
      records = await dnsPromises.resolveTxt(qname);
    }
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new SmtpPolicyError("smtp/tls-rpt-lookup-failed",
      "TLS-RPT TXT lookup for " + qname + " failed: " +
      ((e && e.message) || String(e)));
  }
  // Pick the first record that begins with v=TLSRPTv1 per RFC 8460 §3.
  var joined = "";
  for (var i = 0; i < (records || []).length; i += 1) {
    var rec = records[i];
    var s = Array.isArray(rec) ? rec.join("") : String(rec);
    if (/^v=TLSRPTv1\b/i.test(s)) { joined = s; break; }
  }
  if (joined.length === 0) return null;
  var parts = joined.split(";");
  var rua = [];
  for (var p = 0; p < parts.length; p += 1) {
    var t = parts[p].trim();
    var eq = t.indexOf("=");
    if (eq === -1) continue;
    var k = t.slice(0, eq).trim().toLowerCase();
    var v = t.slice(eq + 1).trim();
    if (k === "rua") {
      var uris = v.split(",");
      for (var u = 0; u < uris.length; u += 1) {
        var uri = uris[u].trim();
        if (uri.length > 0) rua.push(uri);
      }
    }
  }
  return { version: "TLSRPTv1", rua: rua };
}

// ---- TLS-RPT report submission (RFC 8460 §6) ----
//
// Submit a generated report (from tlsRptRecordShape) to a published
// rua endpoint. HTTPS endpoints receive `application/tlsrpt+gzip`
// (gzip-compressed JSON); mailto: endpoints receive the JSON via SMTP
// (operator wires `b.mail`). The framework ships HTTPS submission
// directly and exposes a `mailtoBody` builder so operators can hand
// the body to their mail transport.

async function tlsRptSubmit(report, opts) {
  if (!report || typeof report !== "object") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-report",
      "tlsRpt.submit: report must be an object");
  }
  opts = opts || {};
  validateOpts(opts, ["rua", "httpClient", "timeoutMs", "audit"], "tlsRpt.submit");
  if (!Array.isArray(opts.rua) || opts.rua.length === 0) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-rua",
      "tlsRpt.submit: opts.rua must be a non-empty array of URIs");
  }
  var json = JSON.stringify(report);
  var gzipped = zlib.gzipSync(Buffer.from(json, "utf8"));
  var client = opts.httpClient || httpClient();
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(30);

  var results = [];
  for (var i = 0; i < opts.rua.length; i += 1) {
    var uri = opts.rua[i];
    var entry = { uri: uri, ok: false, status: null, error: null, kind: null };
    try {
      if (/^https:\/\//i.test(uri)) {
        entry.kind = "https";
        // allow:raw-outbound-http — `client` is the framework httpClient
        // (or operator-supplied test mock); SSRF + DNS-pin already
        // applied through the framework wrapper.
        var rv = await client.request({
          method:  "POST",
          url:     uri,
          headers: {
            "content-type":     "application/tlsrpt+gzip",
            "content-encoding": "gzip",
          },
          body:    gzipped,
          timeoutMs: timeoutMs,
        });
        entry.status = rv && rv.status;
        entry.ok = entry.status >= 200 && entry.status < 300;                  // allow:raw-byte-literal — HTTP 2xx range
        if (!entry.ok) entry.error = "HTTP " + entry.status;
      } else if (/^mailto:/i.test(uri)) {
        // Operator-side transport. Surface the prepared body so the
        // operator can hand it to b.mail directly.
        entry.kind = "mailto";
        entry.ok = true;
        entry.mailto = {
          to:          uri.slice("mailto:".length),
          subject:     "Report Domain: " + (report["organization-name"] || "") +
                       " Submitter: " + (report["organization-name"] || "") +
                       " Report-ID: <" + (report["report-id"] || "") + ">",
          contentType: "application/tlsrpt+gzip",
          encoding:    "gzip",
          body:        gzipped,
        };
      } else {
        entry.error = "unsupported rua URI scheme: " + uri.split(":")[0];
      }
    } catch (e) {
      entry.error = (e && e.message) || String(e);
    }
    results.push(entry);
  }
  return { submitted: results.length, results: results };
}

module.exports = {
  mtaSts: Object.freeze({
    fetch:   mtaStsFetch,
    matchMx: mtaStsMatchMx,
    parsePolicy: _parseStsPolicy,
  }),
  dane: Object.freeze({
    tlsa:        daneTlsa,
    recordShape: daneRecordShape,
  }),
  tlsRpt: Object.freeze({
    recordShape: tlsRptRecordShape,
    fetchPolicy: tlsRptFetchPolicy,
    submit:      tlsRptSubmit,
  }),
  SmtpPolicyError: SmtpPolicyError,
};
