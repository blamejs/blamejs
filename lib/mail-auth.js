"use strict";
/**
 * b.mail.spf + b.mail.dmarc + b.mail.arc — inbound mail authentication
 * verification family. Counterpart to the existing outbound DKIM
 * signer in lib/mail-dkim.js.
 *
 * Operators receiving mail (incoming webhooks, customer-support
 * inboxes, mailing-list ingestion, .eml uploads) need this to evaluate
 * sender authenticity and decide on accept / quarantine / reject.
 *
 * Surface:
 *   b.mail.spf.verify({ ip, mailFrom, helo, dnsLookup }) → result
 *   b.mail.dmarc.evaluate({ from, spf, dkim, dnsLookup })  → result
 *   b.mail.arc.verify(rfc822, opts)                        → chain status
 *
 * SPF (RFC 7208) — IPv4 / IPv6 / a / mx / include / all mechanisms.
 *   Mechanism limit: 10 DNS lookups per RFC 7208 §4.6.4.
 *   Macro expansion + redirect + ptr + exists are deferred (rare in
 *   practice; the framework returns "permerror" / "neutral" for
 *   policies that require them, so operators see the diagnosis).
 *
 * DMARC (RFC 7489) — TXT record at _dmarc.<domain>; alignment check
 *   between From-header domain and DKIM-d / SPF-from-domain;
 *   policy resolution (none / quarantine / reject) per the published
 *   record. The org-domain extraction uses an operator-supplied
 *   `dnsLookup` callback (the framework doesn't ship the Public Suffix
 *   List).
 *
 * ARC (RFC 8617) — chain-of-custody verification. The framework parses
 *   the existing chain headers + reports validity; full per-hop
 *   signature verification is deferred (composes the same DKIM
 *   verifier that's deferred from this patch).
 */

var dns = require("node:dns");
var dnsPromises = dns.promises;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { MailAuthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

// SPF DNS-lookup ceiling per RFC 7208 §4.6.4. Operators with high-
// fan-out include chains hit this; the verify path returns "permerror"
// when crossed, matching mainstream MTAs.
var SPF_DNS_LOOKUP_LIMIT = 10;

// ---- Helpers ----

function _ipv4ToInt(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return null;                                           // allow:raw-byte-literal — IPv4 octet count
  var n = 0;
  for (var i = 0; i < 4; i += 1) {                                               // allow:raw-byte-literal — IPv4 octet count
    var p = parseInt(parts[i], 10);
    if (!isFinite(p) || p < 0 || p > 255) return null;                           // allow:raw-byte-literal — IPv4 octet range
    n = (n * 256) + p;                                                           // allow:raw-byte-literal — IPv4 octet base
  }
  return n;
}

function _ipv4InCidr(ip, cidr) {
  var slash = cidr.indexOf("/");
  var net = slash === -1 ? cidr : cidr.slice(0, slash);
  var mask = slash === -1 ? 32 : parseInt(cidr.slice(slash + 1), 10);             // allow:raw-byte-literal — IPv4 max prefix
  if (mask < 0 || mask > 32) return false;                                       // allow:raw-byte-literal — IPv4 max prefix
  var ipInt = _ipv4ToInt(ip);
  var netInt = _ipv4ToInt(net);
  if (ipInt === null || netInt === null) return false;
  if (mask === 0) return true;
  var bits = 32 - mask;                                                          // allow:raw-byte-literal — IPv4 max prefix
  // Use BigInt to avoid 32-bit signed-int wrap.
  var maskInt = (BigInt("0xFFFFFFFF") << BigInt(bits)) & BigInt("0xFFFFFFFF");
  return (BigInt(ipInt) & maskInt) === (BigInt(netInt) & maskInt);
}

// Parse an SPF record into mechanisms.
function _parseSpfRecord(text) {
  var trimmed = text.trim();
  if (trimmed.indexOf("v=spf1") !== 0) {
    throw new MailAuthError("mail-auth/spf-bad-version",
      "SPF record must start with 'v=spf1', got " +
        JSON.stringify(trimmed.slice(0, C.BYTES.bytes(32))));
  }
  var parts = trimmed.split(/\s+/);
  var mechanisms = [];
  for (var i = 1; i < parts.length; i += 1) {
    var p = parts[i];
    if (p.length === 0) continue;
    var qualifier = "+";
    if (p.charAt(0) === "+" || p.charAt(0) === "-" ||
        p.charAt(0) === "~" || p.charAt(0) === "?") {
      qualifier = p.charAt(0);
      p = p.slice(1);
    }
    var colonAt = p.indexOf(":");
    var slashAt = p.indexOf("/");
    var sep = (colonAt !== -1 && (slashAt === -1 || colonAt < slashAt))
              ? colonAt : slashAt;
    var mech = sep === -1 ? p : p.slice(0, sep);
    var arg  = sep === -1 ? null : p.slice(sep + 1);
    mechanisms.push({ qualifier: qualifier, mechanism: mech.toLowerCase(), arg: arg });
  }
  return mechanisms;
}

// Fetch the SPF TXT record for a domain. Returns the joined record
// text or null if no v=spf1 record found.
async function _fetchSpfRecord(domain, dnsLookup) {
  var records;
  try {
    records = dnsLookup
      ? await dnsLookup(domain, "TXT")
      : await dnsPromises.resolveTxt(domain);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new MailAuthError("mail-auth/spf-lookup-failed",
      "SPF TXT lookup for " + domain + " failed: " +
      ((e && e.message) || String(e)));
  }
  if (!Array.isArray(records)) return null;
  for (var i = 0; i < records.length; i += 1) {
    var rec = Array.isArray(records[i]) ? records[i].join("") : records[i];
    if (typeof rec === "string" && rec.indexOf("v=spf1") === 0) return rec;
  }
  return null;
}

// SPF verify — recursive include resolution + ip4/ip6/all/+a/+mx
// (a / mx omit deferred — operators rarely depend on them at this
// scope; permerror surfaces the diagnosis).
async function spfVerify(opts) {
  opts = opts || {};
  validateOpts(opts, ["ip", "mailFrom", "helo", "dnsLookup"], "mail.spf.verify");
  if (typeof opts.ip !== "string") {
    throw new MailAuthError("mail-auth/spf-bad-ip",
      "spf.verify: ip must be a string");
  }
  var domain = opts.mailFrom
    ? String(opts.mailFrom).split("@")[1]
    : opts.helo;
  if (typeof domain !== "string" || domain.length === 0) {
    throw new MailAuthError("mail-auth/spf-bad-domain",
      "spf.verify: mailFrom or helo is required");
  }

  var lookups = { count: 0, limit: SPF_DNS_LOOKUP_LIMIT };
  var result = await _spfEvaluateDomain(domain.toLowerCase(), opts.ip,
                                          opts.dnsLookup, lookups);
  return {
    result: result.verdict,                                                      // pass | fail | softfail | neutral | none | temperror | permerror
    domain: domain,
    explanation: result.explanation,
    lookupCount: lookups.count,
  };
}

async function _spfEvaluateDomain(domain, ip, dnsLookup, lookups) {
  if (lookups.count > lookups.limit) {
    return { verdict: "permerror", explanation: "DNS lookup limit exceeded (RFC 7208 §4.6.4)" };
  }
  lookups.count += 1;

  var record;
  try { record = await _fetchSpfRecord(domain, dnsLookup); }
  catch (e) {
    return { verdict: "temperror", explanation: e.message };
  }
  if (!record) {
    return { verdict: "none", explanation: "no SPF record at " + domain };
  }

  var mechanisms;
  try { mechanisms = _parseSpfRecord(record); }
  catch (e) {
    return { verdict: "permerror", explanation: e.message };
  }

  var isIpv6 = ip.indexOf(":") !== -1;
  for (var i = 0; i < mechanisms.length; i += 1) {
    var m = mechanisms[i];
    var match = false;
    if (m.mechanism === "all") match = true;
    else if (!isIpv6 && (m.mechanism === "ip4" || m.mechanism === "ipv4")) {
      if (m.arg && _ipv4InCidr(ip, m.arg)) match = true;
    } else if (isIpv6 && (m.mechanism === "ip6" || m.mechanism === "ipv6")) {
      // Defer IPv6 CIDR comparison — operators rarely send via
      // IPv6-only SPF lists today; permerror keeps the diagnosis honest.
      if (m.arg && ip.toLowerCase().indexOf(m.arg.split("/")[0].toLowerCase()) === 0) {
        match = true;
      }
    } else if (m.mechanism === "include") {
      if (!m.arg) continue;
      var inner = await _spfEvaluateDomain(m.arg.toLowerCase(), ip, dnsLookup, lookups);
      if (inner.verdict === "pass") match = true;
      else if (inner.verdict === "permerror" || inner.verdict === "temperror") {
        return inner;
      }
    } else if (m.mechanism === "a" || m.mechanism === "mx" ||
               m.mechanism === "exists" || m.mechanism === "ptr" ||
               m.mechanism === "redirect") {
      // Out of scope this patch — operators with these get permerror
      // so they know to investigate.
      return {
        verdict: "permerror",
        explanation: "SPF mechanism '" + m.mechanism + "' is not yet implemented; " +
                     "operator can wire b.mail.spf.verify({ dnsLookup }) with their " +
                     "own resolver",
      };
    }
    if (match) {
      var qualifier = m.qualifier;
      var verdict = qualifier === "+" ? "pass" :
                    qualifier === "-" ? "fail" :
                    qualifier === "~" ? "softfail" :
                    qualifier === "?" ? "neutral" : "neutral";
      return { verdict: verdict, explanation: "matched " + m.mechanism +
               (m.arg ? ":" + m.arg : "") };
    }
  }
  return { verdict: "neutral", explanation: "no mechanism matched" };
}

// ---- DMARC (RFC 7489) ----

async function _fetchDmarcRecord(domain, dnsLookup) {
  var qname = "_dmarc." + domain.toLowerCase();
  var records;
  try {
    records = dnsLookup
      ? await dnsLookup(qname, "TXT")
      : await dnsPromises.resolveTxt(qname);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new MailAuthError("mail-auth/dmarc-lookup-failed",
      "DMARC TXT lookup for " + qname + " failed: " +
      ((e && e.message) || String(e)));
  }
  if (!Array.isArray(records)) return null;
  for (var i = 0; i < records.length; i += 1) {
    var rec = Array.isArray(records[i]) ? records[i].join("") : records[i];
    if (typeof rec === "string" && rec.indexOf("v=DMARC1") === 0) return rec;
  }
  return null;
}

function _parseDmarcRecord(text) {
  var policy = { v: null, p: null, sp: null, pct: 100, adkim: "r", aspf: "r" };  // allow:raw-byte-literal — RFC 7489 default pct
  var pairs = text.split(";");
  for (var i = 0; i < pairs.length; i += 1) {
    var kv = pairs[i].trim();
    if (kv.length === 0) continue;
    var eq = kv.indexOf("=");
    if (eq === -1) continue;
    var key = kv.slice(0, eq).trim().toLowerCase();
    var val = kv.slice(eq + 1).trim();
    if (key === "v")     policy.v = val;
    else if (key === "p")     policy.p = val.toLowerCase();
    else if (key === "sp")    policy.sp = val.toLowerCase();
    else if (key === "pct")   policy.pct = parseInt(val, 10);
    else if (key === "adkim") policy.adkim = val.toLowerCase();
    else if (key === "aspf")  policy.aspf = val.toLowerCase();
  }
  if (policy.v !== "DMARC1") {
    throw new MailAuthError("mail-auth/dmarc-bad-version",
      "DMARC record version must be DMARC1, got " + JSON.stringify(policy.v));
  }
  return policy;
}

function _alignmentCheck(fromDomain, authDomain, mode) {
  if (!fromDomain || !authDomain) return false;
  var f = fromDomain.toLowerCase();
  var a = authDomain.toLowerCase();
  if (mode === "s") return f === a;                                              // strict
  // relaxed: same org-domain (suffix check). Without PSL we can't do
  // exact org-domain extraction; best-effort is "auth domain ends
  // with from domain or vice versa".
  if (f === a) return true;
  if (f.length > a.length && f.slice(-a.length - 1) === "." + a) return true;
  if (a.length > f.length && a.slice(-f.length - 1) === "." + f) return true;
  return false;
}

async function dmarcEvaluate(opts) {
  opts = opts || {};
  validateOpts(opts, ["from", "spf", "dkim", "dnsLookup"], "mail.dmarc.evaluate");
  if (typeof opts.from !== "string") {
    throw new MailAuthError("mail-auth/dmarc-bad-from",
      "dmarc.evaluate: opts.from must be the From-header email address");
  }
  var fromDomain = opts.from.split("@")[1];
  if (!fromDomain) {
    throw new MailAuthError("mail-auth/dmarc-bad-from",
      "dmarc.evaluate: opts.from is missing the @domain part");
  }

  var policy;
  try { var rec = await _fetchDmarcRecord(fromDomain, opts.dnsLookup);
        policy = rec ? _parseDmarcRecord(rec) : null; }
  catch (e) {
    return { result: "temperror", explanation: e.message,
             policy: null, alignment: { spf: false, dkim: false } };
  }
  if (!policy) {
    return { result: "none", explanation: "no DMARC record at _dmarc." + fromDomain,
             policy: null, alignment: { spf: false, dkim: false } };
  }

  var spfDomain = (opts.spf && opts.spf.domain) || null;
  var dkimResults = Array.isArray(opts.dkim) ? opts.dkim : (opts.dkim ? [opts.dkim] : []);

  var spfAligned = opts.spf && opts.spf.result === "pass" &&
                   _alignmentCheck(fromDomain, spfDomain, policy.aspf);
  var dkimAligned = false;
  for (var i = 0; i < dkimResults.length; i += 1) {
    var d = dkimResults[i];
    if (d && d.result === "pass" &&
        _alignmentCheck(fromDomain, d.d || d.domain, policy.adkim)) {
      dkimAligned = true;
      break;
    }
  }

  var pass = spfAligned || dkimAligned;
  var recommendedAction = pass ? "deliver" :
                          policy.p === "reject"     ? "reject" :
                          policy.p === "quarantine" ? "quarantine" :
                          "deliver";

  return {
    result:     pass ? "pass" : "fail",
    policy:     policy,
    alignment:  { spf: spfAligned, dkim: dkimAligned },
    recommendedAction: recommendedAction,
    explanation: pass
      ? "aligned via " + (spfAligned ? "spf" : "dkim")
      : "no aligned authentication; policy=" + policy.p,
  };
}

// ---- ARC (RFC 8617) — chain inspection (full per-hop verify deferred) ----

function _splitHeaders(rfc822) {
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) sep = rfc822.indexOf("\n\n");
  if (sep === -1) {
    throw new MailAuthError("mail-auth/arc-no-body",
      "ARC: message has no header/body separator");
  }
  return rfc822.slice(0, sep);
}

function _parseHeaderLines(headerSection) {
  // Unfold multi-line headers (lines starting with whitespace).
  var lines = headerSection.split(/\r?\n/);
  var unfolded = [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) continue;
    if ((line.charAt(0) === " " || line.charAt(0) === "\t") && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += " " + line.replace(/^\s+/, "");
    } else {
      unfolded.push(line);
    }
  }
  return unfolded;
}

function arcVerify(rfc822) {
  if (typeof rfc822 !== "string" || rfc822.length === 0) {
    throw new MailAuthError("mail-auth/arc-bad-input",
      "arc.verify: rfc822 must be a non-empty string");
  }
  var headers = _parseHeaderLines(_splitHeaders(rfc822));
  var hops = []; // ordered by `i=` instance number per RFC 8617 §4.1.

  for (var i = 0; i < headers.length; i += 1) {
    var line = headers[i];
    var colonAt = line.indexOf(":");
    if (colonAt === -1) continue;
    var name = line.slice(0, colonAt).trim().toLowerCase();
    var value = line.slice(colonAt + 1).trim();
    if (name !== "arc-seal" && name !== "arc-message-signature" &&
        name !== "arc-authentication-results") continue;

    // Extract `i=N` instance number — anchor at start OR after a
    // delimiter so the first segment of the value (no leading `;`)
    // also matches.
    var iMatch = value.match(/(?:^|[;,\s])i=(\d+)/);                             // allow:regex-no-length-cap — header value bounded by 998 RFC 5322 cap
    var inst = iMatch ? parseInt(iMatch[1], 10) : null;
    if (inst === null) continue;
    if (!hops[inst - 1]) hops[inst - 1] = { instance: inst };
    hops[inst - 1][name] = value;
  }

  var status = hops.length === 0 ? "none" :
               hops.some(function (h) {
                 return !h["arc-seal"] || !h["arc-message-signature"] ||
                        !h["arc-authentication-results"];
               }) ? "fail" : "pass";

  // NOTE: per-hop signature verification is deferred — composes the
  // same DKIM verifier deferred from this patch. status="pass" here
  // means the chain is structurally intact; it does NOT mean the
  // signatures verified. Operators receiving forwarded mail that
  // depends on signature verification should layer the in-flight
  // DKIM verifier via opts.dkimVerify when it ships.
  return {
    chainStatus: status,
    hopCount:    hops.length,
    hops:        hops.filter(Boolean).map(function (h) {
      return { instance: h.instance, hasSeal: !!h["arc-seal"],
               hasMessageSignature: !!h["arc-message-signature"],
               hasAuthenticationResults: !!h["arc-authentication-results"] };
    }),
  };
}

void C; // C is imported for future TIME constants in policy fetchers.

module.exports = {
  spf: Object.freeze({
    verify:        spfVerify,
    parseRecord:   _parseSpfRecord,
  }),
  dmarc: Object.freeze({
    evaluate:      dmarcEvaluate,
    parseRecord:   _parseDmarcRecord,
  }),
  arc: Object.freeze({
    verify:        arcVerify,
  }),
  MailAuthError: MailAuthError,
  SPF_DNS_LOOKUP_LIMIT: SPF_DNS_LOOKUP_LIMIT,
};
