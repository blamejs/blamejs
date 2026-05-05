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
var dkim = require("./mail-dkim");
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

// ---- ARC (RFC 8617) — full per-hop verification ----
//
// Each hop carries three headers — ARC-Authentication-Results (AAR),
// ARC-Message-Signature (AMS), ARC-Seal (AS). AMS verifies the
// message body + selected headers (DKIM-shaped signature). AS signs
// the chain-of-custody (all prior AAR/AMS/AS headers + own AAR/AMS
// with empty b=). Verification follows §5.1.1 (AMS) + §5.1.2 (AS).

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

// RFC 8617 §5.1.2 caps the chain at 50 sets to bound verifier work and
// limit how far an attacker can push junk headers.
var ARC_MAX_HOPS = 50;                                                           // allow:raw-byte-literal — RFC 8617 §5.1.2 chain ceiling

async function arcVerify(rfc822, opts) {
  if (typeof rfc822 !== "string" || rfc822.length === 0) {
    throw new MailAuthError("mail-auth/arc-bad-input",
      "arc.verify: rfc822 must be a non-empty string");
  }
  opts = opts || {};
  var headers = _parseHeaderLines(_splitHeaders(rfc822));
  var hops = [];
  var seenSlot = {};                                                             // {`<instance>:<name>`: true} — duplicate detection

  // 1. Index ARC headers by instance number. Refuse duplicates: a single
  //    hop has exactly one ARC-Seal / ARC-Message-Signature /
  //    ARC-Authentication-Results. A second copy at the same instance is
  //    a malformed chain (per RFC 8617 §5.1 implicit, and a known
  //    injection vector — a forwarder that re-signs with a duplicate
  //    instance would silently overwrite the original signer).
  var duplicate = false;
  var maxInstanceSeen = 0;
  for (var i = 0; i < headers.length; i += 1) {
    var line = headers[i];
    var colonAt = line.indexOf(":");
    if (colonAt === -1) continue;
    var name = line.slice(0, colonAt).trim().toLowerCase();
    var value = line.slice(colonAt + 1).trim();
    if (name !== "arc-seal" && name !== "arc-message-signature" &&
        name !== "arc-authentication-results") continue;
    var iMatch = value.match(/(?:^|[;,\s])i=(\d+)/);                             // allow:regex-no-length-cap — header bounded by RFC 5322 998
    var inst = iMatch ? parseInt(iMatch[1], 10) : null;
    if (inst === null || !isFinite(inst) || inst < 1) continue;
    if (inst > maxInstanceSeen) maxInstanceSeen = inst;
    var slotKey = inst + ":" + name;
    if (seenSlot[slotKey]) { duplicate = true; continue; }
    seenSlot[slotKey] = true;
    if (!hops[inst - 1]) hops[inst - 1] = { instance: inst };
    hops[inst - 1][name] = value;
  }

  if (hops.length === 0) {
    return { chainStatus: "none", hopCount: 0, hops: [] };
  }

  if (duplicate) {
    return {
      chainStatus: "fail",
      reason:      "duplicate-instance",
      hopCount:    hops.filter(Boolean).length,
      hops: hops.filter(Boolean).map(function (h) {
        return { instance: h.instance,
                 hasSeal: !!h["arc-seal"],
                 hasMessageSignature: !!h["arc-message-signature"],
                 hasAuthenticationResults: !!h["arc-authentication-results"],
                 amsResult: "skipped", asResult: "skipped" };
      }),
    };
  }

  if (maxInstanceSeen > ARC_MAX_HOPS) {
    return {
      chainStatus: "fail",
      reason:      "too-many-hops",
      hopCount:    maxInstanceSeen,
      hops:        [],
    };
  }

  // 2. Structural check — every hop must carry all three headers AND
  //    the chain must start at i=1 with no gaps. RFC 8617 §5.1 requires
  //    instances to form a contiguous 1..N sequence. Indexed loop (not
  //    .some) because sparse arrays skip empty slots in callbacks —
  //    a non-contiguous chain ([hop1, , hop3]) would silently pass.
  var structuralFail = false;
  for (var sci = 0; sci < hops.length; sci += 1) {
    var sch = hops[sci];
    if (!sch || !sch["arc-seal"] || !sch["arc-message-signature"] ||
        !sch["arc-authentication-results"]) {
      structuralFail = true;
      break;
    }
  }
  if (structuralFail) {
    return {
      chainStatus: "fail",
      reason:      "incomplete-or-non-contiguous",
      hopCount:    hops.filter(Boolean).length,
      hops: hops.filter(Boolean).map(function (h) {
        return { instance: h.instance,
                 hasSeal: !!h["arc-seal"],
                 hasMessageSignature: !!h["arc-message-signature"],
                 hasAuthenticationResults: !!h["arc-authentication-results"],
                 amsResult: "skipped", asResult: "skipped" };
      }),
    };
  }

  // 3. Per-hop AMS + AS verification.
  var perHop = [];
  var anyFail = false;

  for (var hopIdx = 0; hopIdx < hops.length; hopIdx += 1) {
    var hop = hops[hopIdx];

    // AMS — RFC 8617 §5.1.1. Same shape as a DKIM-Signature; reuses
    // the DKIM verifier by injecting a temporary message that has
    // the AMS as the signing header.
    var amsResult = await _verifyArc(rfc822, hop, hops, "ams", opts.dnsLookup, dkim);

    // AS — RFC 8617 §5.1.2. Signs the catenation of all prior
    // ARC-{AAR,AMS,AS} headers plus current AAR + AMS, then the AS
    // itself with empty b=.
    var asResult = await _verifyArc(rfc822, hop, hops, "as", opts.dnsLookup, dkim);

    perHop.push({
      instance:                 hop.instance,
      hasSeal:                  true,
      hasMessageSignature:      true,
      hasAuthenticationResults: true,
      amsResult:                amsResult.result,
      asResult:                 asResult.result,
      amsErrors:                amsResult.errors,
      asErrors:                 asResult.errors,
    });
    if (amsResult.result !== "pass" || asResult.result !== "pass") anyFail = true;
  }

  // 4. Chain Validation per RFC 8617 §5.2.
  //
  //    Per-hop cv= self-attestation rules:
  //      i=1   — cv=none REQUIRED (no upstream chain to validate)
  //      i>=2  — cv=pass or cv=fail; cv=none is invalid at i>=2
  //
  //    Once any hop's AS reports cv=fail, the chain is permanently
  //    broken — downstream cv=pass claims after an upstream cv=fail
  //    are malformed (a hop can't claim the chain validates when it
  //    knows an earlier hop saw it fail).
  var perHopCv = [];
  var hopRuleViolation = null;
  var sawFail = false;
  for (var hi = 0; hi < hops.length; hi += 1) {
    var as = hops[hi]["arc-seal"];
    var hopCvMatch = as.match(/(?:^|[;,\s])cv=(none|pass|fail)/);
    var hopCv = hopCvMatch ? hopCvMatch[1] : null;
    perHopCv.push(hopCv);
    if (hopCv === null) {
      hopRuleViolation = "missing-cv-at-i=" + (hi + 1);
      break;
    }
    if (hi === 0 && hopCv !== "none") {
      hopRuleViolation = "i=1-cv-must-be-none-got-" + hopCv;
      break;
    }
    if (hi >= 1 && hopCv === "none") {
      hopRuleViolation = "i=" + (hi + 1) + "-cv=none-invalid-after-hop-1";
      break;
    }
    if (hopCv === "fail") sawFail = true;
    if (hopCv === "pass" && sawFail) {
      hopRuleViolation = "i=" + (hi + 1) + "-cv=pass-after-upstream-fail";
      break;
    }
  }

  var lastCv = perHopCv[perHopCv.length - 1];
  var chainStatus;
  var reasonOut = null;
  if (hopRuleViolation) {
    chainStatus = "fail";
    reasonOut = hopRuleViolation;
  } else if (anyFail) {
    chainStatus = "fail";
    reasonOut = "signature-verification-failed";
  } else if (lastCv === "fail") {
    chainStatus = "fail";
    reasonOut = "last-as-cv=fail";
  } else if (hops.length === 1 && lastCv === "none") {
    chainStatus = "pass";
  } else if (hops.length > 1 && lastCv === "pass") {
    chainStatus = "pass";
  } else {
    chainStatus = "fail";
    reasonOut = "unexpected-cv-state";
  }

  var out = {
    chainStatus: chainStatus,
    hopCount:    hops.length,
    cv:          lastCv,
    perHopCv:    perHopCv,
    hops:        perHop,
  };
  if (reasonOut) out.reason = reasonOut;
  return out;
}

// Verify a single AMS or AS within the chain by reconstructing the
// signed string per RFC 8617 + invoking node:crypto.verify with the
// public key fetched from the AMS's d= + s= TXT record.
async function _verifyArc(rfc822, hop, allHops, kind, dnsLookup, dkim) {
  var sigHeaderName = kind === "ams" ? "arc-message-signature" : "arc-seal";
  var sigValue = hop[sigHeaderName];
  var tags = _parseArcTagList(sigValue);
  if (!tags.d || !tags.s || !tags.b || !tags.a) {
    return { result: "permerror", errors: [kind + ": missing required tag(s) d/s/b/a"] };
  }
  if (tags.a !== "rsa-sha256" && tags.a !== "ed25519-sha256") {
    return { result: "permerror", errors: [kind + ": unsupported alg '" + tags.a + "'"] };
  }

  // Fetch the signing public key from <s>._domainkey.<d>.
  var keyTags;
  try {
    var qname = tags.s + "._domainkey." + tags.d;
    var records;
    if (dnsLookup) records = await dnsLookup(qname, "TXT");
    else {
      var dnsModule = require("node:dns/promises");
      records = await dnsModule.resolveTxt(qname);
    }
    keyTags = _parseDkimKeyRecord(records);
  } catch (e) {
    var verdict = (e && (e.code === "ENOTFOUND" || e.code === "ENODATA"))
                  ? "permerror" : "temperror";
    return { result: verdict, errors: [kind + ": key lookup failed: " +
             ((e && e.message) || String(e))] };
  }
  if (!keyTags || !keyTags.p) {
    return { result: "permerror", errors: [kind + ": key record missing p="] };
  }

  // Reconstruct the canonical signed string.
  var canonicalized;
  if (kind === "ams") {
    // AMS signs the body + selected headers, identical to DKIM-Sig.
    // Reuse the DKIM verifier by passing a synthetic message where
    // the AMS header is renamed to DKIM-Signature.
    return await _verifyAmsViaDkim(rfc822, hop, sigValue, tags, dkim, dnsLookup);
  }

  // AS signs the catenation of every prior AAR/AMS/AS plus current
  // AAR/AMS, then the AS itself with empty b= per RFC 8617 §5.1.2.
  canonicalized = "";
  for (var prior = 0; prior < hop.instance; prior += 1) {
    var p = allHops[prior];
    if (!p) continue;
    canonicalized += _canonRelaxedHeader("ARC-Authentication-Results", p["arc-authentication-results"]);
    canonicalized += _canonRelaxedHeader("ARC-Message-Signature",      p["arc-message-signature"]);
    if (p.instance !== hop.instance) {
      // Prior AS gets included whole.
      canonicalized += _canonRelaxedHeader("ARC-Seal", p["arc-seal"]);
    }
  }
  // Current AS with b= emptied. RFC 8617 §5.1.2: canonicalization
  // includes the AS header with `b=` value stripped + no trailing CRLF.
  var asUnsigned = sigValue.replace(/(\bb=)[^;]*/i, "$1");
  canonicalized += _canonRelaxedHeader("ARC-Seal", asUnsigned).replace(/\r\n$/, "");

  // Verify the AS signature.
  return _runVerify(canonicalized, tags.b, tags.a, keyTags.p, "as");
}

async function _verifyAmsViaDkim(rfc822, hop, sigValue, tags, dkim, dnsLookup) {
  // Build a synthetic rfc822 where the ARC-Message-Signature is renamed
  // to DKIM-Signature so the existing DKIM verifier handles AMS
  // verification (the cryptographic shape is identical).
  var renamedHeader = "DKIM-Signature: " + sigValue;
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) sep = rfc822.indexOf("\n\n");
  var headerEnd = sep === -1 ? rfc822.length : sep;
  // Strip every other ARC-* header so the DKIM verifier doesn't see
  // them, AND replace the AMS itself with DKIM-Signature for this hop.
  var headerLines = _parseHeaderLines(rfc822.slice(0, headerEnd));
  var rebuilt = [];
  for (var i = 0; i < headerLines.length; i += 1) {
    var line = headerLines[i];
    var colonAt = line.indexOf(":");
    if (colonAt === -1) { rebuilt.push(line); continue; }
    var name = line.slice(0, colonAt).trim().toLowerCase();
    if (name === "arc-message-signature" ||
        name === "arc-seal" ||
        name === "arc-authentication-results" ||
        name === "dkim-signature") {
      // Drop pre-existing ARC + DKIM headers from the synthetic.
      continue;
    }
    rebuilt.push(line);
  }
  rebuilt.unshift(renamedHeader);
  var synthetic = rebuilt.join("\r\n") + (sep === -1 ? "" :
    rfc822.slice(headerEnd));
  var rv = await dkim.verify(synthetic, { dnsLookup: dnsLookup });
  if (!Array.isArray(rv) || rv.length === 0) {
    return { result: "permerror", errors: ["ams: dkim verifier returned no results"] };
  }
  return { result: rv[0].result, errors: rv[0].errors || [] };
}

function _parseArcTagList(value) {
  var tags = {};
  var parts = String(value).split(";");
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    tags[p.slice(0, eq).trim().toLowerCase()] = p.slice(eq + 1).trim().replace(/\s+/g, "");
  }
  return tags;
}

function _parseDkimKeyRecord(records) {
  var joined = "";
  if (Array.isArray(records)) {
    for (var i = 0; i < records.length; i += 1) {
      var rec = records[i];
      joined = Array.isArray(rec) ? rec.join("") : String(rec);
      if (joined.indexOf("v=DKIM1") === 0 || joined.indexOf("p=") !== -1) break;
    }
  } else {
    joined = String(records || "");
  }
  return _parseArcTagList(joined);
}

function _canonRelaxedHeader(name, value) {
  // RFC 6376 §3.4.2 — relaxed header canon: lowercase name, unfold,
  // collapse internal WSP runs, strip trailing WSP.
  var unfolded = String(value).replace(/\r?\n[ \t]+/g, " ");
  var trimmed = unfolded.replace(/[ \t]+/g, " ").replace(/^[ \t]+|[ \t]+$/g, "");
  return name.toLowerCase() + ":" + trimmed + "\r\n";
}

function _pemFromB64KeyMaterial(b64) {
  var pem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < b64.length; i += 64) {                                     // allow:raw-byte-literal — PEM wrap width
    pem += b64.slice(i, i + 64) + "\n";                                          // allow:raw-byte-literal — PEM wrap width
  }
  pem += "-----END PUBLIC KEY-----\n";
  return pem;
}

function _runVerify(signedString, sigB64, algorithm, keyB64, label) {
  var nodeCrypto = require("node:crypto");
  var pem = _pemFromB64KeyMaterial(keyB64);
  var keyObj;
  try { keyObj = nodeCrypto.createPublicKey(pem); }
  catch (e) {
    return { result: "permerror",
             errors: [label + ": key parse failed: " + ((e && e.message) || String(e))] };
  }
  var nodeAlgo = algorithm === "rsa-sha256" ? "sha256" : null;
  var sigBuf = Buffer.from(sigB64, "base64");
  var verified;
  try {
    verified = nodeCrypto.verify(nodeAlgo, Buffer.from(signedString, "utf8"), keyObj, sigBuf);
  } catch (e) {
    return { result: "permerror",
             errors: [label + ": verify threw: " + ((e && e.message) || String(e))] };
  }
  return verified
    ? { result: "pass", errors: [] }
    : { result: "fail", errors: [label + ": signature verification failed"] };
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
