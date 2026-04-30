"use strict";
/**
 * mail-dkim — DKIM-Signature header generation for outbound mail.
 *
 * RFC 6376 (rsa-sha256) is the default; RFC 8463 (ed25519-sha256) is
 * available as opt-in. The two share the same signer surface so
 * operators flip algorithms by changing the `algorithm` opt and the
 * private key — no code change.
 *
 * Forward-looking: the DKIM-Signature `a=` tag carries an algorithm
 * identifier. When the IETF standardizes a post-quantum DKIM algorithm
 * (an SLH-DSA or ML-DSA variant), this module gains a third allowed
 * value alongside `rsa-sha256` and `ed25519-sha256`. The signer's
 * outer surface stays the same.
 *
 * Public API:
 *
 *   var signer = b.mail.dkim.create({
 *     domain:          "example.com",
 *     selector:        "s1",
 *     privateKey:      pemString | crypto.KeyObject,
 *     algorithm:       "rsa-sha256" (default) | "ed25519-sha256"
 *     headersToSign:   ["from","to","subject","date","message-id"]
 *                       (default — order matters in the signed string)
 *     canonicalization:"relaxed/relaxed" (default) | "simple/simple"
 *                      | "relaxed/simple" | "simple/relaxed"
 *     bodyLength:      number (optional `l=` cap; off by default)
 *     audit:           false (default true)
 *   });
 *
 *   var signedRfc822 = signer.sign(rfc822String);
 *
 * The signer never mutates the message object — it consumes the final
 * RFC 822 wire format produced by `mail._buildRfc822` and returns a
 * new string with the DKIM-Signature header prepended.
 *
 * Validation surface uses DkimError (FrameworkError subclass) with a
 * permanent flag — every problem here is a configuration / shape
 * problem, not a transient one.
 */
var lazyRequire = require("./lazy-require");
var audit       = lazyRequire(function () { return require("./audit"); });
var nodeCrypto  = require("crypto");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

class DkimError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "DkimError";
    this.permanent = true;
    this.isDkimError = true;
  }
}

var ALLOWED_ALGORITHMS = ["rsa-sha256", "ed25519-sha256"];
var ALLOWED_CANON = [
  "relaxed/relaxed",
  "simple/simple",
  "relaxed/simple",
  "simple/relaxed",
];
var DEFAULT_HEADERS = ["from", "to", "subject", "date", "message-id"];

// ---- Canonicalization (RFC 6376 §3.4) ----

function _canonHeaderRelaxed(name, value) {
  // Lowercase name, unfold continuations, collapse internal WSP runs to
  // single SP, strip leading/trailing WSP from value.
  var unfolded = String(value).replace(/\r?\n[ \t]+/g, " ");
  var trimmed = unfolded.replace(/[ \t]+/g, " ").replace(/^[ \t]+|[ \t]+$/g, "");
  return name.toLowerCase() + ":" + trimmed + "\r\n";
}

function _canonHeaderSimple(name, value) {
  // Preserve as-is. Used rarely in practice but spec-compliant.
  return name + ":" + value + "\r\n";
}

function _canonBodyRelaxed(body) {
  // 1) Reduce internal WSP runs in each line to a single SP, strip
  //    trailing WSP. 2) Strip empty lines at end of body. 3) Ensure
  //    a single trailing CRLF. Empty body → just "\r\n".
  if (!body) return "\r\n";
  var normalized = body.replace(/\r?\n/g, "\r\n");
  var lines = normalized.split("\r\n");
  for (var i = 0; i < lines.length; i++) {
    lines[i] = lines[i].replace(/[ \t]+/g, " ").replace(/[ \t]+$/, "");
  }
  // Drop trailing empty lines.
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  if (lines.length === 0) return "\r\n";
  return lines.join("\r\n") + "\r\n";
}

function _canonBodySimple(body) {
  // Strip trailing empty lines but otherwise preserve the body. Empty
  // body → "\r\n".
  if (!body) return "\r\n";
  var normalized = body.replace(/\r?\n/g, "\r\n");
  // Strip trailing empty lines.
  while (normalized.endsWith("\r\n\r\n")) {
    normalized = normalized.slice(0, -2);
  }
  if (!normalized.endsWith("\r\n")) normalized += "\r\n";
  return normalized;
}

// ---- RFC 822 split ----

function _splitHeadersBody(rfc822) {
  // Headers terminated by the first empty line. Headers may use folded
  // continuation lines (CRLF + WSP); we keep them folded and let the
  // canonicalizer unfold relaxed-mode.
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) {
    throw new DkimError("dkim/missing-body-separator",
      "rfc822 input has no header/body separator (CRLF CRLF)");
  }
  return {
    headers: rfc822.slice(0, sep + 2),  // include trailing CRLF after last header
    body:    rfc822.slice(sep + 4),
  };
}

function _parseHeaders(rawHeaders) {
  // Parse into [{ name, value }, ...] preserving order. Folded
  // continuation lines (start with WSP) are appended to the prior
  // header's value verbatim.
  var lines = rawHeaders.split("\r\n");
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    if (line[0] === " " || line[0] === "\t") {
      if (out.length > 0) out[out.length - 1].value += "\r\n" + line;
      continue;
    }
    var colon = line.indexOf(":");
    if (colon === -1) continue;
    out.push({
      name:  line.slice(0, colon),
      value: line.slice(colon + 1),  // preserve leading SP for simple canon
    });
  }
  return out;
}

// ---- Hashing + signing ----

function _bodyHashB64(body, algorithm, canonBody) {
  var canonicalized = canonBody === "simple"
    ? _canonBodySimple(body)
    : _canonBodyRelaxed(body);
  var hashName = "sha256";  // both rsa-sha256 and ed25519-sha256 hash with sha256
  return nodeCrypto.createHash(hashName)
    .update(canonicalized).digest("base64");
}

function _signString(strToSign, privateKey, algorithm) {
  if (algorithm === "rsa-sha256") {
    return nodeCrypto.createSign("RSA-SHA256")
      .update(strToSign).sign(privateKey).toString("base64");
  }
  if (algorithm === "ed25519-sha256") {
    // Ed25519 in node:crypto signs the raw message (it hashes
    // internally as part of EdDSA). Per RFC 8463 the verifier still
    // sees `a=ed25519-sha256` because the body hash is sha256.
    return nodeCrypto.sign(null, Buffer.from(strToSign, "utf8"), privateKey)
      .toString("base64");
  }
  throw new DkimError("dkim/bad-algorithm",
    "unknown algorithm: " + algorithm);
}

// ---- Signature header construction ----

function _foldSignatureHeader(unfolded) {
  // RFC 5322 §2.2.3 line length: 78 preferred, 998 max. The b= value
  // is long enough that folding helps readability and stays well clear
  // of the limit.
  var maxLine = 76;
  var name = "DKIM-Signature: ";
  var rest = unfolded;
  if ((name + rest).length <= maxLine) return name + rest;
  // Fold on tag boundaries (`; tag=value`). Keep the first chunk on
  // the header line, subsequent chunks on continuation lines starting
  // with TAB.
  var parts = rest.split("; ");
  var lines = [name + parts[0]];
  for (var i = 1; i < parts.length; i++) {
    lines.push("\t" + parts[i] + (i < parts.length - 1 ? ";" : ""));
  }
  return lines.join("\r\n");
}

// ---- Public surface ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "domain", "selector", "privateKey", "algorithm",
    "headersToSign", "canonicalization", "bodyLength", "audit",
  ], "mail.dkim.create");

  if (typeof opts.domain !== "string" || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(opts.domain)) {
    throw new DkimError("dkim/bad-domain",
      "domain must be a valid DNS name (e.g. 'example.com')");
  }
  if (typeof opts.selector !== "string" || !/^[a-z0-9_-]+$/i.test(opts.selector)) {
    throw new DkimError("dkim/bad-selector",
      "selector must be a non-empty token of [A-Za-z0-9_-]");
  }
  if (!opts.privateKey || (typeof opts.privateKey !== "string" &&
      typeof opts.privateKey !== "object")) {
    throw new DkimError("dkim/missing-private-key",
      "privateKey is required (PEM string or crypto.KeyObject)");
  }
  var algorithm = opts.algorithm || "rsa-sha256";
  if (ALLOWED_ALGORITHMS.indexOf(algorithm) === -1) {
    throw new DkimError("dkim/bad-algorithm",
      "algorithm must be one of: " + ALLOWED_ALGORITHMS.join(", "));
  }
  var canonicalization = opts.canonicalization || "relaxed/relaxed";
  if (ALLOWED_CANON.indexOf(canonicalization) === -1) {
    throw new DkimError("dkim/bad-canonicalization",
      "canonicalization must be one of: " + ALLOWED_CANON.join(", "));
  }
  var canonHeader = canonicalization.split("/")[0];
  var canonBody   = canonicalization.split("/")[1];

  var headersToSign = opts.headersToSign || DEFAULT_HEADERS;
  if (!Array.isArray(headersToSign) || headersToSign.length === 0) {
    throw new DkimError("dkim/bad-headers",
      "headersToSign must be a non-empty array of header names");
  }
  for (var i = 0; i < headersToSign.length; i++) {
    if (typeof headersToSign[i] !== "string" || headersToSign[i].length === 0) {
      throw new DkimError("dkim/bad-headers",
        "headersToSign[" + i + "] must be a non-empty string");
    }
  }
  if (opts.bodyLength !== undefined &&
      (typeof opts.bodyLength !== "number" || !isFinite(opts.bodyLength) || opts.bodyLength < 0)) {
    throw new DkimError("dkim/bad-body-length",
      "bodyLength must be a non-negative finite number");
  }

  var auditOn = opts.audit !== false;
  // Try to parse the private key once at create time so misconfigured
  // operators see the failure at boot rather than at first send().
  var keyObject;
  try {
    keyObject = typeof opts.privateKey === "string" || Buffer.isBuffer(opts.privateKey)
      ? nodeCrypto.createPrivateKey({ key: opts.privateKey, format: "pem" })
      : opts.privateKey;
  } catch (e) {
    throw new DkimError("dkim/bad-private-key",
      "privateKey could not be parsed: " + ((e && e.message) || String(e)));
  }

  function _emit(action, info) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   action,
      outcome:  info.outcome || "success",
      actor:    info.actor || {},
      metadata: {
        domain:     opts.domain,
        selector:   opts.selector,
        algorithm:  algorithm,
        bodyLength: info.bodyLength,
        durationMs: info.durationMs,
      },
      reason: info.reason || null,
    });
  }

  function sign(rfc822) {
    if (typeof rfc822 !== "string" || rfc822.length === 0) {
      throw new DkimError("dkim/bad-input",
        "sign() requires the rfc822 wire format as a non-empty string");
    }
    var t0 = Date.now();
    var split = _splitHeadersBody(rfc822);
    var parsedHeaders = _parseHeaders(split.headers);

    // Body hash
    var body = split.body;
    if (opts.bodyLength !== undefined) {
      body = body.slice(0, opts.bodyLength);
    }
    var bh = _bodyHashB64(body, algorithm, canonBody);

    // Build the unsigned DKIM-Signature header (b= empty).
    // Tag order follows RFC 6376 examples: v, a, c, d, s, h, bh, b.
    var sigTags = [
      "v=1",
      "a=" + algorithm,
      "c=" + canonicalization,
      "d=" + opts.domain,
      "s=" + opts.selector,
      "h=" + headersToSign.join(":"),
      "bh=" + bh,
    ];
    if (opts.bodyLength !== undefined) sigTags.push("l=" + opts.bodyLength);
    sigTags.push("b=");
    var unsignedSigValue = sigTags.join("; ");

    // Canonicalize the header set: each header in headersToSign (in
    // order, picking the LAST occurrence per RFC 6376 §5.4.2), then
    // the DKIM-Signature header itself with empty b=. The result is
    // what gets signed.
    var headerNamesLc = parsedHeaders.map(function (h) { return h.name.toLowerCase(); });
    var canonicalizedHeaders = "";
    for (var j = 0; j < headersToSign.length; j++) {
      var wantLc = headersToSign[j].toLowerCase();
      var idx = -1;
      for (var k = 0; k < headerNamesLc.length; k++) {
        if (headerNamesLc[k] === wantLc) idx = k;
      }
      if (idx === -1) continue;  // missing headers are skipped (signer's choice)
      var h = parsedHeaders[idx];
      canonicalizedHeaders += canonHeader === "simple"
        ? _canonHeaderSimple(h.name, h.value)
        : _canonHeaderRelaxed(h.name, h.value);
    }
    // Append the unsigned DKIM-Signature header without trailing CRLF
    // per RFC 6376 §3.7.
    var dkimHeaderForSigning = canonHeader === "simple"
      ? _canonHeaderSimple("DKIM-Signature", " " + unsignedSigValue)
      : _canonHeaderRelaxed("DKIM-Signature", unsignedSigValue);
    canonicalizedHeaders += dkimHeaderForSigning.replace(/\r\n$/, "");

    var signature = _signString(canonicalizedHeaders, keyObject, algorithm);
    // Replace the empty `b=` placeholder with the actual base64 signature.
    var finalSigValue = sigTags.slice(0, -1).concat(["b=" + signature]).join("; ");

    var dkimHeaderLine = _foldSignatureHeader(finalSigValue) + "\r\n";

    _emit("dkim.sign.success", {
      bodyLength: body.length,
      durationMs: Date.now() - t0,
    });

    return dkimHeaderLine + rfc822;
  }

  return {
    sign: sign,
    domain:    opts.domain,
    selector:  opts.selector,
    algorithm: algorithm,
  };
}

// Test-only exports for unit testing the canonicalization primitives
// directly without going through a full sign() round.
module.exports = {
  create:    create,
  DkimError: DkimError,
  _canonHeaderRelaxedForTest: _canonHeaderRelaxed,
  _canonBodyRelaxedForTest:   _canonBodyRelaxed,
  _canonBodySimpleForTest:    _canonBodySimple,
};
