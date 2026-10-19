// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// SMOKE_RUN_SOLO: growth checks here compare wall-clock time across input sizes, which a CPU shared with the smoke pool distorts.
/**
 * b.redact.installOutboundDlp + b.redact.classifyDefaults — outbound
 * DLP scanner + interceptor wiring.
 *
 * Run standalone: `node test/layer-0-primitives/redact-dlp.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var childProcess = require("node:child_process");
var http = require("node:http");
var path = require("node:path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (event) { captured.push(event); },
    captured: captured,
    byAction: function (action) {
      return captured.filter(function (e) { return e.action === action; });
    },
  };
}

function _fakeHttpClient() {
  var sent = [];
  return {
    sent:    sent,
    request: function (opts) {
      sent.push(opts);
      return Promise.resolve({ statusCode: 200, headers: {}, body: Buffer.from("ok") });
    },
  };
}

function _fakeMail() {
  var sent = [];
  return {
    sent: sent,
    send: function (msg) {
      sent.push(msg);
      return Promise.resolve({ accepted: true });
    },
  };
}

function _fakeWebhookSigner() {
  var sent = [];
  return {
    sent: sent,
    send: function (input) {
      sent.push(input);
      return Promise.resolve({ statusCode: 200 });
    },
  };
}

function testSurface() {
  check("b.redact.classifyDefaults is a function", typeof b.redact.classifyDefaults === "function");
  check("b.redact.installOutboundDlp is a function", typeof b.redact.installOutboundDlp === "function");
  check("b.redact.CLASSIFIER_PATTERNS frozen", Object.isFrozen(b.redact.CLASSIFIER_PATTERNS));
  check("CLASSIFIER_PATTERNS includes pan", typeof b.redact.CLASSIFIER_PATTERNS.pan === "object");
  check("CLASSIFIER_PATTERNS includes phi-shape", typeof b.redact.CLASSIFIER_PATTERNS["phi-shape"] === "object");
  check("DlpError class exposed", typeof b.redact.DlpError === "function");
}

// A classifier spec is a `detect` predicate plus an action, matching the
// shipped CLASSIFIER_PATTERNS entries.
function _looksLikeToken(v) {
  return typeof v === "string" && v.indexOf("tok_") === 0;
}

function testClassifierRejectsBadOpts() {
  var threw;
  threw = false;
  try { b.redact.classifyDefaults({ patterns: [] }); } catch (_e) { threw = true; }
  check("classifyDefaults rejects empty patterns", threw);

  threw = false;
  try { b.redact.classifyDefaults({ patterns: ["nonexistent"] }); } catch (_e) { threw = true; }
  check("classifyDefaults rejects unknown pattern", threw);

  threw = false;
  try { b.redact.classifyDefaults({ patterns: [123] }); } catch (_e) { threw = true; }
  check("classifyDefaults rejects non-string pattern", threw);

  // The unknown-pattern check reads `opts.extra[name]` through the prototype,
  // so once an operator supplies ANY extra pattern, "constructor" / "toString"
  // / "valueOf" resolve to inherited functions and pass as known names. The
  // scanner then reaches a function where a pattern spec should be and throws
  // an untyped error at scan time — a DLP classifier failing open at the
  // moment it is asked to look, instead of refusing at boot.
  var protoNames = ["constructor", "toString", "valueOf", "hasOwnProperty"];
  for (var i = 0; i < protoNames.length; i += 1) {
    var caught = null;
    try {
      b.redact.classifyDefaults({
        patterns: [protoNames[i]],
        extra: { "my-token": { detect: _looksLikeToken, action: "refuse" } },
      });
    } catch (e) { caught = e; }
    check("classifyDefaults refuses the prototype name '" + protoNames[i] + "' at config time",
          caught !== null && caught.code === "redact-dlp/unknown-pattern",
          String(caught && (caught.code || caught.message)));
  }

  // Control: a real `extra` pattern must still be accepted by name, or the
  // refusals above could be a check that rejects every extra.
  var ok = null;
  try {
    var c = b.redact.classifyDefaults({
      patterns: ["my-token"],
      extra: { "my-token": { detect: _looksLikeToken, action: "refuse" } },
    });
    ok = c({ body: { note: "tok_abc" } });
  } catch (e) { ok = e; }
  check("classifyDefaults control: an operator-supplied extra pattern still works",
        ok && ok.verdict === "refuse", JSON.stringify(ok && (ok.verdict || ok.message)));
}

function testClassifyPan() {
  var classify = b.redact.classifyDefaults({ patterns: ["pan", "credit-card"] });
  // 4111-1111-1111-1111 is a valid Luhn-passing test PAN.
  var result = classify({ body: { card: "4111-1111-1111-1111" } });
  check("classify detects valid PAN", result.verdict === "refuse");
  check("classify hits include pan or credit-card",
    result.hits.some(function (h) { return h.label === "pan" || h.label === "credit-card"; }));

  var clean = classify({ body: { card: "4111-1111-1111-1112" } });  // bad luhn
  check("classify ignores invalid PAN", clean.verdict === "clean");
}

function testClassifySsn() {
  var classify = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var result = classify({ body: { note: "patient ssn 123-45-6789 confirmed" } });
  check("classify detects SSN", result.verdict === "redact");
  check("classify redacted body scrubs SSN",
    String(result.redactedBody.note).indexOf("123-45-6789") === -1);
}

function testClassifyJwtAndAwsKey() {
  var classify = b.redact.classifyDefaults({ patterns: ["jwt", "aws-access-key"] });
  // Build a JWS-shaped token at runtime so no hard-coded literal lands
  // in source. The shape eyJ... . eyJ... . sig matches the detector.
  var jwt = ["eyJ", "ABCDef0_-", "."].join("") +
            ["eyJ", "QRSTuv1_-", "."].join("") +
            "signaturepart";
  // AWS access-key shape: AKIA + 16 [A-Z0-9].
  var aws = "AKIA" + "BCDEFGHIJKLMNOPQ";
  check("classify flags JWT", classify({ body: { tok: jwt } }).verdict === "redact");
  check("classify flags AWS access key", classify({ body: { secret: aws } }).verdict === "refuse");
}

function testClassifyHeaders() {
  var classify = b.redact.classifyDefaults({ patterns: ["pan"] });
  var r = classify({ body: { ok: true }, headers: { "x-card-number": "4111-1111-1111-1111" } });
  check("classify scans headers", r.verdict === "refuse");
  check("classify hit reports header location",
    r.hits.some(function (h) { return h.where && h.where.indexOf("headers.") === 0; }));
}

async function testInstallHttpClientRefuse() {
  var client = _fakeHttpClient();
  var auditMock = _captureAudit();
  // Patch global audit to capture (the redact module uses lazyRequire(audit)).
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { auditMock.captured.push(e); };

  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  check("install registers httpClient", handle.installed.httpClient === true);

  var threw = false;
  try {
    await client.request({ url: "https://example.com/x", body: { card: "4111111111111111" } });
  } catch (e) { threw = e; }
  b.audit.safeEmit = origAudit;
  check("httpClient.request refuses on PAN", threw && threw.code === "redact-dlp/refused");
  check("audit emitted dlp.outbound.refused",
    auditMock.captured.some(function (e) { return e.action === "dlp.outbound.refused"; }));
  check("audit emitted dlp.outbound.installed",
    auditMock.captured.some(function (e) { return e.action === "dlp.outbound.installed"; }));
  handle.uninstall();
  // After uninstall, the request should pass through.
  await client.request({ url: "https://example.com/x", body: { card: "4111111111111111" } });
  check("after uninstall, request passes through", client.sent.length === 1);
}

async function testInstallHttpClientRedact() {
  var client = _fakeHttpClient();
  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    classifier: b.redact.classifyDefaults({ patterns: ["ssn"] }),
  });
  await client.request({ url: "https://example.com/x", body: { note: "ssn 123-45-6789" } });
  check("redacted body sent to httpClient", client.sent.length === 1);
  var sentBody = client.sent[0].body;
  check("sent body scrubs SSN",
    JSON.stringify(sentBody).indexOf("123-45-6789") === -1);
  handle.uninstall();
}

async function testInstallMail() {
  var mail = _fakeMail();
  var handle = b.redact.installOutboundDlp({
    mail: mail,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  var threw = false;
  try {
    await mail.send({ to: "x@y", subject: "card", text: "use 4111-1111-1111-1111", html: "<p>4111-1111-1111-1111</p>" });
  } catch (e) { threw = e; }
  check("mail.send refuses on PAN", threw && threw.code === "redact-dlp/refused");
  handle.uninstall();
}

async function testInstallWebhook() {
  var signer = _fakeWebhookSigner();
  var handle = b.redact.installOutboundDlp({
    webhook: signer,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  var threw = false;
  try {
    await signer.send({ url: "https://example.com/hook", body: JSON.stringify({ card: "4111-1111-1111-1111" }) });
  } catch (e) { threw = e; }
  check("webhook.send refuses on PAN in JSON body", threw && threw.code === "redact-dlp/refused");
  handle.uninstall();
}

// A value on the wire is scanned whatever JavaScript type carries it: a PAN
// in a numeric JSON field, or text handed over as a Buffer inside the body.
// 4111111111111111110 is a 19-digit Luhn-valid PAN; JSON.parse rounds it to
// 4111111111111111000, which is not Luhn-valid, so only the wire text shows
// the PAN.
var PAN19 = "4111111111111111110";

function testClassifyNonStringLeaves() {
  var classify = b.redact.classifyDefaults({ patterns: ["pan"] });
  var rNum = classify({ body: { card: 4111111111111111 } });
  check("classify scans a number leaf: a numeric PAN is refused", rNum.verdict === "refuse",
    JSON.stringify(rNum.hits));
  var rBig = classify({ body: { card: BigInt("4111111111111111") } });
  check("classify scans a bigint leaf: a bigint PAN is refused", rBig.verdict === "refuse");
  var rBuf = classify({ body: { card: Buffer.from("4111111111111111") } });
  check("classify scans a nested Buffer leaf: a PAN inside it is refused", rBuf.verdict === "refuse");
  var rArr = classify({ body: { cards: [Buffer.from("4111 1111 1111 1111")] } });
  check("classify scans a Buffer inside an array", rArr.verdict === "refuse");

  var classifySsn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var rSsn = classifySsn({ body: { s: Buffer.from("ssn 123-45-6789") } });
  check("classify redacts an SSN inside a nested Buffer", rSsn.verdict === "redact" &&
    Buffer.isBuffer(rSsn.redactedBody.s) &&
    rSsn.redactedBody.s.toString("utf8").indexOf("123-45-6789") === -1,
    rSsn.redactedBody && String(rSsn.redactedBody.s));

  var classifyCtl = b.redact.classifyDefaults({ patterns: ["pan"] });
  var rCtl = classifyCtl({ body: { n: 42, ok: true, buf: Buffer.from("hello") } });
  check("control: an ordinary number, boolean and Buffer stay clean and unchanged",
    rCtl.verdict === "clean" && rCtl.redactedBody.n === 42 && rCtl.redactedBody.ok === true &&
    Buffer.isBuffer(rCtl.redactedBody.buf));

  // About one 13-digit millisecond timestamp in ten passes the Luhn check.
  // A numeric timestamp is not a card number and must not be refused.
  var ts = LUHN_VALID_MS_TIMESTAMP;
  var rTs = b.redact.classifyDefaults({ patterns: ["pan", "credit-card"] })(
    { body: { created: ts, createdUs: ts * 1000 } });
  check("a Luhn-valid numeric millisecond timestamp is not classified as a card number",
    rTs.verdict === "clean" && rTs.redactedBody.created === ts, JSON.stringify(rTs.hits));
}

function _luhn(s) {
  var sum = 0;
  var alt = false;
  for (var i = s.length - 1; i >= 0; i -= 1) {
    var d = s.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}
var LUHN_VALID_MS_TIMESTAMP = (function () {
  for (var t = 1760000000000; ; t += 1) { if (_luhn(String(t))) return t; }
})();

async function testWebhookScansNumericAndWireText() {
  var signer = _fakeWebhookSigner();
  var handle = b.redact.installOutboundDlp({
    webhook: signer,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  try {
    var threwNum = null;
    try { await signer.send({ url: "https://example.com/hook", body: '{"card":4111111111111111}' }); }
    catch (e) { threwNum = e; }
    check("webhook.send refuses a PAN carried as a JSON number",
      threwNum && threwNum.code === "redact-dlp/refused" && signer.sent.length === 0,
      threwNum ? threwNum.code : "sent " + signer.sent.length);

    var threwRound = null;
    try { await signer.send({ url: "https://example.com/hook", body: '{"card":' + PAN19 + "}" }); }
    catch (e) { threwRound = e; }
    check("webhook.send refuses a PAN that JSON.parse rounds, by scanning the wire text",
      threwRound && threwRound.code === "redact-dlp/refused" && signer.sent.length === 0,
      threwRound ? threwRound.code : "sent " + signer.sent.length);

    await signer.send({ url: "https://example.com/hook", body: '{"n":42}' });
    check("control: a clean JSON body is sent unchanged",
      signer.sent.length === 1 && signer.sent[0].body === '{"n":42}');

    var tsBody = '{"created":' + LUHN_VALID_MS_TIMESTAMP + ',"note":"x 1.5e3"}';
    await signer.send({ url: "https://example.com/hook", body: tsBody });
    check("control: a JSON body carrying a Luhn-valid millisecond timestamp is sent unchanged",
      signer.sent.length === 2 && signer.sent[1].body === tsBody);
  } finally { handle.uninstall(); }

  // The raw wire text is redacted when only the raw scan finds the value.
  var signer2 = _fakeWebhookSigner();
  var handle2 = b.redact.installOutboundDlp({
    webhook: signer2,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"], overrideAction: "redact" }),
  });
  try {
    var body2 = '{"card":' + PAN19 + ',"ref":"' + PAN19 + 'x","n":12345678901234567890}';
    await signer2.send({ url: "https://example.com/hook", body: body2 });
    var sent2 = signer2.sent[0] && String(signer2.sent[0].body);
    var parsed2 = null;
    try { parsed2 = JSON.parse(sent2); } catch (_e) { parsed2 = null; }
    check("webhook.send redacts a rounded PAN literal in the wire text and keeps the JSON valid",
      signer2.sent.length === 1 && parsed2 !== null && typeof parsed2.card === "string" &&
      sent2.indexOf('"card":' + PAN19) === -1, sent2);
    check("and leaves the other fields of the wire text as they were",
      parsed2 !== null && parsed2.ref === PAN19 + "x" && sent2.indexOf("12345678901234567890") !== -1,
      sent2);
  } finally { handle2.uninstall(); }
}

// A Luhn-valid 16-digit number whose first digit is 8, held exactly by a
// JavaScript number.
var PAN8 = (function () {
  for (var t = 8100000000000000; ; t += 1) { if (_luhn(String(t))) return t; }
})();

async function _sendThroughDlp(classifier, body, hooks) {
  var signer = _fakeWebhookSigner();
  var installOpts = { webhook: signer, classifier: classifier };
  var seen = { refused: null, redacted: null };
  installOpts.onRefuse = function (ev) { seen.refused = ev.verdict; if (hooks && hooks.onRefuse) hooks.onRefuse(ev); };
  installOpts.onRedact = function (ev) { seen.redacted = ev.verdict; };
  var handle = b.redact.installOutboundDlp(installOpts);
  var threw = null;
  try { await signer.send({ url: "https://example.com/hook", body: body }); }
  catch (e) { threw = e; }
  finally { handle.uninstall(); }
  return {
    threw:    threw,
    sent:     signer.sent.length > 0 ? String(signer.sent[0].body) : null,
    refused:  seen.refused,
    redacted: seen.redacted,
  };
}

function _labels(verdict) {
  return verdict ? verdict.hits.map(function (h) { return h.label + "@" + h.where; }) : [];
}

async function testWebhookScansWhatItSends() {
  var first16 = PAN19.slice(0, 16);

  // Both the parsed body and a JSON-rounded PAN literal need redacting.
  var r1 = await _sendThroughDlp(
    b.redact.classifyDefaults({ patterns: ["pan", "ssn"], overrideAction: "redact" }),
    '{"card":' + PAN19 + ',"note":"ssn 123-45-6789"}');
  check("webhook redact: a rounded PAN literal is removed when the parsed body is redacted too",
    r1.sent !== null && r1.sent.indexOf(first16) === -1 && r1.sent.indexOf("123-45-6789") === -1,
    r1.threw ? r1.threw.code : r1.sent);
  check("webhook redact: the redacted body is valid JSON",
    (function () { try { JSON.parse(r1.sent); return true; } catch (_e) { return false; } })(), r1.sent);
  var l1 = _labels(r1.redacted);
  check("webhook redact: the hook and audit hits carry both the pan and the ssn hit",
    l1.indexOf("pan@body.card") !== -1 && l1.indexOf("ssn@body.note") !== -1, JSON.stringify(l1));

  // Refuse: the parsed scan's hits are kept beside the wire scan's.
  var r2 = await _sendThroughDlp(
    b.redact.classifyDefaults({ patterns: ["pan", "ssn"] }),
    '{"card":' + PAN19 + ',"note":"123-45-6789"}');
  var l2 = _labels(r2.refused);
  check("webhook refuse: the refusal lists the ssn hit and names the PAN by its field",
    r2.threw && r2.threw.code === "redact-dlp/refused" &&
    l2.indexOf("ssn@body.note") !== -1 && l2.indexOf("pan@body.card") !== -1, JSON.stringify(l2));

  // A classifier that serializes its input sees only JSON-serializable values.
  var serializing = function (input) {
    JSON.stringify(input.body);
    return { verdict: "clean", hits: [], redactedBody: input.body };
  };
  var r3 = await _sendThroughDlp(serializing, '{"id":18446744073709551615,"msg":"hello"}');
  check("webhook: a clean body with a 64-bit id passes a classifier that serializes its input",
    r3.threw === null && r3.sent === '{"id":18446744073709551615,"msg":"hello"}',
    r3.threw ? r3.threw.message : r3.sent);
  var r3b = await _sendThroughDlp(serializing, '{"id":4611686018427387904}');
  check("webhook: a card-shaped 64-bit id reaches a serializing classifier as a string",
    r3b.threw === null && r3b.sent === '{"id":4611686018427387904}',
    r3b.threw ? r3b.threw.message : r3b.sent);

  // A repeated member name: JSON.parse keeps the last, the wire carries both.
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var r4 = await _sendThroughDlp(pan, '{"card":4111111111111111,"card":"x"}');
  check("webhook refuses a numeric PAN under a repeated member name",
    r4.threw && r4.threw.code === "redact-dlp/refused" && r4.sent === null, r4.sent);
  var r5 = await _sendThroughDlp(pan, '{"card":"4111111111111111","card":"x"}');
  check("webhook refuses a string PAN under a repeated member name",
    r5.threw && r5.threw.code === "redact-dlp/refused" && r5.sent === null, r5.sent);
  var r6 = await _sendThroughDlp(pan, '{"a":{"card":"4111111111111111"},"a":1}');
  check("webhook refuses a PAN nested in a member a later duplicate replaces",
    r6.threw && r6.threw.code === "redact-dlp/refused" && r6.sent === null, r6.sent);
  // A prototype key: the parser drops it, the wire carries it.
  var r7 = await _sendThroughDlp(pan, '{"__proto__":{"card":"4111111111111111"},"id":1}');
  check("webhook refuses a PAN inside a __proto__ member that the parse drops",
    r7.threw && r7.threw.code === "redact-dlp/refused" && r7.sent === null, r7.sent);
  var r8 = await _sendThroughDlp(
    b.redact.classifyDefaults({ patterns: ["pan"], overrideAction: "redact" }),
    '{"card":"4111111111111111","card":"x","n":12345678901234567890}');
  check("webhook redact: a PAN under a repeated member name is not in the sent body",
    r8.sent !== null && r8.sent.indexOf("4111111111111111") === -1, r8.sent);
  check("webhook redact: an unredacted 64-bit integer keeps its exact digits",
    r8.sent !== null && r8.sent.indexOf("12345678901234567890") !== -1, r8.sent);
  var r9 = await _sendThroughDlp(pan, '{"card":"x","card":"y"}');
  check("control: a repeated member name with no sensitive value is sent unchanged",
    r9.threw === null && r9.sent === '{"card":"x","card":"y"}', r9.sent);

  // Card ranges whose first digit is 7-9.
  var r10 = b.redact.classifyDefaults({ patterns: ["pan"] })({ body: { card: PAN8 } });
  check("classify refuses a numeric PAN whose first digit is 8", r10.verdict === "refuse",
    JSON.stringify(r10.hits));
  var r11 = b.redact.redact({ n: PAN8 });
  check("redact: a numeric card number whose first digit is 8 is redacted",
    r11.n !== PAN8 && typeof r11.n === "string", JSON.stringify(r11));
  var r12 = await _sendThroughDlp(pan, '{"card":' + PAN8 + "}");
  check("webhook refuses a numeric PAN whose first digit is 8",
    r12.threw && r12.threw.code === "redact-dlp/refused", r12.sent);
}

// A redaction a classifier makes to a number the parse rounded is what goes on
// the wire; the exact literal is restored only where the value was left alone.
// Restoring the literals of a large array costs time linear in its length.
async function testWebhookExactLiteralsRespectRedactions() {
  var zeroing = function (input) {
    var out = Object.assign({}, input.body, { id: 0 });
    return { verdict: "redact", hits: [{ label: "id", where: "body.id" }], redactedBody: out };
  };
  var r1 = await _sendThroughDlp(zeroing, '{"id":10000000000000001,"keep":18446744073709551615}');
  check("webhook redact: a classifier's numeric replacement of a rounded integer is sent",
    r1.sent !== null && r1.sent.indexOf("10000000000000001") === -1 && /"id":0\b/.test(r1.sent),
    r1.threw ? r1.threw.code : r1.sent);
  check("webhook redact: an untouched rounded integer next to it keeps its exact digits",
    r1.sent !== null && r1.sent.indexOf("18446744073709551615") !== -1, r1.sent);

  var redactSsn = b.redact.classifyDefaults({ patterns: ["ssn"], overrideAction: "redact" });
  function _body(n) {
    var ids = [];
    var first = BigInt("10000000000000001");
    for (var i = 0; i < n; i += 1) ids.push((first + BigInt(i * 2)).toString());
    return '{"ids":[' + ids.join(",") + '],"note":"ssn 123-45-6789"}';
  }
  var probe = await _sendThroughDlp(redactSsn, _body(3));
  check("control: the array body is redacted and keeps its exact literals",
    probe.sent !== null && probe.sent.indexOf("123-45-6789") === -1 &&
    probe.sent.indexOf("10000000000000001") !== -1, probe.sent);
  var growth = await helpers.looksSuperlinearAsync(function (n) {
    return _sendThroughDlp(redactSsn, _body(n));
  }, { small: 5000, large: 20000, threshold: 8, label: "webhook redact: exact-literal restore over a large array" });
  check("webhook redact: restoring exact literals in a large array costs time linear in its length",
    growth.superlinear === false, JSON.stringify(growth));
}

// A PAN that JSON.parse rounds is found however the number is spelled: with a
// fraction, an exponent, or both. A number the parse cannot hold exactly keeps
// its literal text when another field is redacted.
var PAN19_SPELLINGS = [
  PAN19 + ".0", PAN19 + "e0", "4.11111111111111111e18", "41111111111111111100e-1",
  "-" + PAN19 + ".0", "0." + PAN19 + "e19", PAN19 + ".00E+0", "4111111111111111.110e3",
];

async function testWebhookScansRoundedPanInEverySpelling() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var redactPan = b.redact.classifyDefaults({ patterns: ["pan"], overrideAction: "redact" });
  var leaked = [];
  var kept = [];
  for (var i = 0; i < PAN19_SPELLINGS.length; i += 1) {
    var s = PAN19_SPELLINGS[i];
    var r = await _sendThroughDlp(pan, '{"card":' + s + "}");
    if (!(r.threw && r.threw.code === "redact-dlp/refused" && r.sent === null)) leaked.push(s + " -> " + r.sent);
    var rr = await _sendThroughDlp(redactPan, '{"card":' + s + ',"n":1}');
    var parsed = null;
    try { parsed = JSON.parse(rr.sent); } catch (_e) { parsed = null; }
    if (parsed === null || typeof parsed.card !== "string" || parsed.n !== 1 ||
        rr.sent.indexOf(s) !== -1) {
      kept.push(s + " -> " + rr.sent);
    }
  }
  check("webhook refuses a rounded PAN written with a fraction or an exponent",
    leaked.length === 0, leaked.join("; "));
  check("webhook redact: a rounded PAN written with a fraction or an exponent is replaced",
    kept.length === 0, kept.join("; "));

  var controls = ["3.14", "1e400", "-1e999999", "1e-999999", "12345678901234567890.0", "0.0", "1e2"];
  var refused = [];
  for (var c = 0; c < controls.length; c += 1) {
    var body = '{"v":' + controls[c] + "}";
    var rc = await _sendThroughDlp(pan, body);
    if (rc.threw !== null || rc.sent !== body) refused.push(controls[c] + " -> " + (rc.threw ? rc.threw.code : rc.sent));
  }
  check("control: a float, an out-of-range exponent and a 20-digit integer are sent unchanged",
    refused.length === 0, refused.join("; "));

  var redactSsn = b.redact.classifyDefaults({ patterns: ["ssn"], overrideAction: "redact" });
  var exact = ["1e400", "-1e999999", "1e-999999", "12345678901234567890.0", "0.10000000000000000000001"];
  var rewritten = [];
  for (var e = 0; e < exact.length; e += 1) {
    var re = await _sendThroughDlp(redactSsn, '{"v":' + exact[e] + ',"note":"ssn 123-45-6789"}');
    if (re.sent === null || re.sent.indexOf('"v":' + exact[e] + ",") === -1 ||
        re.sent.indexOf("123-45-6789") !== -1) {
      rewritten.push(exact[e] + " -> " + re.sent);
    }
  }
  check("webhook redact: a number the parse cannot hold exactly keeps its literal text",
    rewritten.length === 0, rewritten.join("; "));
  var r314 = await _sendThroughDlp(redactSsn, '{"v":3.14,"z":0.0,"note":"ssn 123-45-6789"}');
  check("control: a number the parse holds exactly is written as JSON.stringify writes it",
    r314.sent === '{"v":3.14,"z":0,"note":"ssn [REDACTED]"}', r314.sent);
}

// Scanning the wire text of a deep, wide body takes memory in proportion to the
// body, not to the body times its nesting depth. Each case runs in a child
// process with a small heap.
var WIRE_WALK_HEAP_MB = 96;

// mode "send": the body is sent unchanged. "refuse": it is refused. "redact":
// it is sent with every unit replaced.
var WIRE_WALK_EXPECT = { send: "sent 1 true", refuse: "threw redact-dlp/refused", redact: "sent 1 redacted" };

function _wireWalkInChild(depth, unit, mode) {
  mode = mode || "send";
  var redactPath = path.resolve(__dirname, "..", "..", "lib", "redact.js");
  var script = [
    "var redact = require(" + JSON.stringify(redactPath) + ");",
    "var depth = " + depth + ", unit = " + JSON.stringify(unit) + ";",
    "var count = Math.floor((1048576 - 2 * depth - 16) / (unit.length + 1));",
    "var body = '['.repeat(depth) + new Array(count).fill(unit).join(',') + ']'.repeat(depth);",
    "var sent = [];",
    "var signer = { send: function (i) { sent.push(i); return Promise.resolve({}); } };",
    "var hits = 0;",
    "redact.installOutboundDlp({ webhook: signer, onScan: function (ev) { hits = ev.verdict.hits.length; },",
    "  classifier: redact.classifyDefaults({ patterns: ['pan']" +
      (mode === "redact" ? ", overrideAction: 'redact'" : "") + " }) });",
    "signer.send({ url: 'https://example.com/hook', body: body }).then(function () {",
    "  var b0 = sent[0] && sent[0].body;",
    "  process.stdout.write('sent ' + sent.length + ' ' + (b0 === body ? 'true' :",
    "    (typeof b0 === 'string' && b0.indexOf(unit) === -1 && hits === count ? 'redacted' : 'changed')));",
    "}, function (e) { process.stdout.write('threw ' + (e && e.code)); });",
  ].join("\n");
  var out = childProcess.spawnSync(process.execPath,
    ["--max-old-space-size=" + WIRE_WALK_HEAP_MB, "-e", script], { encoding: "utf8", timeout: 60000 });
  return { ok: out.status === 0 && out.stdout === WIRE_WALK_EXPECT[mode],
    detail: "depth " + depth + " unit " + unit + " mode " + mode + ": status " + out.status +
      " signal " + out.signal + " stdout " + out.stdout + " stderr " + String(out.stderr || "").slice(0, 160) };
}

async function testWebhookWireWalkMemoryIsBoundedByTheBody() {
  var flat = _wireWalkInChild(1, '""');
  check("control: a 1 MiB flat array of strings is scanned and sent within a " + WIRE_WALK_HEAP_MB + " MB heap",
    flat.ok, flat.detail);
  var flatHits = _wireWalkInChild(1, PAN19, "refuse");
  check("control: a 1 MiB flat array of rounded PANs is refused within a " + WIRE_WALK_HEAP_MB + " MB heap",
    flatHits.ok, flatHits.detail);
  var cases = [[96, '""'], [96, "1"], [96, '{"a":""}'], [96, "10000000000000001"],
    [96, PAN19, "refuse"], [96, PAN19, "redact"], [96, "4.11111111111111111e18", "refuse"],
    [1000, '""'], [1000, '{"a":"x"}'], [1000, PAN19, "refuse"]];
  for (var i = 0; i < cases.length; i += 1) {
    var mode = cases[i][2] || "send";
    var r = _wireWalkInChild(cases[i][0], cases[i][1], mode);
    check("webhook: a 1 MiB body nested " + cases[i][0] + " deep of " + cases[i][1] +
      " is " + (mode === "send" ? "scanned and sent" : mode === "refuse" ? "refused" : "redacted") +
      " within a " + WIRE_WALK_HEAP_MB + " MB heap", r.ok, r.detail);
  }

  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  function _deepBody(n) {
    return "[".repeat(96) + new Array(n).fill('"a"').join(",") + "]".repeat(96);
  }
  var growth = await helpers.looksSuperlinearAsync(function (n) {
    return _sendThroughDlp(pan, _deepBody(n));
  }, { small: 40000, large: 80000, threshold: 3, label: "webhook: wire walk over a deep, wide body" });
  check("webhook: scanning a deep, wide body costs time linear in its width",
    growth.superlinear === false, JSON.stringify(growth));
}

async function _requestThroughDlp(classifier, reqOpts) {
  var client = _fakeHttpClient();
  var seen = { refused: null, redacted: null, redactedOpts: null };
  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    classifier: classifier,
    onRefuse:   function (ev) { seen.refused = ev.verdict; },
    onRedact:   function (ev) { seen.redacted = ev.verdict; seen.redactedOpts = ev.opts; },
  });
  var threw = null;
  var syncThrew = null;
  try {
    var pending = null;
    try { pending = client.request(reqOpts); }
    catch (e) { syncThrew = e; }
    if (syncThrew === null) await pending;
  } catch (e) { threw = e; }
  finally { handle.uninstall(); }
  var sentOpts = client.sent.length > 0 ? client.sent[0] : null;
  return {
    threw:        syncThrew !== null ? syncThrew : threw,
    syncThrew:    syncThrew,
    sentOpts:     sentOpts,
    sent:         sentOpts !== null ? sentOpts.body : null,
    refused:      seen.refused,
    redacted:     seen.redacted,
    redactedOpts: seen.redactedOpts,
  };
}

async function _httpThroughDlp(classifier, body) {
  return _requestThroughDlp(classifier, { url: "https://example.com/x", body: body });
}

function _refused(r) {
  return r.threw !== null && r.threw.code === "redact-dlp/refused" && r.sent === null;
}

// A 13-digit millisecond timestamp that fails the Luhn check.
var NOT_LUHN_MS_TIMESTAMP = (function () {
  for (var t = 1760000000000; ; t += 1) { if (!_luhn(String(t))) return t; }
})();

// A 13-digit millisecond timestamp that passes the Luhn check.
var LUHN_MS_TIMESTAMP = (function () {
  for (var t = 1760000000000; ; t += 1) { if (_luhn(String(t))) return t; }
})();

// A string is checked for a card number at every run of digits in it, so a
// timestamp or an order number written before the card does not hide it.
async function testPanDetectorChecksEveryDigitRun() {
  var strings = [
    "ts " + NOT_LUHN_MS_TIMESTAMP + " card 4111111111111111",
    "ts=" + NOT_LUHN_MS_TIMESTAMP + "&card=4111111111111111",
    "order 2024 4111 1111 1111 1111",
    "ref " + NOT_LUHN_MS_TIMESTAMP + "-4111-1111-1111-1111",
  ];
  var names = ["pan", "credit-card"];
  var missed = [];
  for (var n = 0; n < names.length; n += 1) {
    var classify = b.redact.classifyDefaults({ patterns: [names[n]] });
    for (var s = 0; s < strings.length; s += 1) {
      var r = classify({ body: { note: strings[s] } });
      if (r.verdict !== "refuse") missed.push(names[n] + ": " + strings[s]);
    }
  }
  check("classify finds a card number after a digit run that is not one", missed.length === 0,
    missed.join("; "));
  var textLeft = [];
  for (var ts = 0; ts < strings.length; ts += 1) {
    var scrubbed = b.redact.redactText(strings[ts]);
    if (/4111.?1111.?1111.?1111/.test(scrubbed)) textLeft.push(strings[ts] + " -> " + scrubbed);
  }
  check("redactText removes a card number after a digit run that is not one", textLeft.length === 0,
    textLeft.join("; "));
  check("control: redactText keeps a digit run that is not a card number",
    b.redact.redactText("order 2024 4111 1111 1111 1112") === "order 2024 4111 1111 1111 1112" &&
    b.redact.redactText("ts " + NOT_LUHN_MS_TIMESTAMP + " x") === "ts " + NOT_LUHN_MS_TIMESTAMP + " x");

  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var wh1 = await _sendThroughDlp(pan, JSON.stringify({ note: strings[0] }));
  check("webhook refuses a JSON string value with a card number after a timestamp", _refused(wh1), wh1.sent);
  var wh2 = await _sendThroughDlp(pan, strings[1]);
  check("webhook refuses a form body with a card number after a timestamp", _refused(wh2), wh2.sent);
  var hc = await _httpThroughDlp(pan,
    '{"ts":' + NOT_LUHN_MS_TIMESTAMP + ',"card":"4111111111111111"}');
  check("httpClient refuses a JSON string body with a card number after a timestamp", _refused(hc),
    String(hc.sent));

  var controls = [
    "ts " + NOT_LUHN_MS_TIMESTAMP + " card 4111111111111112",
    "order 2024 4111 1111 1111 1112",
    "ts " + NOT_LUHN_MS_TIMESTAMP + " and " + NOT_LUHN_MS_TIMESTAMP,
  ];
  var flagged = [];
  for (var cn = 0; cn < names.length; cn += 1) {
    var classifyCtl = b.redact.classifyDefaults({ patterns: [names[cn]] });
    for (var c = 0; c < controls.length; c += 1) {
      if (classifyCtl({ body: { note: controls[c] } }).verdict !== "clean") flagged.push(names[cn] + ": " + controls[c]);
    }
  }
  check("control: strings whose digit runs all fail the Luhn check stay clean", flagged.length === 0,
    flagged.join("; "));

  var detect = b.redact.CLASSIFIER_PATTERNS.pan.detect;
  var growth = helpers.superlinearRatio(function (n) {
    detect("4111 1111 1111 1112 ".repeat(n));
    b.redact.redactText("2024 4111 1111 1111 1112 ".repeat(n));
  }, { small: 20000, large: 80000, threshold: 8, label: "pan detector over many digit runs" });
  check("checking every digit run of a string costs time linear in its length",
    growth.superlinear === false, JSON.stringify(growth));
}

// A rounded PAN written with a fraction or an exponent is found in a body that
// is scanned as text: a webhook string that safeJson.parse refuses, and an
// httpClient body given as a string or as bytes.
async function testRawTextScansRoundedPanInEverySpelling() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var pad = "x".repeat(1048576);
  var leaked = [];
  for (var i = 0; i < PAN19_SPELLINGS.length; i += 1) {
    var s = PAN19_SPELLINGS[i];
    var shapes = [
      ["webhook over 1 MiB", "webhook", '{"card":' + s + ',"pad":"' + pad + '"}'],
      ["webhook deeper than 100", "webhook", "[".repeat(120) + s + "]".repeat(120)],
      ["webhook form body", "webhook", "card=" + s + "&x=1"],
      ["httpClient string", "http", '{"card":' + s + "}"],
      ["httpClient bytes", "http", Buffer.from('{"card":' + s + "}")],
    ];
    for (var k = 0; k < shapes.length; k += 1) {
      var r = shapes[k][1] === "webhook"
        ? await _sendThroughDlp(pan, shapes[k][2])
        : await _httpThroughDlp(pan, shapes[k][2]);
      if (!_refused(r)) leaked.push(shapes[k][0] + " " + s);
    }
  }
  check("a rounded PAN with a fraction or an exponent is refused in a body scanned as text",
    leaked.length === 0, leaked.join("; "));

  var redactPan = b.redact.classifyDefaults({ patterns: ["pan"], overrideAction: "redact" });
  var kept = [];
  for (var j = 0; j < PAN19_SPELLINGS.length; j += 1) {
    var sp = PAN19_SPELLINGS[j];
    var text = '{"card":' + sp + ',"n":1}';
    var outs = [
      ["httpClient string", (await _httpThroughDlp(redactPan, text)).sent],
      ["httpClient bytes", (await _httpThroughDlp(redactPan, Buffer.from(text))).sent],
      ["webhook over 1 MiB", (await _sendThroughDlp(redactPan, '{"card":' + sp + ',"n":1,"pad":"' + pad + '"}')).sent],
    ];
    for (var o = 0; o < outs.length; o += 1) {
      var sent = outs[o][1];
      var asText = Buffer.isBuffer(sent) ? sent.toString("utf8") : sent;
      var parsed = null;
      try { parsed = JSON.parse(asText); } catch (_e) { parsed = null; }
      if (o === 1 && !Buffer.isBuffer(sent)) parsed = null;
      if (parsed === null || typeof parsed.card !== "string" || parsed.n !== 1 || asText.indexOf(sp) !== -1) {
        kept.push(outs[o][0] + " " + sp + " -> " + String(asText).slice(0, 60));
      }
    }
  }
  check("redact: a rounded PAN with a fraction or an exponent is replaced in a body scanned as text",
    kept.length === 0, kept.join("; "));
  var inString = await _httpThroughDlp(redactPan,
    '{"note":"v 4.11111111111111111e18 \\" 4.11111111111111111e18","n":4.11111111111111111e18}');
  var inStringParsed = null;
  try { inStringParsed = JSON.parse(inString.sent); } catch (_e) { inStringParsed = null; }
  check("redact: a number inside a JSON string value of a text body is replaced inside the string",
    inStringParsed !== null && inStringParsed.note === 'v [REDACTED] " [REDACTED]' &&
    inStringParsed.n === "[REDACTED]", String(inString.sent));

  var controls = ["3.14", "1e400", "-1e999999", "1e-999999", "12345678901234567890.0", "0.0", "1e2", "1.5e3"];
  var changed = [];
  for (var c = 0; c < controls.length; c += 1) {
    var body = '{"v":' + controls[c] + "}";
    var hr = await _httpThroughDlp(pan, body);
    if (hr.threw !== null || hr.sent !== body) changed.push("httpClient " + controls[c]);
    var big = '{"v":' + controls[c] + ',"pad":"' + pad + '"}';
    var wr = await _sendThroughDlp(pan, big);
    if (wr.threw !== null || wr.sent !== big) changed.push("webhook " + controls[c]);
  }
  check("control: ordinary and out-of-range numbers in a body scanned as text are sent unchanged",
    changed.length === 0, changed.join("; "));

  // A classifier that reports a redact hit on a wire value without changing
  // it: the value is replaced with the marker rather than sent as written.
  var hitOnly = function (input) {
    if (!Array.isArray(input.body)) return { verdict: "clean", hits: [], redactedBody: input.body };
    return { verdict: "redact", hits: [{ label: "x", action: "redact", where: "body[0]" }],
      redactedBody: input.body };
  };
  var hw = await _sendThroughDlp(hitOnly, '{"card":' + PAN19 + "}");
  check("webhook redact: a redacted rounded PAN the classifier left unchanged is not sent",
    hw.sent !== null && hw.sent.indexOf(PAN19) === -1 && JSON.parse(hw.sent).card === "[REDACTED]", hw.sent);
  var hh = await _httpThroughDlp(hitOnly, '{"card":4.11111111111111111e18}');
  check("httpClient redact: a redacted exponent PAN the classifier left unchanged is not sent",
    hh.sent === '{"card":"[REDACTED]"}', String(hh.sent));
  var auditOnly = function (input) {
    if (!Array.isArray(input.body)) return { verdict: "redact", hits: [], redactedBody: input.body };
    return { verdict: "audit-only", hits: [{ label: "x", action: "audit-only", where: "body[0]" }],
      redactedBody: input.body };
  };
  var ha = await _sendThroughDlp(auditOnly, '{"card":' + PAN19 + "}");
  check("control: a wire value with only an audit-only hit keeps its literal text",
    ha.sent === '{"card":' + PAN19 + "}", ha.sent);

  var growth = await helpers.looksSuperlinearAsync(function (n) {
    return _httpThroughDlp(pan, "[" + new Array(n).fill("1.5e3").join(",") + "]");
  }, { small: 50000, large: 200000, threshold: 8, label: "httpClient: number scan over a text body" });
  check("scanning the numbers of a text body costs time linear in its length",
    growth.superlinear === false, JSON.stringify(growth));
}

function _sentText(r) {
  if (r.sent === null) return null;
  return Buffer.isBuffer(r.sent) ? r.sent.toString("utf8") : r.sent;
}

function _jsonOf(text) {
  try { return JSON.parse(text); } catch (_e) { return undefined; }
}

// An httpClient body given as JSON text, as a string or as bytes, is
// classified parsed as well as scanned as text. A value written behind a JSON
// escape, and a value that an anchored detector matches only as a whole
// string, are found the way the webhook finds them.
async function testHttpClientJsonTextIsClassifiedParsed() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var escaped = [
    '{"card":"\\u0034111111111111111"}',
    '{"note":"line\\n4111111111111111"}',
    '{"note":"tab\\t4111 1111 1111 1111"}',
    '[{"deep":["x\\u000a4111111111111111"]}]',
  ];
  var leaked = [];
  for (var i = 0; i < escaped.length; i += 1) {
    var w = await _sendThroughDlp(pan, escaped[i]);
    if (!_refused(w)) leaked.push("webhook " + escaped[i]);
    var hs = await _httpThroughDlp(pan, escaped[i]);
    if (!_refused(hs)) leaked.push("httpClient string " + escaped[i]);
    var hb = await _httpThroughDlp(pan, Buffer.from(escaped[i], "utf8"));
    if (!_refused(hb)) leaked.push("httpClient bytes " + escaped[i]);
  }
  check("httpClient refuses a card number written behind a JSON escape, as the webhook does",
    leaked.length === 0, leaked.join("; "));

  var jwt = ["eyJ", "ABCDef0_-", "."].join("") + ["eyJ", "QRSTuv1_-", "."].join("") + "signaturepart";
  var apiKey = "K9" + "a".repeat(30);
  var iban = "GB82" + "WEST" + "12345698765432";
  var anchored = [
    ["jwt", '{"tok":"' + jwt + '","n":1}', "tok"],
    ["api-key-shape", '{"key":"' + apiKey + '","n":1}', "key"],
  ];
  var missed = [];
  for (var a = 0; a < anchored.length; a += 1) {
    var cls = b.redact.classifyDefaults({ patterns: [anchored[a][0]] });
    var bodies = [anchored[a][1], Buffer.from(anchored[a][1], "utf8")];
    for (var bi = 0; bi < bodies.length; bi += 1) {
      var ra = await _httpThroughDlp(cls, bodies[bi]);
      var parsed = _jsonOf(_sentText(ra));
      if (ra.threw !== null || !parsed || parsed[anchored[a][2]] !== "[REDACTED]" || parsed.n !== 1 ||
          Buffer.isBuffer(ra.sent) !== Buffer.isBuffer(bodies[bi])) {
        missed.push(anchored[a][0] + (bi ? " bytes" : " string") + " -> " + String(_sentText(ra)));
      }
    }
  }
  var ri = await _httpThroughDlp(b.redact.classifyDefaults({ patterns: ["iban"] }), '{"iban":"' + iban + '"}');
  if (!_refused(ri)) missed.push("iban -> " + String(_sentText(ri)));
  check("httpClient finds a JWT, an api-key-shaped value and an IBAN inside a JSON text body",
    missed.length === 0, missed.join("; "));

  var redactPan = b.redact.classifyDefaults({ patterns: ["pan"], overrideAction: "redact" });
  var escText = '{"card":"\\u0034111111111111111","n":1}';
  var rs = await _httpThroughDlp(redactPan, escText);
  var rb = await _httpThroughDlp(redactPan, Buffer.from(escText, "utf8"));
  var ps = _jsonOf(_sentText(rs));
  var pb = _jsonOf(_sentText(rb));
  check("httpClient redact: an escaped card number in a JSON text body is replaced and the body stays JSON",
    typeof rs.sent === "string" && ps && ps.card === "[REDACTED]" && ps.n === 1 &&
    Buffer.isBuffer(rb.sent) && pb && pb.card === "[REDACTED]" && pb.n === 1,
    String(_sentText(rs)) + " | " + String(_sentText(rb)));

  // The text scan still runs: a classifier that reads only text bodies sees
  // the JSON text it saw before.
  var textOnly = function (input) {
    if (typeof input.body === "string" && input.body.indexOf("marker-x") !== -1) {
      return { verdict: "refuse", hits: [{ label: "marker", action: "refuse", where: "body" }], redactedBody: input.body };
    }
    return { verdict: "clean", hits: [], redactedBody: input.body };
  };
  var rt = await _httpThroughDlp(textOnly, '{"note":"marker-x"}');
  check("httpClient: a classifier that reads only text bodies is still given the JSON text",
    _refused(rt), String(_sentText(rt)));
  var rm = await _httpThroughDlp(pan, '{"4111111111111111":1}');
  check("httpClient refuses a card number as a member name of a JSON text body", _refused(rm),
    String(_sentText(rm)));

  var clean = [
    '{ "a" : "x",\n  "n": 12345678901234567890, "f": 1.50, "e": "\\u00e9" }',
    '[1, 2.0, "3", null, true, {"k": []}]',
    '"just a string"',
  ];
  var altered = [];
  for (var c = 0; c < clean.length; c += 1) {
    var cs = await _httpThroughDlp(pan, clean[c]);
    if (cs.threw !== null || cs.sent !== clean[c]) altered.push("string " + clean[c]);
    var buf = Buffer.from(clean[c], "utf8");
    var cb = await _httpThroughDlp(pan, buf);
    if (cb.threw !== null || cb.sent !== buf) altered.push("bytes " + clean[c]);
  }
  check("control: a clean JSON text body is sent through httpClient as given",
    altered.length === 0, altered.join("; "));
}

// A member name is scanned at every depth. A member name that would need
// redacting is refused, since renaming a member changes what the body means.
async function testMemberNamesAreScanned() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var r1 = pan({ body: { "4111111111111111": 1 } });
  check("classifyDefaults refuses a card number used as a member name",
    r1.verdict === "refuse" && r1.hits.length === 1 && r1.hits[0].where === "body@key:0", JSON.stringify(r1.hits));
  var r2 = pan({ body: { a: [{ x: 1, "4111 1111 1111 1111": { y: "z" } }] } });
  check("classifyDefaults refuses a nested member name and names it by position, not by its text",
    r2.verdict === "refuse" && r2.hits.length === 1 && r2.hits[0].where === "body.a[0]@key:1",
    JSON.stringify(r2.hits));
  var under = pan({ body: { "4111111111111111": "4111111111111111" } });
  check("classifyDefaults: a hit under a flagged member name is not labeled with that name",
    under.verdict === "refuse" && under.hits.every(function (h) { return h.where.indexOf("4111") === -1; }),
    JSON.stringify(under.hits));

  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var r3 = ssn({ body: { "123-45-6789": "x", note: "ok" } });
  check("classifyDefaults refuses a member name a redact pattern matches rather than renaming it",
    r3.verdict === "refuse" && r3.hits[0].action === "refuse", JSON.stringify(r3));
  var ssnOverride = b.redact.classifyDefaults({ patterns: ["ssn"], overrideAction: "redact" });
  var r4 = ssnOverride({ body: { "123-45-6789": "x" } });
  check("classifyDefaults refuses a member name even when overrideAction is redact",
    r4.verdict === "refuse", JSON.stringify(r4));
  var auditOnly = b.redact.classifyDefaults({ patterns: ["ssn"], overrideAction: "audit-only" });
  var r5 = auditOnly({ body: { "123-45-6789": "x" } });
  check("classifyDefaults: an audit-only member-name hit stays audit-only",
    r5.verdict === "audit-only" && Object.keys(r5.redactedBody)[0] === "123-45-6789", JSON.stringify(r5));
  var r6 = pan({ body: { card: "x", "4111111111111112": 1, nested: { "abc": [1] } } });
  check("control: member names that match no pattern stay clean", r6.verdict === "clean", JSON.stringify(r6.hits));

  var webhookBodies = [
    '{"4111111111111111":1}',
    '{"a":{"b":{"4111111111111111":true}}}',
    '[{"4111 1111 1111 1111":null}]',
    '{"\\u0034111111111111111":1}',
    '{"__proto__":{"4111111111111111":1},"id":1}',
    '{"a":{"4111111111111111":1},"a":1}',
    '{"a":[{"x":{"4111111111111111":1}}],"a":2}',
  ];
  var sent = [];
  for (var i = 0; i < webhookBodies.length; i += 1) {
    var w = await _sendThroughDlp(pan, webhookBodies[i]);
    if (!_refused(w)) sent.push("webhook " + webhookBodies[i]);
  }
  var redactSsn = b.redact.classifyDefaults({ patterns: ["ssn"], overrideAction: "redact" });
  var ws = await _sendThroughDlp(redactSsn, '{"123-45-6789":"x","n":1}');
  if (!_refused(ws)) sent.push("webhook redact " + ws.sent);
  var wd = await _sendThroughDlp(redactSsn, '{"a":{"123-45-6789":"x"},"a":1}');
  if (!_refused(wd)) sent.push("webhook redact dropped " + wd.sent);
  var h1 = await _httpThroughDlp(pan, { "4111111111111111": 1 });
  if (!_refused(h1)) sent.push("httpClient object");
  var h2 = await _httpThroughDlp(pan, { a: [{ "4111111111111111": 1 }] });
  if (!_refused(h2)) sent.push("httpClient nested object");
  var h3 = await _httpThroughDlp(pan, '{"\\u0034111111111111111":1}');
  if (!_refused(h3)) sent.push("httpClient escaped member name");
  var h4 = await _httpThroughDlp(redactSsn, { "123-45-6789": "x" });
  if (!_refused(h4)) sent.push("httpClient redact object " + JSON.stringify(h4.sent));
  check("webhook and httpClient refuse a card number or SSN used as a member name",
    sent.length === 0, sent.join("; "));

  var dropped = await _sendThroughDlp(pan, '{"__proto__":{"4111111111111111":1},"id":1}');
  var dl = _labels(dropped.refused);
  check("webhook: a member name inside a dropped member is named by its offset",
    dl.length > 0 && dl.every(function (l) { return l.indexOf("4111") === -1; }) &&
    dl.some(function (l) { return /^pan@body@offset:\d+$/.test(l); }), JSON.stringify(dl));

  var wireUnder = await _sendThroughDlp(pan, '{"4111111111111111":' + PAN19 + "}");
  var wl = _labels(wireUnder.refused);
  check("webhook: a wire hit under a flagged member name is named by its offset, not by that name",
    _refused(wireUnder) && wl.length >= 2 && wl.every(function (l) { return l.indexOf("4111111111111111@") === -1 &&
      l.indexOf("body.4111") === -1; }), JSON.stringify(wl));

  // A map keyed by ULIDs, uppercase hex IDs or millisecond timestamps. The
  // timestamp is Luhn-valid, so a card-number check on it would refuse.
  var idKeyed = ['{"users":{"01ARZ3NDEKTSV4RRFFQ69G5FAV":{"n":1}}}', '{"ABCDEF0123456789ABCDEF01":true}'];
  var idObjects = [JSON.parse(idKeyed[0]), JSON.parse(idKeyed[1])];
  var tsKeyed = {};
  tsKeyed[String(LUHN_MS_TIMESTAMP)] = { n: 1 };
  idObjects.push(tsKeyed);
  var keyRefused = [];
  var postures = ["fapi2", "soc2", "gdpr", "pci-dss", "hipaa"];
  for (var pi = 0; pi < postures.length; pi += 1) {
    var pc = _fakeHttpClient();
    var ph = b.redact.installOutboundDlp({ httpClient: pc, posture: postures[pi] });
    var bodies = idKeyed.concat(idObjects);
    for (var ib = 0; ib < bodies.length; ib += 1) {
      try { await pc.request({ url: "https://example.com/x", body: bodies[ib] }); }
      catch (e) { keyRefused.push(postures[pi] + " " + JSON.stringify(bodies[ib]) + " " + e.code); }
    }
    ph.uninstall();
    for (var sb = 0; sb < pc.sent.length; sb += 1) {
      if (JSON.stringify(pc.sent[sb].body) !== JSON.stringify(bodies[sb])) {
        keyRefused.push(postures[pi] + " changed " + JSON.stringify(bodies[sb]));
      }
    }
  }
  check("an object keyed by ordinary IDs or timestamps is sent under every posture",
    keyRefused.length === 0, keyRefused.join("; "));
  var keyLike = b.redact.classifyDefaults({ patterns: ["api-key-shape"] });
  var kv = keyLike({ body: { id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAV": 1 } });
  check("control: an api-key-shaped member value is still redacted while the same text as a member name is not",
    kv.verdict === "redact" && kv.hits.length === 1 && kv.hits[0].where === "body.id" &&
    kv.redactedBody.id === "[REDACTED]" && kv.redactedBody["01ARZ3NDEKTSV4RRFFQ69G5FAV"] === 1, JSON.stringify(kv));
  var digitNames = pan({ body: { "4111111111111111": 1, "04111111111111111": 2 } });
  check("control: a member name written as an integer is checked by its digits",
    digitNames.verdict === "refuse" && digitNames.hits.length === 2, JSON.stringify(digitNames.hits));

  var protoBody = JSON.parse('{"__proto__":{"note":"ssn 123-45-6789"},"a":"ssn 123-45-6789"}');
  var rp = redactSsn({ body: protoBody });
  check("classifyDefaults redact: an own __proto__ member stays an own member of the redacted copy",
    rp.verdict === "redact" && Object.keys(rp.redactedBody).join(",") === "__proto__,a" &&
    JSON.stringify(rp.redactedBody) === '{"__proto__":{"note":"ssn [REDACTED]"},"a":"ssn [REDACTED]"}' &&
    Object.getPrototypeOf(rp.redactedBody) === Object.prototype, JSON.stringify(rp.redactedBody));

  var cleanBody = '{"card":"x","4111111111111112":{"a":"b"},"a":1,"a":2}';
  var wc = await _sendThroughDlp(pan, cleanBody);
  check("control: a webhook body whose member names match no pattern is sent unchanged",
    wc.threw === null && wc.sent === cleanBody, wc.threw ? wc.threw.code : wc.sent);
}

function _membersText(count) {
  var members = [];
  for (var i = 0; i < count; i += 1) members.push('"k' + i + '":0');
  return members.join(",");
}

function _hasLabel(r, label) {
  return r.refused !== null && r.refused.hits.some(function (h) { return h.label === label; });
}

// A JSON text body that is larger, deeper or wider than safeJson.parse
// accepts by default is still read the way the receiver reads it: parsed when
// it is at most 1 MiB, and token by token past that or past 1000 levels.
async function testJsonTextBeyondTheDefaultParseLimits() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var many = _membersText(10001);
  var pad = "x".repeat(1048576 + 16);
  var shapes = [
    ["10,001 members and an escaped card value", "{" + many + ',"card":"\\u0034111111111111111"}'],
    ["an escaped card member name beside a 10,001-member object",
      '{"\\u0034111111111111111":1,"many":{' + many + "}}"],
    ["an escaped card value beside a nested 10,001-member object",
      '{"card":"\\u0034111111111111111","many":{' + many + "}}"],
    ["over 1 MiB with an escaped card value", '{"card":"\\u0034111111111111111","pad":"' + pad + '"}'],
    ["nested 101 deep with an escaped card value",
      "[".repeat(101) + '"\\u0034111111111111111"' + "]".repeat(101)],
    ["nested 1001 deep with an escaped card value",
      "[".repeat(1001) + '"\\u0034111111111111111"' + "]".repeat(1001)],
    ["over 1 MiB with an escaped card member name", '{"pad":"' + pad + '","a":{"\\u0034111111111111111":1}}'],
    ["over 1 MiB with a card behind a surrogate-pair escape",
      '{"pad":"' + pad + '","c":"\\ud83d\\ude00 \\u0034111\\t1111 1111 1111"}'],
  ];
  var leaked = [];
  for (var i = 0; i < shapes.length; i += 1) {
    var w = await _sendThroughDlp(pan, shapes[i][1]);
    if (!_refused(w)) leaked.push("webhook: " + shapes[i][0]);
    var hs = await _httpThroughDlp(pan, shapes[i][1]);
    if (!_refused(hs)) leaked.push("httpClient string: " + shapes[i][0]);
    var hb = await _httpThroughDlp(pan, Buffer.from(shapes[i][1], "utf8"));
    if (!_refused(hb)) leaked.push("httpClient bytes: " + shapes[i][0]);
  }
  check("a card number behind a JSON escape is refused in a body over the default parse limits",
    leaked.length === 0, leaked.join("; "));

  var jwt = ["eyJ", "ABCDef0_-", "."].join("") + ["eyJ", "QRSTuv1_-", "."].join("") + "signaturepart";
  var jwtCls = b.redact.classifyDefaults({ patterns: ["jwt"] });
  var jwtBody = "{" + many + ',"tok":"' + jwt + '"}';
  var jh = await _httpThroughDlp(jwtCls, jwtBody);
  var jw = await _sendThroughDlp(jwtCls, jwtBody);
  var jhp = _jsonOf(_sentText(jh));
  var jwp = _jsonOf(jw.sent);
  check("a JWT in a body with 10,001 members is redacted and the rest of the body is kept",
    jhp && jhp.tok === "[REDACTED]" && jhp.k10000 === 0 && jwp && jwp.tok === "[REDACTED]" && jwp.k10000 === 0,
    String(_sentText(jh)).slice(-80) + " | " + String(jw.sent).slice(-80));

  var bigJwt = '{"pad":"' + pad + '","tok":"' + jwt + '","n":10000000000000001}';
  var bh = await _httpThroughDlp(jwtCls, bigJwt);
  var bb = await _httpThroughDlp(jwtCls, Buffer.from(bigJwt, "utf8"));
  var bw = await _sendThroughDlp(jwtCls, bigJwt);
  var bigOk = [_sentText(bh), _sentText(bb), bw.sent].every(function (t) {
    return typeof t === "string" && t === bigJwt.replace('"' + jwt + '"', '"[REDACTED]"');
  });
  check("a JWT in a body over 1 MiB is replaced in place and every other byte is kept",
    bigOk && Buffer.isBuffer(bb.sent) && typeof bh.sent === "string",
    [_sentText(bh), _sentText(bb), bw.sent].map(function (t) { return String(t).slice(-60); }).join(" | "));
  var redactPan = b.redact.classifyDefaults({ patterns: ["pan"], overrideAction: "redact" });
  var bigName = '{"pad":"' + pad + '","a":{"\\u0034111111111111111":1},"b":' + PAN19 + "}";
  var bn = await _httpThroughDlp(redactPan, bigName);
  check("redact: a card number as a member name of a body over 1 MiB is refused rather than renamed",
    _refused(bn), String(_sentText(bn)).slice(-80));
  var manySsn = '{"pad":"' + pad + '","v":[' + new Array(3000).fill('"123-45-6789"').join(",") + "]}";
  var ms = await _httpThroughDlp(b.redact.classifyDefaults({ patterns: ["ssn"] }), manySsn);
  var msText = _sentText(ms);
  check("redact: every SSN in a body over 1 MiB is replaced, and the hits list at most 1000 of them plus the text scan",
    typeof msText === "string" && msText.indexOf("123-45-6789") === -1 && ms.redacted !== null &&
    ms.redacted.hits.length <= 1001 && ms.redacted.hits.length >= 1000 &&
    _jsonOf(msText) !== undefined && _jsonOf(msText).v.length === 3000,
    String(ms.redacted && ms.redacted.hits.length) + " " + String(msText).slice(-60));
  var bigNum = '{"pad":"' + pad + '","b":' + PAN19 + ',"c":"x"}';
  var bnr = await _httpThroughDlp(redactPan, bigNum);
  check("redact: a rounded PAN in a body over 1 MiB is replaced in place",
    _sentText(bnr) === bigNum.replace(PAN19, '"[REDACTED]"'), String(_sentText(bnr)).slice(-80));

  var cleanBodies = [
    '{"a":1,"pad":"' + pad + '"}',
    "{" + many + "}",
    "[".repeat(150) + '"ok"' + "]".repeat(150),
    "[".repeat(1001) + '"ok",1.5e3,10000000000000001' + "]".repeat(1001),
    "{" + _membersText(1000001) + "}",
    '["' + "x".repeat(64 * 1048576) + '"]',
    "x".repeat(64 * 1048576 + 16),
    '{"card":"\\u0034111111111111111"',
  ];
  var altered = [];
  for (var c = 0; c < cleanBodies.length; c += 1) {
    var cw = await _sendThroughDlp(pan, cleanBodies[c]);
    if (cw.threw !== null || cw.sent !== cleanBodies[c]) altered.push("webhook " + c);
    var ch = await _httpThroughDlp(pan, cleanBodies[c]);
    if (ch.threw !== null || ch.sent !== cleanBodies[c]) altered.push("httpClient " + c);
  }
  check("control: large, wide and deep clean bodies, a large text and a body that is not JSON are sent as given",
    altered.length === 0, altered.join("; "));
}

// A JSON body over 1 MiB is scanned in batches, so the memory it takes does
// not grow with the number of values in it. Each case runs in a child process
// with a small heap. mode "send": sent unchanged; "refuse": refused;
// "redact": sent with every unit replaced.
function _tokenScanInChild(unit, mib, heapMb, mode, pattern) {
  var redactPath = path.resolve(__dirname, "..", "..", "lib", "redact.js");
  var script = [
    "var redact = require(" + JSON.stringify(redactPath) + ");",
    "var unit = " + JSON.stringify(unit) + ";",
    "var count = Math.floor((" + mib + " * 1048576) / (unit.length + 1));",
    "var body = '[' + new Array(count).fill(unit).join(',') + ']';",
    "var sent = [];",
    "var client = { request: function (o) { sent.push(o); return Promise.resolve({}); } };",
    "redact.installOutboundDlp({ httpClient: client, classifier: redact.classifyDefaults({ patterns: [" +
      JSON.stringify(pattern) + "] }) });",
    "client.request({ url: 'https://example.com/x', body: body }).then(function () {",
    "  var b0 = sent[0] && sent[0].body;",
    "  process.stdout.write(b0 === body ? 'send' : (typeof b0 === 'string' && b0.indexOf(unit) === -1 ? 'redact' : 'changed'));",
    "}, function (e) { process.stdout.write(e && e.code === 'redact-dlp/refused' ? 'refuse' : 'threw ' + (e && e.code)); });",
  ].join("\n");
  var out = childProcess.spawnSync(process.execPath,
    ["--max-old-space-size=" + heapMb, "-e", script], { encoding: "utf8", timeout: 120000 });
  return { ok: out.status === 0 && out.stdout === mode,
    detail: unit + " " + mib + " MiB heap " + heapMb + ": status " + out.status + " signal " + out.signal +
      " stdout " + out.stdout + " stderr " + String(out.stderr || "").slice(0, 160) };
}

async function testTokenScanMemoryIsBoundedByTheBody() {
  var cases = [['""', 160, "send", "pan"], ['{"a":"x"}', 160, "send", "pan"], ["{}", 160, "send", "pan"],
    ['"4111111111111111"', 160, "refuse", "pan"], ['"123-45-6789"', 320, "redact", "ssn"]];
  for (var i = 0; i < cases.length; i += 1) {
    var r = _tokenScanInChild(cases[i][0], 32, cases[i][1], cases[i][2], cases[i][3]);
    check("httpClient: a 32 MiB JSON body of " + cases[i][0] + " is " +
      (cases[i][2] === "send" ? "scanned and sent" : cases[i][2] === "refuse" ? "refused" : "redacted") +
      " within a " + cases[i][1] + " MB heap", r.ok, r.detail);
  }
}

// A header name is scanned as a member name is: refused rather than renamed,
// and named by position.
async function testHeaderNamesAreScanned() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var r1 = pan({ body: {}, headers: { "x-4111111111111111": "1" } });
  check("classifyDefaults refuses a card number used as a header name",
    r1.verdict === "refuse" && r1.hits.length === 1 && r1.hits[0].where === "headers@key:0", JSON.stringify(r1.hits));
  var r2 = pan({ headers: { accept: "*/*", "x-4111111111111111": "4111111111111111" } });
  check("classifyDefaults: a hit on a header value under a flagged name does not name the header",
    r2.verdict === "refuse" && r2.hits.length === 2 &&
    r2.hits.every(function (h) { return h.where === "headers@key:1"; }), JSON.stringify(r2.hits));
  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var r3 = ssn({ headers: { "x-123-45-6789": "1" } });
  check("classifyDefaults refuses a header name a redact pattern matches",
    r3.verdict === "refuse" && r3.hits[0].action === "refuse", JSON.stringify(r3.hits));
  var r4 = pan({ headers: { "content-type": "application/json", "x-card-number": "none" } });
  check("control: header names that match no pattern stay clean", r4.verdict === "clean", JSON.stringify(r4.hits));

  var h = await _requestThroughDlp(pan,
    { url: "https://example.com/x", headers: { "x-4111111111111111": "1" }, body: "{}" });
  check("httpClient refuses a card number used as a header name", _refused(h), JSON.stringify(h.sentOpts));
  var mail = _fakeMail();
  var mh = b.redact.installOutboundDlp({ mail: mail, classifier: pan });
  var mailThrew = null;
  try { await mail.send({ to: "x@y", subject: "s", text: "t", headers: { "X-4111111111111111": "1" } }); }
  catch (e) { mailThrew = e; }
  mh.uninstall();
  check("mail refuses a card number used as a header name",
    mailThrew !== null && mailThrew.code === "redact-dlp/refused" && mail.sent.length === 0,
    String(mailThrew && mailThrew.code));
}

// The URL of a request is scanned: host labels, user info, path segments,
// query names and values and the fragment, each decoded. A URL is never
// rewritten, so a hit that would redact it refuses the request.
async function testRequestUrlIsScanned() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var urls = [
    "https://example.com/x?card=4111111111111111",
    "https://example.com/x?card=4111+1111+1111+1111",
    "https://example.com/x?c=%34111111111111111",
    "https://example.com/x?4111111111111111=1",
    "https://example.com/v1/4111111111111111/x",
    "https://example.com/v1/4111%201111%201111%201111",
    "https://4111111111111111.example.com/",
    "https://user:4111111111111111@example.com/",
    "https://example.com/x#4111111111111111",
    "/relative/4111111111111111",
  ];
  var sent = [];
  for (var i = 0; i < urls.length; i += 1) {
    var r = await _requestThroughDlp(pan, { url: urls[i], body: "{}" });
    if (!_refused(r)) sent.push(urls[i]);
    else if (r.refused.hits.some(function (h) { return h.where.indexOf("4111") !== -1; })) sent.push("label " + urls[i]);
  }
  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var rs = await _requestThroughDlp(ssn, { url: "https://example.com/x?ssn=123-45-6789", body: "{}" });
  if (!_refused(rs)) sent.push("ssn query " + JSON.stringify(rs.sentOpts && rs.sentOpts.url));
  var jwt = ["eyJ", "ABCDef0_-", "."].join("") + ["eyJ", "QRSTuv1_-", "."].join("") + "signaturepart";
  var rj = await _requestThroughDlp(b.redact.classifyDefaults({ patterns: ["jwt"] }),
    { url: "https://example.com/x?token=" + jwt });
  if (!_refused(rj)) sent.push("jwt query");
  var hook = await _sendThroughDlp(pan, "{}");
  if (hook.threw !== null) sent.push("webhook control threw");
  var signer = _fakeWebhookSigner();
  var wh = b.redact.installOutboundDlp({ webhook: signer, classifier: pan });
  var whThrew = null;
  try { await signer.send({ url: "https://example.com/hook/4111111111111111", body: "{}" }); }
  catch (e) { whThrew = e; }
  wh.uninstall();
  if (whThrew === null || signer.sent.length !== 0) sent.push("webhook url");
  check("a card number, an SSN or a JWT in a request URL is refused", sent.length === 0, sent.join("; "));

  var defaults = b.redact.classifyDefaults({});
  var cleanUrls = [
    "https://example.com/v1/users/01ARZ3NDEKTSV4RRFFQ69G5FAV?cursor=AbCdEfGhIjKlMnOpQrStUvWx12&since=" +
      LUHN_MS_TIMESTAMP,
    "https://example.com/v1/orders/" + LUHN_MS_TIMESTAMP + "?q=a%20b#top",
  ];
  var refusedClean = [];
  for (var c = 0; c < cleanUrls.length; c += 1) {
    var rc = await _requestThroughDlp(defaults, { url: cleanUrls[c], body: "{}" });
    if (rc.threw !== null || !rc.sentOpts || rc.sentOpts.url !== cleanUrls[c]) refusedClean.push(cleanUrls[c]);
  }
  check("control: a URL with IDs, a cursor and a millisecond timestamp is sent unchanged",
    refusedClean.length === 0, refusedClean.join("; "));
}

// A multipart request is scanned field by field: field names and file names
// as names, field values and in-memory file contents as values.
async function testMultipartIsScanned() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var specs = [
    ["a field value", { fields: { card: "4111111111111111" } }],
    ["a repeated field value", { fields: { card: ["ok", "4111111111111111"] } }],
    ["a field value given as bytes", { fields: { card: Buffer.from("4111111111111111") } }],
    ["a field name", { fields: { "4111111111111111": "x" } }],
    ["a file name", { files: [{ field: "f", filename: "4111111111111111.txt", content: "x" }] }],
    ["a file field name", { files: [{ field: "4111111111111111", content: "x" }] }],
    ["in-memory file content", { files: [{ field: "f", content: "card 4111111111111111" }] }],
    ["in-memory file content as bytes", { files: [{ field: "f", content: Buffer.from("card 4111111111111111") }] }],
  ];
  var sent = [];
  for (var i = 0; i < specs.length; i += 1) {
    var r = await _requestThroughDlp(pan, { url: "https://example.com/up", multipart: specs[i][1] });
    if (!_refused(r) || r.sentOpts !== null) sent.push(specs[i][0]);
  }
  check("a card number anywhere in a multipart request is refused", sent.length === 0, sent.join("; "));

  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var rr = await _requestThroughDlp(ssn, { url: "https://example.com/up", multipart: {
    fields: { note: "ssn 123-45-6789", n: 7 },
    files:  [{ field: "f", filename: "a.txt", content: Buffer.from("id 123-45-6789"), contentType: "text/plain" }],
    streaming: true,
  } });
  var mp = rr.sentOpts && rr.sentOpts.multipart;
  check("redact: a multipart field value and file content are redacted and the rest of the spec is kept",
    rr.threw === null && mp && mp.fields.note === "ssn [REDACTED]" && mp.fields.n === 7 &&
    Buffer.isBuffer(mp.files[0].content) && mp.files[0].content.toString() === "id [REDACTED]" &&
    mp.files[0].filename === "a.txt" && mp.files[0].contentType === "text/plain" && mp.streaming === true &&
    rr.redactedOpts === rr.sentOpts, JSON.stringify(mp));
  var rn = await _requestThroughDlp(ssn, { url: "https://example.com/up",
    multipart: { files: [{ field: "f", filename: "123-45-6789.txt", content: "x" }] } });
  check("redact: a file name a redact pattern matches is refused rather than renamed", _refused(rn),
    JSON.stringify(rn.sentOpts && rn.sentOpts.multipart));

  var cleanSpec = { fields: { a: "1", b: ["x", "y"] }, files: [{ field: "f", filename: "a.txt", content: "hello" }] };
  var rc = await _requestThroughDlp(pan, { url: "https://example.com/up", multipart: cleanSpec });
  check("control: a clean multipart request is sent with the same spec",
    rc.threw === null && rc.sentOpts && rc.sentOpts.multipart === cleanSpec, String(rc.threw && rc.threw.code));
}

// A request whose before hooks change it is classified again after the last
// hook, through the real httpClient, against a local server.
async function testRealHttpClientScansWhatReachesTheServer() {
  var received = [];
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      received.push({ url: req.url, body: Buffer.concat(chunks).toString("utf8") });
      res.end("ok");
    });
  });
  var port = await helpers.listenOnRandomPort(server);
  var base = "http://127.0.0.1:" + port;
  var client = {
    request: function (o) {
      return b.httpClient.request(Object.assign({ allowInternal: true, allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL }, o));
    },
  };
  async function go(classifier, reqOpts) {
    var handle = b.redact.installOutboundDlp({ httpClient: client, classifier: classifier });
    var before = received.length;
    var threw = null;
    try { await client.request(Object.assign({ method: "POST", url: base + "/p" }, reqOpts)); }
    catch (e) { threw = e; }
    finally { handle.uninstall(); }
    return { threw: threw, got: received.length > before ? received[received.length - 1] : null };
  }
  await helpers.withDrain("redact-dlp: real httpClient server", async function () {
    var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
    var hookRuns = 0;
    var cases = [
      ["a multipart field", { multipart: { fields: { card: "4111111111111111" } } }],
      ["a URL query value", { url: base + "/p?card=4111111111111111" }],
      ["a body a before hook sets", { body: "{}", before: [function (o) {
        hookRuns += 1;
        return Object.assign({}, o, { body: "card 4111111111111111" });
      }] }],
      ["a multipart spec a before hook sets", { before: [function (o) {
        return Object.assign({}, o, { multipart: { fields: { card: "4111111111111111" } } });
      }] }],
      ["a URL a before hook sets", { body: "{}", before: [function (o) {
        return Object.assign({}, o, { url: base + "/p?card=4111111111111111" });
      }] }],
    ];
    var reached = [];
    for (var i = 0; i < cases.length; i += 1) {
      var r = await go(pan, cases[i][1]);
      if (r.got !== null || r.threw === null || r.threw.code !== "redact-dlp/refused") {
        reached.push(cases[i][0] + ": " + (r.threw ? r.threw.code : "sent " + JSON.stringify(r.got)));
      }
    }
    check("real httpClient: a card number in a multipart field, the URL or a before hook's change does not reach the server",
      reached.length === 0 && hookRuns === 1, reached.join("; ") + " hookRuns " + hookRuns);

    var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
    var rr = await go(ssn, { body: "{}", before: [function (o) { return Object.assign({}, o, { body: "ssn 123-45-6789" }); }] });
    check("real httpClient redact: a body a before hook sets is redacted before it is sent",
      rr.threw === null && rr.got !== null && rr.got.body === "ssn [REDACTED]", JSON.stringify(rr.got));

    var cleanRuns = 0;
    var rc = await go(pan, { url: base + "/p?q=1", multipart: { fields: { a: "1" } }, before: [function (o) {
      cleanRuns += 1;
      return o;
    }] });
    check("control: a clean multipart request with a before hook reaches the server once, unchanged",
      rc.threw === null && rc.got !== null && rc.got.url === "/p?q=1" && rc.got.body.indexOf('name="a"') !== -1 &&
      cleanRuns === 1, JSON.stringify(rc.got) + " " + String(rc.threw && rc.threw.code));
  }, function () {
    return new Promise(function (resolve) { server.close(resolve); });
  });
}

// A client that awaits each before hook, and one that awaits only the value
// the last hook returns, both send what the DLP scanned after the hooks.
async function testAsyncBeforeHooksAreScanned() {
  function client(awaitEach) {
    var sent = [];
    return {
      sent:    sent,
      request: async function (o) {
        var w = o;
        var hooks = o.before || [];
        for (var i = 0; i < hooks.length; i += 1) {
          var r = hooks[i](w);
          if (awaitEach) r = await r;
          if (r && typeof r === "object") w = r;
        }
        w = await w;
        sent.push(w);
        return {};
      },
    };
  }
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var wrong = [];
  var shapes = [true, false];
  for (var s = 0; s < shapes.length; s += 1) {
    var label = shapes[s] ? "awaiting each hook" : "awaiting the last hook";
    var c1 = client(shapes[s]);
    var h1 = b.redact.installOutboundDlp({ httpClient: c1, classifier: pan });
    var threw = null;
    try {
      await c1.request({ url: "https://example.com/x", body: "{}", before: [function (o) {
        return Promise.resolve(Object.assign({}, o, { body: "card 4111111111111111" }));
      }] });
    } catch (e) { threw = e; }
    h1.uninstall();
    if (threw === null || threw.code !== "redact-dlp/refused" || c1.sent.length !== 0) wrong.push(label + " refuse");
    var c2 = client(shapes[s]);
    var h2 = b.redact.installOutboundDlp({ httpClient: c2, classifier: ssn });
    try {
      await c2.request({ url: "https://example.com/x", body: "{}", before: [function (o) {
        return Promise.resolve(Object.assign({}, o, { body: "ssn 123-45-6789" }));
      }] });
    } catch (e) { wrong.push(label + " redact threw " + e.code); }
    h2.uninstall();
    if (c2.sent.length !== 1 || c2.sent[0].body !== "ssn [REDACTED]") wrong.push(label + " redact " + JSON.stringify(c2.sent));
  }
  check("a body a before hook resolves to is refused or redacted however the client awaits its hooks",
    wrong.length === 0, wrong.join("; "));
}

// The verdict the hooks receive describes the body that is sent.
async function testHookVerdictDescribesTheSentBody() {
  var cases = [
    ["a fraction PAN in a string value", b.redact.classifyDefaults({ patterns: ["pan"], overrideAction: "redact" }),
      '{"note":"4.111111111111111e15"}'],
    ["an SSN in a JSON string body", b.redact.classifyDefaults({ patterns: ["ssn"] }), '{"note":"ssn 123-45-6789"}'],
    ["an SSN in a JSON bytes body", b.redact.classifyDefaults({ patterns: ["ssn"] }),
      Buffer.from('{"note":"ssn 123-45-6789"}')],
    ["an SSN in a text body", b.redact.classifyDefaults({ patterns: ["ssn"] }), "note ssn 123-45-6789"],
    ["an SSN in an object body", b.redact.classifyDefaults({ patterns: ["ssn"] }), { note: "ssn 123-45-6789" }],
  ];
  var differ = [];
  for (var i = 0; i < cases.length; i += 1) {
    var r = await _httpThroughDlp(cases[i][1], cases[i][2]);
    if (r.redacted === null || r.redacted.redactedBody !== r.sent || r.redactedOpts.body !== r.sent) {
      differ.push(cases[i][0] + ": sent " + JSON.stringify(String(_sentText(r) || r.sent)) + " verdict " +
        JSON.stringify(r.redacted && r.redacted.redactedBody));
    }
  }
  check("httpClient: onRedact's verdict.redactedBody is the body that is sent", differ.length === 0, differ.join("; "));
}

// A classifier that reports a redact verdict without a body that can be sent
// in place of a text body fails closed, and every failure is a rejection.
function _anyText(v) {
  if (typeof v === "string") return v;
  if (Buffer.isBuffer(v)) return v.toString("utf8");
  try { return JSON.stringify(v) || ""; } catch (_e) { return ""; }
}

async function testRedactWithoutABodyFailsClosed() {
  var noBody = function (input) {
    if (_anyText(input.body).indexOf("secret") !== -1 || _anyText(input.headers).indexOf("secret") !== -1) {
      return { verdict: "redact", hits: [{ label: "s", action: "redact", where: "body" }] };
    }
    return { verdict: "clean", hits: [], redactedBody: input.body };
  };
  var bodies = ['{"a":"secret"}', Buffer.from('{"a":"secret"}'), "plain secret", Buffer.from("plain secret")];
  var wrong = [];
  for (var i = 0; i < bodies.length; i += 1) {
    var r = await _requestThroughDlp(noBody, { url: "https://example.com/x", body: bodies[i] });
    if (r.syncThrew !== null) wrong.push(i + " threw synchronously: " + r.syncThrew.message);
    else if (!_refused(r) || !_hasLabel(r, "classifier-bad-verdict")) {
      wrong.push(i + " " + (r.threw ? r.threw.code : "sent " + JSON.stringify(String(r.sent))));
    }
  }
  var throwing = function () { throw new Error("boom"); };
  var rt = await _requestThroughDlp(throwing, { url: "https://example.com/x", body: Buffer.from('{"a":1}') });
  if (rt.syncThrew !== null || !_refused(rt)) wrong.push("throwing classifier");
  check("httpClient: a redact verdict with no usable body for a text body is refused as a rejected promise",
    wrong.length === 0, wrong.join("; "));
  var rg = await _requestThroughDlp(noBody, { url: "https://example.com/x", method: "GET", headers: { h: "secret" } });
  check("control: a redact verdict with no body for a request that has no body is sent",
    rg.threw === null && rg.sentOpts !== null && rg.sent === undefined, String(rg.threw && rg.threw.code));
}

// A bytes body is decoded for the scan by its byte-order mark first, then by
// the charset of its Content-Type, and read as UTF-8 when it has neither.
function _utf16be(text) {
  return Buffer.from(text, "utf16le").swap16();
}
var BOM_UTF16LE = Buffer.from([0xff, 0xfe]);
var BOM_UTF16BE = Buffer.from([0xfe, 0xff]);
var BOM_UTF32LE = Buffer.from([0xff, 0xfe, 0x00, 0x00]);
var BOM_UTF32BE = Buffer.from([0x00, 0x00, 0xfe, 0xff]);
var BOM_UTF8 = Buffer.from([0xef, 0xbb, 0xbf]);
var CARD_JSON = '{"card":"4111111111111111"}';
var CLEAN_JSON = '{"note":"hello"}';

function _ct(charset) {
  return { "content-type": "application/json; charset=" + charset };
}

function _outcome(r) {
  if (r.syncThrew !== null) return "threw synchronously " + r.syncThrew.message;
  if (r.threw !== null) return "threw " + r.threw.code + (r.sent === null ? "" : " but sent");
  return "sent " + (Buffer.isBuffer(r.sent) ? "bytes " + r.sent.toString("hex") : JSON.stringify(r.sent));
}

async function testBytesBodyIsDecodedByBomAndCharset() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var refusedCases = [
    ["UTF-16LE with a BOM", Buffer.concat([BOM_UTF16LE, Buffer.from(CARD_JSON, "utf16le")]), {}],
    ["UTF-16BE with a BOM", Buffer.concat([BOM_UTF16BE, _utf16be(CARD_JSON)]), {}],
    ["UTF-16LE named by charset=utf-16le", Buffer.from(CARD_JSON, "utf16le"), _ct("utf-16le")],
    ["UTF-16BE named by a quoted, uppercase charset", _utf16be(CARD_JSON),
      { "Content-Type": "application/json; charset=\"UTF-16BE\"" }],
    ["UTF-16 with a BOM named by charset=utf-16", Buffer.concat([BOM_UTF16LE, Buffer.from(CARD_JSON, "utf16le")]),
      _ct("utf-16")],
    ["UTF-16LE with a BOM under charset=utf-8", Buffer.concat([BOM_UTF16LE, Buffer.from(CARD_JSON, "utf16le")]),
      _ct("utf-8")],
    ["UTF-16LE text that is not JSON", Buffer.from("card 4111 1111 1111 1111", "utf16le"),
      { "CONTENT-TYPE": "text/plain;charset=utf-16le" }],
    ["windows-1252 text", Buffer.from("card 4111111111111111", "latin1"), { "content-type": "text/plain; charset=windows-1252" }],
    ["a UTF-8 body with a BOM", Buffer.concat([BOM_UTF8, Buffer.from(CARD_JSON)]), {}],
    ["UTF-16LE named after a quoted parameter that holds a semicolon", Buffer.from(CARD_JSON, "utf16le"),
      { "content-type": "application/json; note=\"a;charset=utf-8\"; charset=utf-16le" }],
  ];
  var wrong = [];
  for (var i = 0; i < refusedCases.length; i += 1) {
    var r = await _requestThroughDlp(pan, { url: "https://example.com/x", headers: refusedCases[i][2], body: refusedCases[i][1] });
    if (!_refused(r)) wrong.push(refusedCases[i][0] + ": " + _outcome(r));
  }
  check("httpClient: a card number in a bytes body is found in the encoding its BOM or charset names",
    wrong.length === 0, wrong.join("; "));

  var undecodable = [
    ["a UTF-32LE BOM", Buffer.concat([BOM_UTF32LE, Buffer.from("{}", "utf16le")]), {}],
    ["a UTF-32BE BOM", Buffer.concat([BOM_UTF32BE, Buffer.from("{}")]), {}],
    ["charset=utf-16 without a BOM", Buffer.from(CLEAN_JSON, "utf16le"), _ct("utf-16")],
    ["charset=ucs-2 without a BOM", Buffer.from(CLEAN_JSON, "utf16le"), _ct("ucs-2")],
    ["charset=utf-32", Buffer.from(CLEAN_JSON), _ct("utf-32")],
    ["a charset the runtime cannot decode", Buffer.from(CLEAN_JSON), _ct("x-no-such-charset")],
    ["a Content-Type that ends inside a quoted string", Buffer.from(CLEAN_JSON), _ct("\"utf-8")],
    ["two Content-Type headers naming different charsets", Buffer.from(CLEAN_JSON),
      { "Content-Type": "application/json; charset=utf-8", "content-type": "application/json; charset=utf-16le" }],
  ];
  var notRefused = [];
  for (var u = 0; u < undecodable.length; u += 1) {
    var ru = await _requestThroughDlp(pan, { url: "https://example.com/x", headers: undecodable[u][2], body: undecodable[u][1] });
    if (ru.syncThrew !== null || ru.threw === null || ru.threw.code !== "redact-dlp/undecodable-body" ||
        ru.sent !== null || !_hasLabel(ru, "undecodable-body")) {
      notRefused.push(undecodable[u][0] + ": " + _outcome(ru));
    }
  }
  check("httpClient: a bytes body whose encoding cannot be read is refused with redact-dlp/undecodable-body",
    notRefused.length === 0, notRefused.join("; "));

  var sentCases = [
    ["clean UTF-16LE with a BOM", Buffer.concat([BOM_UTF16LE, Buffer.from(CLEAN_JSON, "utf16le")]), {}],
    ["clean UTF-16BE named by charset", _utf16be(CLEAN_JSON), _ct("utf-16be")],
    ["clean UTF-16 with a BOM named by charset=utf-16", Buffer.concat([BOM_UTF16BE, _utf16be(CLEAN_JSON)]), _ct("utf-16")],
    ["clean windows-1252", Buffer.from("café ok", "latin1"), { "content-type": "text/plain; charset=windows-1252" }],
    ["clean UTF-8 named by charset", Buffer.from(CLEAN_JSON), _ct("utf-8")],
    ["an empty body under charset=utf-16", Buffer.alloc(0), _ct("utf-16")],
    ["binary bytes with no charset", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d]),
      { "content-type": "image/png" }],
  ];
  var notSent = [];
  for (var s = 0; s < sentCases.length; s += 1) {
    var rs = await _requestThroughDlp(pan, { url: "https://example.com/x", headers: sentCases[s][2], body: sentCases[s][1] });
    if (rs.threw !== null || rs.sent !== sentCases[s][1]) notSent.push(sentCases[s][0] + ": " + _outcome(rs));
  }
  check("control: a clean bytes body in any readable encoding is sent as the same bytes",
    notSent.length === 0, notSent.join("; "));
}

async function testNonUtf8BytesBodyIsRefusedRatherThanReEncoded() {
  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var bodies = [
    ["UTF-16LE with a BOM", Buffer.concat([BOM_UTF16LE, Buffer.from('{"note":"ssn 123-45-6789"}', "utf16le")]), {}],
    ["UTF-16BE named by charset", _utf16be("ssn 123-45-6789"), { "content-type": "text/plain; charset=utf-16be" }],
    ["windows-1252", Buffer.from("café ssn 123-45-6789", "latin1"), { "content-type": "text/plain; charset=windows-1252" }],
  ];
  var wrong = [];
  for (var i = 0; i < bodies.length; i += 1) {
    var r = await _requestThroughDlp(ssn, { url: "https://example.com/x", headers: bodies[i][2], body: bodies[i][1] });
    var refusedHit = r.refused !== null && r.refused.hits.some(function (h) { return h.label === "ssn" && h.action === "refuse"; });
    if (!_refused(r) || !refusedHit) wrong.push(bodies[i][0] + ": " + _outcome(r));
  }
  check("httpClient: a body in an encoding other than UTF-8 that needs redacting is refused, not re-encoded",
    wrong.length === 0, wrong.join("; "));

  var utf8 = await _requestThroughDlp(ssn, { url: "https://example.com/x", headers: _ct("utf-8"),
    body: Buffer.from("ssn 123-45-6789") });
  check("control: a UTF-8 bytes body that needs redacting is sent redacted as bytes",
    utf8.threw === null && Buffer.isBuffer(utf8.sent) && utf8.sent.toString("utf8") === "ssn [REDACTED]",
    _outcome(utf8));

  var seen = [];
  var recording = function (input) {
    seen.push(typeof input.body === "string" ? input.body : Buffer.isBuffer(input.body) ? "bytes" : typeof input.body);
    return { verdict: "clean", hits: [], redactedBody: input.body };
  };
  var rc = await _requestThroughDlp(recording, { url: "https://example.com/x",
    body: Buffer.concat([BOM_UTF16LE, Buffer.from("plain text", "utf16le")]) });
  check("a classifier is given a UTF-16 body as the decoded text and as the bytes",
    rc.threw === null && seen.indexOf("plain text") !== -1 && seen.indexOf("bytes") !== -1, JSON.stringify(seen));

  var hooked = [
    [Buffer.concat([BOM_UTF16LE, Buffer.from("card 4111111111111111", "utf16le")]), "redact-dlp/refused"],
    [Buffer.concat([BOM_UTF32BE, Buffer.from("x")]), "redact-dlp/undecodable-body"],
  ];
  var wrongHooked = [];
  for (var h = 0; h < hooked.length; h += 1) {
    var sentByHook = [];
    var hookClient = {
      request: function (o) {
        var w = o;
        for (var k = 0; k < (o.before || []).length; k += 1) w = o.before[k](w) || w;
        sentByHook.push(w);
        return Promise.resolve({});
      },
    };
    var hh = b.redact.installOutboundDlp({ httpClient: hookClient, classifier: b.redact.classifyDefaults({ patterns: ["pan"] }) });
    var hookThrew = null;
    var swapIn = hooked[h][0];
    try {
      await hookClient.request({ url: "https://example.com/x", body: "{}",
        before: [function (o) { return Object.assign({}, o, { body: swapIn }); }] });
    } catch (e) { hookThrew = e; }
    hh.uninstall();
    if (!hookThrew || hookThrew.code !== hooked[h][1] || sentByHook.length !== 0) {
      wrongHooked.push(h + ": " + (hookThrew ? hookThrew.code : "sent"));
    }
  }
  check("httpClient: a bytes body a before hook returns is decoded by the same rule",
    wrongHooked.length === 0, wrongHooked.join("; "));
}

async function testWebhookAndNestedBytesAreDecodedByBom() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var hooks = [
    ["UTF-16LE with a BOM", Buffer.concat([BOM_UTF16LE, Buffer.from(CARD_JSON, "utf16le")]), undefined, "redact-dlp/refused"],
    ["UTF-16BE named by charset", _utf16be(CARD_JSON), _ct("utf-16be"), "redact-dlp/refused"],
    ["a UTF-32LE BOM", Buffer.concat([BOM_UTF32LE, Buffer.from("{}", "utf16le")]), undefined, "redact-dlp/undecodable-body"],
  ];
  var wrong = [];
  for (var i = 0; i < hooks.length; i += 1) {
    var signer = _fakeWebhookSigner();
    var handle = b.redact.installOutboundDlp({ webhook: signer, classifier: pan });
    var threw = null;
    try { await signer.send({ url: "https://example.com/hook", body: hooks[i][1], headers: hooks[i][2] }); }
    catch (e) { threw = e; }
    finally { handle.uninstall(); }
    if (!threw || threw.code !== hooks[i][3] || signer.sent.length !== 0) {
      wrong.push(hooks[i][0] + ": " + (threw ? threw.code : "sent"));
    }
  }
  check("webhook: a bytes body is decoded by its BOM or charset before the scan", wrong.length === 0, wrong.join("; "));

  var nested = pan({ body: { file: Buffer.concat([BOM_UTF16LE, Buffer.from("card 4111111111111111", "utf16le")]) } });
  check("classifyDefaults: a bytes leaf with a UTF-16 BOM is decoded before the scan",
    nested.verdict === "refuse", JSON.stringify(nested.hits));
  var nestedBe = pan({ body: [Buffer.concat([BOM_UTF16BE, _utf16be("card 4111111111111111")])] });
  check("classifyDefaults: a bytes leaf with a UTF-16BE BOM is decoded before the scan",
    nestedBe.verdict === "refuse", JSON.stringify(nestedBe.hits));
  var nested32 = pan({ body: { file: Buffer.concat([BOM_UTF32BE, Buffer.from("x")]) } });
  check("classifyDefaults: a bytes leaf with a UTF-32 BOM is refused as undecodable",
    nested32.verdict === "refuse" && nested32.hits.some(function (h) {
      return h.label === "undecodable-bytes" && h.where === "body.file";
    }), JSON.stringify(nested32.hits));
  var ssnLeaf = b.redact.classifyDefaults({ patterns: ["ssn"] })({
    body: { file: Buffer.concat([BOM_UTF16LE, Buffer.from("ssn 123-45-6789", "utf16le")]) },
  });
  check("classifyDefaults: a UTF-16 bytes leaf that needs redacting is refused, not re-encoded",
    ssnLeaf.verdict === "refuse" && ssnLeaf.hits.every(function (h) { return h.action === "refuse"; }),
    JSON.stringify(ssnLeaf.hits));
  var cleanLeaf = pan({ body: { file: Buffer.concat([BOM_UTF16LE, Buffer.from("hello", "utf16le")]) } });
  check("control: a clean UTF-16 bytes leaf stays clean", cleanLeaf.verdict === "clean", JSON.stringify(cleanLeaf.hits));

  var mail = _fakeMail();
  var mh = b.redact.installOutboundDlp({ mail: mail, classifier: pan });
  var threwMail = null;
  try {
    await mail.send({ to: "x@y", subject: "s",
      text: Buffer.concat([BOM_UTF16LE, Buffer.from("card 4111111111111111", "utf16le")]) });
  } catch (e) { threwMail = e; }
  finally { mh.uninstall(); }
  check("mail.send refuses a card number in UTF-16 text given as a Buffer",
    threwMail && threwMail.code === "redact-dlp/refused" && mail.sent.length === 0, threwMail && threwMail.code);
}

// A receiver may read a body as UTF-8 whatever its byte-order mark or
// charset says, or read it by a charset that its byte-order mark
// contradicts, so the body is scanned in every one of those readings.
var ASCII_CARD = Buffer.from("card 4111111111111111");
var ASCII_SSN = Buffer.from("ssn 123-45-6789");
// A string whose UTF-8 bytes are the UTF-16LE encoding of a card number.
var UTF16LE_CARD_AS_STRING = Buffer.from("card 4111111111111111", "utf16le").toString("latin1");

async function _webhookThroughDlp(classifier, input) {
  var signer = _fakeWebhookSigner();
  var handle = b.redact.installOutboundDlp({ webhook: signer, classifier: classifier });
  var threw = null;
  try { await signer.send(input); }
  catch (e) { threw = e; }
  finally { handle.uninstall(); }
  return { threw: threw, sent: signer.sent };
}

async function testEveryReadingOfABodyIsScanned() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var text = function (charset) { return { "content-type": "text/plain; charset=" + charset }; };
  var cases = [
    ["FF FE before ASCII text", Buffer.concat([BOM_UTF16LE, ASCII_CARD]), {}],
    ["FE FF before ASCII text", Buffer.concat([BOM_UTF16BE, ASCII_CARD]), {}],
    ["FF FE before ASCII JSON under charset=utf-8", Buffer.concat([BOM_UTF16LE, Buffer.from(CARD_JSON)]), _ct("utf-8")],
    ["ASCII JSON under charset=utf-16le", Buffer.from(CARD_JSON), _ct("utf-16le")],
    ["ASCII text under charset=utf-16be", ASCII_CARD, text("utf-16be")],
    ["ASCII text under charset=UTF-16LE", ASCII_CARD, text("UTF-16LE")],
    ["ASCII text under a quoted, padded charset", ASCII_CARD, text("\" utf-16le \"")],
    ["ASCII text under a charset followed by a tab", ASCII_CARD, text("utf-16le\t")],
    ["a UTF-16BE card after a UTF-16LE BOM under charset=utf-16be",
      Buffer.concat([BOM_UTF16LE, _utf16be("card 4111111111111111")]), text("utf-16be")],
    ["a string body whose UTF-8 bytes are a UTF-16LE card, under charset=utf-16le", UTF16LE_CARD_AS_STRING,
      text("utf-16le")],
  ];
  var sent = [];
  for (var i = 0; i < cases.length; i += 1) {
    var r = await _requestThroughDlp(pan, { url: "https://example.com/x", headers: cases[i][2], body: cases[i][1] });
    if (!_refused(r)) sent.push(cases[i][0] + ": " + _outcome(r));
  }
  check("httpClient: a card number in any reading of a body (UTF-8, its BOM, its charset) is refused",
    sent.length === 0, sent.join("; "));

  var hook = await _webhookThroughDlp(pan, { url: "https://example.com/hook", body: Buffer.concat([BOM_UTF16LE, ASCII_CARD]) });
  var hookCharset = await _webhookThroughDlp(pan, { url: "https://example.com/hook", body: Buffer.from(CARD_JSON),
    headers: _ct("utf-16le") });
  check("webhook: a card number in the UTF-8 reading of a UTF-16 body is refused",
    hook.threw && hook.threw.code === "redact-dlp/refused" && hook.sent.length === 0 &&
    hookCharset.threw && hookCharset.threw.code === "redact-dlp/refused" && hookCharset.sent.length === 0,
    String(hook.threw && hook.threw.code) + " / " + String(hookCharset.threw && hookCharset.threw.code));

  var mp = await _requestThroughDlp(pan, { url: "https://example.com/up",
    multipart: { files: [{ field: "f", filename: "a.txt", content: Buffer.concat([BOM_UTF16LE, ASCII_CARD]) }] } });
  check("httpClient: a card number in the UTF-8 reading of UTF-16 multipart content is refused",
    _refused(mp) && mp.sentOpts === null, _outcome(mp));

  var mail = _fakeMail();
  var mh = b.redact.installOutboundDlp({ mail: mail, classifier: pan });
  var mailThrew = null;
  try { await mail.send({ to: "x@y", subject: "s", text: Buffer.concat([BOM_UTF16LE, ASCII_CARD]) }); }
  catch (e) { mailThrew = e; }
  finally { mh.uninstall(); }
  check("mail.send refuses a card number in the UTF-8 reading of UTF-16 text",
    mailThrew && mailThrew.code === "redact-dlp/refused" && mail.sent.length === 0, mailThrew && mailThrew.code);

  var top = pan({ body: Buffer.concat([BOM_UTF16LE, ASCII_CARD]) });
  var nested = pan({ body: { file: Buffer.concat([BOM_UTF16BE, ASCII_CARD]) } });
  check("classifyDefaults: a card number in the UTF-8 reading of a UTF-16 bytes body or leaf is refused",
    top.verdict === "refuse" && nested.verdict === "refuse", JSON.stringify([top.hits, nested.hits]));

  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var ssnBodies = [
    ["httpClient FF FE before ASCII", { url: "https://example.com/x", body: Buffer.concat([BOM_UTF16LE, ASCII_SSN]) }],
    ["httpClient ASCII under charset=utf-16le", { url: "https://example.com/x", headers: text("utf-16le"), body: ASCII_SSN }],
    ["multipart FF FE before ASCII", { url: "https://example.com/up",
      multipart: { files: [{ field: "f", filename: "a.txt", content: Buffer.concat([BOM_UTF16LE, ASCII_SSN]) }] } }],
  ];
  var wrong = [];
  for (var s = 0; s < ssnBodies.length; s += 1) {
    var rs = await _requestThroughDlp(ssn, ssnBodies[s][1]);
    var refusedHit = rs.refused !== null && rs.refused.hits.some(function (h) { return h.label === "ssn" && h.action === "refuse"; });
    if (!_refused(rs) || !refusedHit || rs.sentOpts !== null) wrong.push(ssnBodies[s][0] + ": " + _outcome(rs));
  }
  var hookSsn = await _webhookThroughDlp(ssn, { url: "https://example.com/hook", body: Buffer.concat([BOM_UTF16LE, ASCII_SSN]) });
  if (!hookSsn.threw || hookSsn.threw.code !== "redact-dlp/refused" || hookSsn.sent.length !== 0) {
    wrong.push("webhook FF FE before ASCII: " + (hookSsn.threw ? hookSsn.threw.code : "sent"));
  }
  var leaf = ssn({ body: { file: Buffer.concat([BOM_UTF16LE, ASCII_SSN]) } });
  if (leaf.verdict !== "refuse" || !leaf.hits.every(function (h) { return h.action === "refuse"; })) {
    wrong.push("classifyDefaults leaf: " + JSON.stringify(leaf.hits));
  }
  check("a redaction found in the UTF-8 reading of a UTF-16 body is refused, not re-encoded",
    wrong.length === 0, wrong.join("; "));

  var undecodable = [
    ["a UTF-16 BOM under a charset the runtime cannot decode", Buffer.concat([BOM_UTF16LE, Buffer.from(CLEAN_JSON, "utf16le")]),
      _ct("x-no-such-charset")],
    ["a UTF-16 BOM under two different charsets", Buffer.concat([BOM_UTF16LE, Buffer.from(CLEAN_JSON, "utf16le")]),
      { "Content-Type": "application/json; charset=utf-8", "content-type": "application/json; charset=windows-1252" }],
    ["a UTF-8 BOM under charset=utf-16", Buffer.concat([BOM_UTF8, Buffer.from(CLEAN_JSON)]), _ct("utf-16")],
    ["a string body under charset=utf-32", CLEAN_JSON, _ct("utf-32")],
    ["a string body under charset=utf-16", CLEAN_JSON, _ct("utf-16")],
  ];
  var notRefused = [];
  for (var u = 0; u < undecodable.length; u += 1) {
    var ru = await _requestThroughDlp(pan, { url: "https://example.com/x", headers: undecodable[u][2], body: undecodable[u][1] });
    if (ru.threw === null || ru.threw.code !== "redact-dlp/undecodable-body" || ru.sent !== null ||
        !_hasLabel(ru, "undecodable-body")) {
      notRefused.push(undecodable[u][0] + ": " + _outcome(ru));
    }
  }
  check("httpClient: a body with a reading that cannot be decoded is refused with redact-dlp/undecodable-body",
    notRefused.length === 0, notRefused.join("; "));

  var controls = [
    ["clean ASCII text under charset=utf-16le", Buffer.from("hello there"), text("utf-16le")],
    ["a clean string body under charset=utf-16le", "hello there", text("utf-16le")],
    ["a clean string body under charset=utf-8", CLEAN_JSON, _ct("utf-8")],
  ];
  var notSent = [];
  for (var c = 0; c < controls.length; c += 1) {
    var rc = await _requestThroughDlp(pan, { url: "https://example.com/x", headers: controls[c][2], body: controls[c][1] });
    if (rc.threw !== null || rc.sent !== controls[c][1]) notSent.push(controls[c][0] + ": " + _outcome(rc));
  }
  check("control: a clean body is sent unchanged in every reading", notSent.length === 0, notSent.join("; "));
  var utf8String = await _requestThroughDlp(ssn, { url: "https://example.com/x", headers: _ct("utf-8"),
    body: "ssn 123-45-6789" });
  check("control: a string body under charset=utf-8 that needs redacting is sent redacted",
    utf8String.threw === null && utf8String.sent === "ssn [REDACTED]", _outcome(utf8String));
}

// Multipart file content is read by its byte-order mark and by the charset
// of the part's Content-Type, as the main body is.
async function testMultipartContentIsDecodedByItsPartCharset() {
  var pan = b.redact.classifyDefaults({ patterns: ["pan"] });
  var part = function (file) { return { url: "https://example.com/up", multipart: { files: [file] } }; };
  var refused = [
    ["UTF-16LE content named by contentType", part({ field: "f", filename: "a.txt",
      contentType: "text/plain; charset=utf-16le", content: Buffer.from("card 4111111111111111", "utf16le") })],
    ["UTF-16BE content named by mimeType", part({ field: "f", filename: "a.txt",
      mimeType: "text/plain; charset=utf-16be", content: _utf16be("card 4111111111111111") })],
    ["string content whose UTF-8 bytes are a UTF-16LE card", part({ field: "f", filename: "a.txt",
      contentType: "text/plain; charset=utf-16le", content: UTF16LE_CARD_AS_STRING })],
  ];
  var sent = [];
  for (var i = 0; i < refused.length; i += 1) {
    var r = await _requestThroughDlp(pan, refused[i][1]);
    if (!_refused(r) || r.sentOpts !== null) sent.push(refused[i][0] + ": " + _outcome(r));
  }
  check("multipart: a card number in content read by the part charset is refused", sent.length === 0, sent.join("; "));

  var undecodable = [
    ["charset=utf-32", part({ field: "f", contentType: "text/plain; charset=utf-32", content: Buffer.from("x") })],
    ["charset=utf-16 without a BOM", part({ field: "f", contentType: "text/plain; charset=utf-16",
      content: Buffer.from("hello", "utf16le") })],
    ["a UTF-32 BOM", part({ field: "f", content: Buffer.concat([BOM_UTF32LE, Buffer.from("x")]) })],
  ];
  var notRefused = [];
  for (var u = 0; u < undecodable.length; u += 1) {
    var ru = await _requestThroughDlp(pan, undecodable[u][1]);
    var where = ru.refused !== null && ru.refused.hits.some(function (h) {
      return h.label === "undecodable-body" && h.where === "multipart.files[0].content";
    });
    if (ru.threw === null || ru.threw.code !== "redact-dlp/undecodable-body" || ru.sentOpts !== null || !where) {
      notRefused.push(undecodable[u][0] + ": " + _outcome(ru) + " " + JSON.stringify(ru.refused && ru.refused.hits));
    }
  }
  check("multipart: content whose part encoding cannot be read is refused with redact-dlp/undecodable-body",
    notRefused.length === 0, notRefused.join("; "));

  var ssn = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var rs = await _requestThroughDlp(ssn, part({ field: "f", filename: "a.txt", contentType: "text/plain; charset=utf-16le",
    content: Buffer.from("ssn 123-45-6789", "utf16le") }));
  check("multipart: UTF-16 content that needs redacting is refused, not re-encoded",
    _refused(rs) && rs.sentOpts === null && rs.refused.hits.some(function (h) { return h.label === "ssn" && h.action === "refuse"; }),
    _outcome(rs) + " " + JSON.stringify(rs.refused && rs.refused.hits));

  var cleanSpec = { files: [{ field: "f", filename: "a.txt", contentType: "text/plain; charset=utf-16le",
    content: Buffer.from("hello there", "utf16le") }] };
  var rc = await _requestThroughDlp(pan, { url: "https://example.com/up", multipart: cleanSpec });
  check("control: clean UTF-16 multipart content is sent with the same spec",
    rc.threw === null && rc.sentOpts && rc.sentOpts.multipart === cleanSpec, _outcome(rc));
  var r8 = await _requestThroughDlp(ssn, part({ field: "f", filename: "a.txt", contentType: "text/plain; charset=utf-8",
    content: Buffer.from("ssn 123-45-6789") }));
  var mp8 = r8.sentOpts && r8.sentOpts.multipart;
  check("control: UTF-8 multipart content that needs redacting is sent redacted",
    r8.threw === null && mp8 && mp8.files[0].content.toString() === "ssn [REDACTED]" &&
    mp8.files[0].contentType === "text/plain; charset=utf-8", _outcome(r8));
}

async function testHttpClientAndMailScanNonStringLeaves() {
  var client = _fakeHttpClient();
  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  try {
    var threw = null;
    try { await client.request({ url: "https://example.com/x", body: { card: 4111111111111111 } }); }
    catch (e) { threw = e; }
    check("httpClient.request refuses a numeric PAN in an object body",
      threw && threw.code === "redact-dlp/refused" && client.sent.length === 0);
  } finally { handle.uninstall(); }

  var mail = _fakeMail();
  var mh = b.redact.installOutboundDlp({
    mail: mail,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  try {
    var threwMail = null;
    try { await mail.send({ to: "x@y", subject: "s", text: Buffer.from("card 4111111111111111") }); }
    catch (e) { threwMail = e; }
    check("mail.send refuses a PAN in text given as a Buffer",
      threwMail && threwMail.code === "redact-dlp/refused" && mail.sent.length === 0);
  } finally { mh.uninstall(); }
}

async function testPostureWiring() {
  var client = _fakeHttpClient();
  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    posture: "pci-dss",
  });
  check("posture install succeeds", handle.installed.httpClient === true);
  var threw = false;
  try { await client.request({ url: "https://x", body: { card: "4111111111111111" } }); }
  catch (e) { threw = e; }
  check("pci-dss posture refuses PAN", threw && threw.code === "redact-dlp/refused");
  handle.uninstall();

  var threwUnknown = false;
  try { b.redact.installOutboundDlp({ httpClient: _fakeHttpClient(), posture: "no-such" }); }
  catch (_e) { threwUnknown = true; }
  check("unknown posture rejected", threwUnknown);
}

async function testIdempotentInstall() {
  var client = _fakeHttpClient();
  var h1 = b.redact.installOutboundDlp({ httpClient: client, posture: "pci-dss" });
  var h2 = b.redact.installOutboundDlp({ httpClient: client, posture: "pci-dss" });
  check("second install on same instance no-ops",
    h1.installed.httpClient === true && h2.installed.httpClient === false);
  h1.uninstall();
}

// Bug A — installForPosture is NOT auto-called by b.compliance.set; the
// install tracking + the boot warning replace the false advertisement.
function testIsOutboundDlpInstalledSurface() {
  b.redact._resetForTest();
  check("b.redact.isOutboundDlpInstalled is a function",
    typeof b.redact.isOutboundDlpInstalled === "function");
  check("isOutboundDlpInstalled false before any install",
    b.redact.isOutboundDlpInstalled() === false);
  var http = _fakeHttpClient();
  var dlp = b.redact.installForPosture("hipaa", { httpClient: http });
  check("isOutboundDlpInstalled true after installForPosture",
    b.redact.isOutboundDlpInstalled() === true);
  dlp.uninstall();
  check("isOutboundDlpInstalled false after uninstall",
    b.redact.isOutboundDlpInstalled() === false);
}

function testComplianceSetWarnsWhenDlpUnwired() {
  b.compliance._resetForTest();
  b.redact._resetForTest();
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    b.compliance.set("hipaa");
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "compliance.posture.outbound_dlp_unwired";
  });
  check("compliance.set('hipaa') warns when no outbound DLP wired",
    warns.length === 1 && warns[0].outcome === "warning" && warns[0].metadata.posture === "hipaa");
  b.compliance._resetForTest();
}

function testComplianceSetNoWarnWhenDlpWired() {
  b.compliance._resetForTest();
  b.redact._resetForTest();
  // Wire DLP first, then pin the posture — set() must NOT warn.
  var http = _fakeHttpClient();
  var dlp = b.redact.installForPosture("pci-dss", { httpClient: http });
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    b.compliance.set("pci-dss");
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "compliance.posture.outbound_dlp_unwired";
  });
  check("compliance.set('pci-dss') does not warn when DLP wired",
    warns.length === 0);
  dlp.uninstall();
  b.compliance._resetForTest();
}

function testComplianceSetNoWarnForNonDlpPosture() {
  b.compliance._resetForTest();
  b.redact._resetForTest();
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    // sox is regulated but has no outbound-DLP classifier preset.
    b.compliance.set("sox");
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "compliance.posture.outbound_dlp_unwired";
  });
  check("compliance.set('sox') (non-DLP-floor posture) does not warn",
    warns.length === 0);
  b.compliance._resetForTest();
}

async function run() {
  testSurface();
  testClassifierRejectsBadOpts();
  testClassifyPan();
  testClassifySsn();
  testClassifyJwtAndAwsKey();
  testClassifyHeaders();
  await testInstallHttpClientRefuse();
  await testInstallHttpClientRedact();
  await testInstallMail();
  await testInstallWebhook();
  testClassifyNonStringLeaves();
  await testWebhookScansNumericAndWireText();
  await testWebhookScansWhatItSends();
  await testWebhookExactLiteralsRespectRedactions();
  await testWebhookScansRoundedPanInEverySpelling();
  await testWebhookWireWalkMemoryIsBoundedByTheBody();
  await testPanDetectorChecksEveryDigitRun();
  await testRawTextScansRoundedPanInEverySpelling();
  await testHttpClientJsonTextIsClassifiedParsed();
  await testMemberNamesAreScanned();
  await testJsonTextBeyondTheDefaultParseLimits();
  await testTokenScanMemoryIsBoundedByTheBody();
  await testHeaderNamesAreScanned();
  await testRequestUrlIsScanned();
  await testMultipartIsScanned();
  await testRealHttpClientScansWhatReachesTheServer();
  await testAsyncBeforeHooksAreScanned();
  await testHookVerdictDescribesTheSentBody();
  await testRedactWithoutABodyFailsClosed();
  await testHttpClientAndMailScanNonStringLeaves();
  await testBytesBodyIsDecodedByBomAndCharset();
  await testNonUtf8BytesBodyIsRefusedRatherThanReEncoded();
  await testWebhookAndNestedBytesAreDecodedByBom();
  await testEveryReadingOfABodyIsScanned();
  await testMultipartContentIsDecodedByItsPartCharset();
  await testPostureWiring();
  await testIdempotentInstall();
  testIsOutboundDlpInstalledSurface();
  testComplianceSetWarnsWhenDlpUnwired();
  testComplianceSetNoWarnWhenDlpWired();
  testComplianceSetNoWarnForNonDlpPosture();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK redact-dlp — " + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { run: run };
