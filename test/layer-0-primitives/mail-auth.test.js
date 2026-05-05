"use strict";
/**
 * b.mail.spf + b.mail.dmarc + b.mail.arc — inbound mail
 * authentication-results verification.
 *
 * Live DNS lookups don't run in smoke (network-bound tests live in
 * test/integration). What's covered: parse + match + alignment logic
 * via operator-supplied dnsLookup mock callbacks; ARC chain shape.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("mail.spf.verify is a function",       typeof b.mail.spf.verify === "function");
  check("mail.spf.parseRecord is a function",  typeof b.mail.spf.parseRecord === "function");
  check("mail.dmarc.evaluate is a function",   typeof b.mail.dmarc.evaluate === "function");
  check("mail.dmarc.parseRecord is a function",typeof b.mail.dmarc.parseRecord === "function");
  check("mail.arc.verify is a function",       typeof b.mail.arc.verify === "function");
  check("frameworkError.MailAuthError exposed",
        typeof b.frameworkError.MailAuthError === "function");
}

function testSpfParse() {
  var rec = b.mail.spf.parseRecord("v=spf1 ip4:192.0.2.0/24 include:mailgun.org -all");
  check("spf.parseRecord returns 3 mechanisms",
        rec.length === 3 &&
        rec[0].mechanism === "ip4" && rec[0].arg === "192.0.2.0/24" &&
        rec[1].mechanism === "include" && rec[1].arg === "mailgun.org" &&
        rec[2].mechanism === "all" && rec[2].qualifier === "-");
}

function testSpfBadRecord() {
  var threw = null;
  try { b.mail.spf.parseRecord("v=spf2 +all"); }
  catch (e) { threw = e; }
  check("spf.parseRecord rejects bad version",
        threw && /spf-bad-version/.test(threw.code || ""));
}

async function testSpfVerifyMockedDns() {
  // Mock dnsLookup that resolves "example.com" SPF record.
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") {
      return [["v=spf1 ip4:192.0.2.0/24 -all"]];
    }
    var err = new Error("ENOTFOUND");
    err.code = "ENOTFOUND";
    throw err;
  };
  var rv = await b.mail.spf.verify({
    ip:       "192.0.2.5",
    mailFrom: "alice@example.com",
    dnsLookup: dnsLookup,
  });
  check("spf.verify(matching ip) → pass",
        rv.result === "pass");

  var rv2 = await b.mail.spf.verify({
    ip:       "203.0.113.99",
    mailFrom: "alice@example.com",
    dnsLookup: dnsLookup,
  });
  check("spf.verify(non-matching ip) → fail (-all)",
        rv2.result === "fail");
}

function testDmarcParse() {
  var policy = b.mail.dmarc.parseRecord("v=DMARC1; p=reject; pct=50; aspf=s; adkim=r");
  check("dmarc.parseRecord returns shape",
        policy.v === "DMARC1" && policy.p === "reject" &&
        policy.pct === 50 && policy.aspf === "s" && policy.adkim === "r");
}

async function testDmarcEvaluateAligned() {
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=reject; aspf=r; adkim=r"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:    "alice@example.com",
    spf:     { result: "pass", domain: "example.com" },
    dkim:    [{ result: "pass", domain: "example.com" }],
    dnsLookup: dnsLookup,
  });
  check("dmarc.evaluate: aligned spf+dkim → pass + deliver",
        rv.result === "pass" && rv.recommendedAction === "deliver" &&
        rv.alignment.spf === true && rv.alignment.dkim === true);
}

async function testDmarcEvaluateUnaligned() {
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=quarantine"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:    "alice@example.com",
    spf:     { result: "pass", domain: "different.org" },
    dkim:    [],
    dnsLookup: dnsLookup,
  });
  check("dmarc.evaluate: unaligned → fail + quarantine",
        rv.result === "fail" && rv.recommendedAction === "quarantine");
}

async function testArcVerifyMissing() {
  var msg = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: incomplete chain → fail",
        rv.chainStatus === "fail");
}

async function testArcVerifyNone() {
  var msg = "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: no ARC headers → none",
        rv.chainStatus === "none" && rv.hopCount === 0);
}

async function testArcVerifyBadSignatures() {
  // All 3 ARC headers present but the b= values are dummy — signature
  // verification fails per-hop. Per the security-no-defer rule this
  // returns fail, NOT pass.
  var msg = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
            "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
            "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
            "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  // dnsLookup that returns a "valid" key for the signature check —
  // signatures are dummy so verify fails cleanly with "fail" not "permerror".
  var dnsLookup = async function (qname) {
    if (qname === "arc._domainkey.example.com") {
      // Generate a valid PEM-shape RSA key for the test (operator-side
      // would be a real DNS-published key). We use a fixed deterministic
      // key so the test doesn't bind to DNS.
      var nodeCrypto = require("crypto");
      var pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
      var spki = pair.publicKey.export({ type: "spki", format: "der" });
      return [["v=DKIM1; k=rsa; p=" + spki.toString("base64")]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.arc.verify(msg, { dnsLookup: dnsLookup });
  check("arc.verify with bad signatures → chainStatus=fail (not pass)",
        rv.chainStatus === "fail");
  check("arc.verify per-hop reports amsResult / asResult",
        rv.hops.length === 1 &&
        rv.hops[0].amsResult !== "pass" &&
        rv.hops[0].asResult !== "pass");
}

function _arcHopHeaders(i, cv) {
  // Synthetic ARC headers — signatures are dummy; the cv= edge tests
  // exercise the chain-rule validator, not the signature verifier.
  return "ARC-Authentication-Results: i=" + i + "; example.com; spf=pass\r\n" +
         "ARC-Message-Signature: i=" + i + "; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
         "ARC-Seal: i=" + i + "; a=rsa-sha256; cv=" + cv + "; d=example.com; s=arc; b=AAAA\r\n";
}

async function testArcVerifyDuplicateInstance() {
  // Two ARC-Seal headers at i=1 — chain MUST refuse rather than
  // silently overwrite the first signer's record.
  var msg = _arcHopHeaders(1, "none") +
            "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=attacker.com; s=arc; b=BBBB\r\n" +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: duplicate instance → fail w/ duplicate-instance reason",
        rv.chainStatus === "fail" && rv.reason === "duplicate-instance");
}

async function testArcVerifyNonContiguous() {
  // i=1 + i=3 (missing i=2) — chain MUST refuse.
  var msg = _arcHopHeaders(1, "none") +
            _arcHopHeaders(3, "pass") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: non-contiguous instances → fail",
        rv.chainStatus === "fail" && /incomplete-or-non-contiguous/.test(rv.reason || ""));
}

async function testArcVerifyTooManyHops() {
  // Synthesize 51 hops — RFC 8617 §5.1.2 caps at 50.
  var hopHeaders = "";
  for (var i = 1; i <= 51; i += 1) {
    hopHeaders += _arcHopHeaders(i, i === 1 ? "none" : "pass");
  }
  var msg = hopHeaders + "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: chain > 50 hops → fail w/ too-many-hops reason",
        rv.chainStatus === "fail" && rv.reason === "too-many-hops");
}

async function testArcVerifyHop1CvMustBeNone() {
  // i=1 with cv=pass — invalid: hop 1 has nothing upstream to validate.
  var msg = _arcHopHeaders(1, "pass") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: i=1 cv=pass → fail w/ i=1-cv-must-be-none reason",
        rv.chainStatus === "fail" && /i=1-cv-must-be-none/.test(rv.reason || ""));
}

async function testArcVerifyHop2CvNoneInvalid() {
  // i=2 with cv=none — invalid: hop 2+ MUST report pass or fail.
  var msg = _arcHopHeaders(1, "none") +
            _arcHopHeaders(2, "none") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: i=2 cv=none → fail w/ cv=none-invalid-after-hop-1 reason",
        rv.chainStatus === "fail" && /cv=none-invalid-after-hop-1/.test(rv.reason || ""));
}

async function testArcVerifyPassAfterFail() {
  // i=1 cv=none, i=2 cv=fail, i=3 cv=pass — invalid: a hop can't
  // claim chain pass after upstream observed fail.
  var msg = _arcHopHeaders(1, "none") +
            _arcHopHeaders(2, "fail") +
            _arcHopHeaders(3, "pass") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: cv=pass after upstream cv=fail → fail w/ pass-after-upstream-fail reason",
        rv.chainStatus === "fail" && /pass-after-upstream-fail/.test(rv.reason || ""));
}

function testDkimVerifySurface() {
  check("mail.dkim.verify is a function",
        typeof b.mail.dkim.verify === "function");
}

async function testDkimVerifyRoundTrip() {
  // Round-trip: sign with a real key, verify with the same key
  // surfaced via a mocked DNS lookup.
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var signer = b.mail.dkim.create({
    domain:     "example.com",
    selector:   "test",
    privateKey: pair.privateKey,
  });
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: hi\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n" +
            "Message-ID: <abc@example.com>\r\n\r\nHello.\r\n";
  var signed = signer.sign(msg);

  // Mocked DNS that returns the matching public key as base64 SPKI.
  var spkiB64 = nodeCrypto.createPublicKey(pair.publicKey)
    .export({ type: "spki", format: "der" })
    .toString("base64");
  var dnsLookup = async function (qname) {
    if (qname === "test._domainkey.example.com") {
      return [["v=DKIM1; k=rsa; p=" + spkiB64]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("dkim.verify round-trip: pass",
        Array.isArray(rv) && rv.length === 1 && rv[0].result === "pass");
}

async function testDkimVerifyNoSignature() {
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.dkim.verify(msg, {});
  check("dkim.verify with no DKIM-Signature → none",
        Array.isArray(rv) && rv[0].result === "none");
}

async function testDkimVerifyTampered() {
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var signer = b.mail.dkim.create({
    domain: "example.com", selector: "test", privateKey: pair.privateKey,
  });
  var signed = signer.sign(
    "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n" +
    "Date: Mon, 5 May 2026 10:00:00 +0000\r\nMessage-ID: <a@example.com>\r\n\r\nbody\r\n"
  );
  // Tamper the body after signing.
  var tampered = signed.replace("body", "EVIL");
  var spkiB64 = nodeCrypto.createPublicKey(pair.publicKey)
    .export({ type: "spki", format: "der" }).toString("base64");
  var dnsLookup = async function (qname) {
    if (qname === "test._domainkey.example.com") {
      return [["v=DKIM1; k=rsa; p=" + spkiB64]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dkim.verify(tampered, { dnsLookup: dnsLookup });
  check("dkim.verify on tampered body → fail",
        rv[0].result === "fail");
}

async function run() {
  testSurface();
  testSpfParse();
  testSpfBadRecord();
  await testSpfVerifyMockedDns();
  testDmarcParse();
  await testDmarcEvaluateAligned();
  await testDmarcEvaluateUnaligned();
  await testArcVerifyMissing();
  await testArcVerifyNone();
  await testArcVerifyBadSignatures();
  await testArcVerifyDuplicateInstance();
  await testArcVerifyNonContiguous();
  await testArcVerifyTooManyHops();
  await testArcVerifyHop1CvMustBeNone();
  await testArcVerifyHop2CvNoneInvalid();
  await testArcVerifyPassAfterFail();
  testDkimVerifySurface();
  await testDkimVerifyRoundTrip();
  await testDkimVerifyNoSignature();
  await testDkimVerifyTampered();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
