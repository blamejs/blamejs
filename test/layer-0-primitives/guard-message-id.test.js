// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardMessageId — RFC 5322 §3.6.4 Message-Id validator.
 * Gates Message-Id / In-Reply-To / References header values at
 * mail-store / MX / submission entry.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("validate is fn",            typeof b.guardMessageId.validate === "function");
  check("validateList is fn",        typeof b.guardMessageId.validateList === "function");
  check("compliancePosture is fn",   typeof b.guardMessageId.compliancePosture === "function");
  check("PROFILES frozen",           Object.isFrozen(b.guardMessageId.PROFILES));
  check("COMPLIANCE_POSTURES frozen", Object.isFrozen(b.guardMessageId.COMPLIANCE_POSTURES));
  check("NAME = messageId",          b.guardMessageId.NAME === "messageId");
  check("KIND = identifier",         b.guardMessageId.KIND === "identifier");
  check("GuardMessageIdError is fn", typeof b.guardMessageId.GuardMessageIdError === "function");
}

function testValidBracketed() {
  check("valid simple",      b.guardMessageId.validate("<abc@example.com>") === "<abc@example.com>");
  check("valid with hyphen", b.guardMessageId.validate("<abc-123@sub.example.com>") === "<abc-123@sub.example.com>");
  check("valid with plus",   b.guardMessageId.validate("<abc+detail@example.com>") === "<abc+detail@example.com>");
}

function expectRefused(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testRefuses() {
  expectRefused("refuses unbracketed (strict)",
    function () { b.guardMessageId.validate("abc@example.com"); },
    "message-id/unbracketed");
  expectRefused("refuses no-at",
    function () { b.guardMessageId.validate("<abc>"); },
    "message-id/no-at");
  expectRefused("refuses empty",
    function () { b.guardMessageId.validate(""); },
    "message-id/empty");
  expectRefused("refuses non-string",
    function () { b.guardMessageId.validate(42); },
    "message-id/bad-input");
  expectRefused("refuses CR (header-injection class)",
    function () { b.guardMessageId.validate("<a\rb@x>"); },
    "message-id/control-char");
  expectRefused("refuses LF (header-injection class)",
    function () { b.guardMessageId.validate("<a\nb@x>"); },
    "message-id/control-char");
  expectRefused("refuses NUL",
    function () { b.guardMessageId.validate("<a\x00b@x>"); },
    "message-id/control-char");
  expectRefused("refuses DEL",
    function () { b.guardMessageId.validate("<a\u007Fb@x>"); },
    "message-id/control-char");
  expectRefused("refuses RTLO bidi (CVE-2021-42574 class)",
    function () { b.guardMessageId.validate("<a‮b@x>"); },
    "message-id/bidi");
  expectRefused("refuses nested brackets",
    function () { b.guardMessageId.validate("<<inner@x>@y>"); },
    "message-id/nested-brackets");
  expectRefused("refuses oversize",
    function () {
      var big = "<" + new Array(1100).join("a") + "@x>";
      b.guardMessageId.validate(big);
    },
    "message-id/oversize");
}

function testProfiles() {
  // balanced — bare token accepted, control chars still refused.
  check("balanced accepts unbracketed",
        b.guardMessageId.validate("abc@example.com", { profile: "balanced" }) === "abc@example.com");
  expectRefused("balanced refuses CR",
    function () { b.guardMessageId.validate("abc\r@x", { profile: "balanced" }); },
    "message-id/control-char");

  // permissive — bidi accepted, NUL still refused.
  check("permissive accepts bidi",
        typeof b.guardMessageId.validate("<a‮b@x>", { profile: "permissive" }) === "string");
  expectRefused("permissive refuses NUL",
    function () { b.guardMessageId.validate("<a\x00b@x>", { profile: "permissive" }); },
    "message-id/control-char");
}

function testCompliancePostures() {
  check("hipaa → strict",     b.guardMessageId.compliancePosture("hipaa") === "strict");
  check("pci-dss → strict",   b.guardMessageId.compliancePosture("pci-dss") === "strict");
  check("gdpr → strict",      b.guardMessageId.compliancePosture("gdpr") === "strict");
  check("soc2 → strict",      b.guardMessageId.compliancePosture("soc2") === "strict");
  check("unknown → null",     b.guardMessageId.compliancePosture("nope") === null);
  // Posture overrides profile — operator passing balanced under HIPAA gets strict.
  expectRefused("posture HIPAA pins strict (refuses bare token)",
    function () { b.guardMessageId.validate("abc@x", { profile: "balanced", posture: "hipaa" }); },
    "message-id/unbracketed");
}

function testValidateList() {
  var ids = b.guardMessageId.validateList("<a@x> <b@x> <c@x>");
  check("list parses 3 ids", ids.length === 3 && ids[0] === "<a@x>");

  // Empty string → empty array.
  var empty = b.guardMessageId.validateList("");
  check("empty list → []", Array.isArray(empty) && empty.length === 0);

  expectRefused("list refuses chain too long",
    function () {
      var ids = [];
      for (var i = 0; i < 105; i += 1) ids.push("<m" + i + "@x>");
      b.guardMessageId.validateList(ids.join(" "));
    },
    "message-id/chain-too-long");

  expectRefused("list refuses bad id within",
    function () { b.guardMessageId.validateList("<a@x> badone <c@x>"); },
    "message-id/unbracketed");
}

async function run() {
  testSurface();
  testValidBracketed();
  testRefuses();
  testProfiles();
  testCompliancePostures();
  testValidateList();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
