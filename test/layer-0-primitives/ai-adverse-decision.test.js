// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

async function run() {
  var captured = null;
  var hire = b.ai.adverseDecision.wrap({
    audit: false,
    name:        "hire-screening",
    model:       "screening-v3.1",
    legalBasis:  "ecoa-1002.9",
    decide:      function (subject) {
      return {
        outcome:          subject.score < 0.5 ? "adverse" : "favorable",
        score:            subject.score,
        principalReasons: subject.score < 0.5 ? ["insufficient-credit-history"] : [],
      };
    },
    onAdverse: function (subject, decision) { captured = decision; },
  });

  var favorable = await hire({ id: "good-1", score: 0.9 });
  check("favorable has no adverseNotice", favorable.adverseNotice === undefined);

  var adverse = await hire({ id: "bad-1", score: 0.1 });
  check("adverse has adverseNotice",                  adverse.adverseNotice !== undefined);
  check("adverseNotice carries subject id",           adverse.adverseNotice.subjectId === "bad-1");
  check("adverseNotice carries principal reasons",    adverse.adverseNotice.principalReasons.length === 1);
  check("adverseNotice carries regulation",           adverse.adverseNotice.regulation.indexOf("ECOA") !== -1);
  check("adverseNotice consumerRights.requestData",   adverse.adverseNotice.consumerRights.requestData === true);
  check("onAdverse hook fired",                       captured && captured.outcome === "adverse");

  var threwBadLegal = false;
  try {
    b.ai.adverseDecision.wrap({
      audit: false, name: "x", model: "x", legalBasis: "",
      decide: function () { return { outcome: "favorable" }; },
    });
  } catch (e) { threwBadLegal = e.code === "ai-adverse/bad-legal-basis"; }
  check("ai.adverseDecision refuses missing legalBasis", threwBadLegal);

  // `legalBasis` selects the statutory deadlines attached to every adverse
  // notice, and an unrecognised value fell back to "operator-defined", whose
  // deadlines are all null. One missing character in "gdpr-22" therefore
  // produced a notice claiming the subject has no right to an explanation, no
  // right to human review and no right to appeal — the exact obligations
  // Article 22 imposes, switched off silently, while the notice still recorded
  // the misspelled basis as though it had been honoured.
  var typoBasis = null;
  try {
    b.ai.adverseDecision.wrap({
      audit: false, name: "loan", model: "m1", legalBasis: "gdpr-2",
      decide: function () { return { outcome: "adverse", principalReasons: ["x"] }; },
    });
  } catch (e) { typoBasis = e; }
  check("ai.adverseDecision refuses a legalBasis it has no deadlines for",
        typoBasis && typoBasis.code === "ai-adverse/bad-legal-basis",
        String(typoBasis && (typoBasis.code || typoBasis.message)));

  // An operator whose regime the framework does not carry says so explicitly,
  // and gets the null deadlines by asking for them.
  var explicit = b.ai.adverseDecision.wrap({
    audit: false, name: "loan", model: "m1", legalBasis: "operator-defined",
    decide: function () { return { outcome: "adverse", principalReasons: ["x"] }; },
  });
  var od = await explicit({ id: "s1" });
  check("ai.adverseDecision: operator-defined is an explicit choice, still accepted",
        od.adverseNotice && od.adverseNotice.regulation === "operator-supplied");

  // Control: a real regime still attaches its real deadlines, so the refusal
  // above cannot be a check that rejects every basis.
  var real = b.ai.adverseDecision.wrap({
    audit: false, name: "loan", model: "m1", legalBasis: "gdpr-22",
    decide: function () { return { outcome: "adverse", principalReasons: ["x"] }; },
  });
  var rv = await real({ id: "s2" });
  check("ai.adverseDecision control: gdpr-22 carries its Article 22 rights",
        rv.adverseNotice.consumerRights.requestExplanation === true &&
        rv.adverseNotice.consumerRights.requestHumanReview === true &&
        rv.adverseNotice.consumerRights.requestAppeal === true,
        JSON.stringify(rv.adverseNotice.consumerRights));

  console.log("OK — ai.adverseDecision tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
