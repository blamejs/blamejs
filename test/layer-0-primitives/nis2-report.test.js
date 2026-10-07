// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

async function run() {
  var n = b.nis2.report.create({
    audit: false,
    entityId: "acme-1", entityType: "essential", sectorAnnex: "I.6",
  });
  var rec = await n.open({ detectedAt: Date.now() });
  check("nis2.open returns id", typeof rec.id === "string");
  check("nis2 uses 30d final", rec.dueBy.final === rec.detectedAt + 30 * 24 * 60 * 60 * 1000);

  var threwBadType = false;
  try { b.nis2.report.create({ entityId: "x", entityType: "huge", sectorAnnex: "I.1" }); }
  catch (e) { threwBadType = e.code === "nis2-report/bad-entity-type"; }
  check("nis2 refuses bad entityType", threwBadType);

  // A stage is recorded against the directive's deadline before the CSIRT
  // POST runs, so a filing can be on time while the endpoint is down. The
  // stage stays filed, and `resubmit` is the retry path: calling the stage
  // again is refused, which used to leave the operator with a record saying
  // the stage was filed and no way to send it.
  var attempts = [];
  var failingClient = {
    request: function (args) {
      attempts.push(JSON.parse(args.body.toString("utf8")));
      return Promise.resolve({ statusCode: 503, headers: {}, body: Buffer.alloc(0) });
    },
  };
  var down = b.nis2.report.create({
    audit: false, entityId: "acme-2", entityType: "important", sectorAnnex: "II.6",
    csirtEndpoint: "https://csirt.example/report", httpClient: failingClient,
  });
  var inc = await down.open({ detectedAt: Date.now() });
  var ew = await down.earlyWarning(inc.id, { submit: true, significant: true });
  check("a 503 from the CSIRT reports submitted:false with the status code",
        !!ew.submitted && ew.submitted.submitted === false &&
        ew.submitted.statusCode === 503, JSON.stringify(ew.submitted));
  check("and the stage is still filed against the 24-hour deadline",
        !!down.get(inc.id).stages.initial);
  check("one POST was attempted", attempts.length === 1, String(attempts.length));

  var refiled = null;
  try { await down.earlyWarning(inc.id, { submit: true }); }
  catch (e) { refiled = e; }
  check("filing the same stage again is refused",
        !!refiled && refiled.code === "incident-report/stage-already-filed",
        refiled && String(refiled.code));
  check("and the refused re-filing did not POST again",
        attempts.length === 1, String(attempts.length));

  var filedAt = down.get(inc.id).stages.initial.filedAt;
  var again = await down.resubmit(inc.id, "early-warning");
  check("resubmit re-POSTs the stage without re-filing it",
        attempts.length === 2 && again.submitted.submitted === false,
        String(attempts.length));
  check("and the filing time is unchanged",
        down.get(inc.id).stages.initial.filedAt === filedAt);
  // Called with no fields, the retry carries the ones the stage was filed
  // with. Sending an empty envelope would hand the CSIRT a report missing
  // what the first attempt said.
  check("the retry sends the fields the stage was filed with",
        attempts[1].fields.significant === true,
        JSON.stringify(attempts[1].fields));
  check("and the retried envelope matches the first attempt's",
        JSON.stringify(attempts[1]) === JSON.stringify(attempts[0]));
  // A third argument replaces them, for a report corrected before the retry.
  await down.resubmit(inc.id, "early-warning", { significant: false, corrected: true });
  check("explicit fields replace the filed ones",
        attempts[2].fields.corrected === true && attempts[2].fields.significant === false,
        JSON.stringify(attempts[2].fields));

  var acceptingClient = { request: function () {
    return Promise.resolve({ statusCode: 202, headers: {}, body: Buffer.alloc(0) });
  } };
  var recovered = b.nis2.report.create({
    audit: false, entityId: "acme-3", entityType: "important", sectorAnnex: "II.6",
    csirtEndpoint: "https://csirt.example/report", httpClient: acceptingClient,
  });
  var inc2 = await recovered.open({ detectedAt: Date.now() });
  await recovered.earlyWarning(inc2.id, { submit: true });
  var accepted = await recovered.resubmit(inc2.id, "early-warning");
  check("resubmit reports success once the endpoint accepts it",
        accepted.submitted.submitted === true && accepted.submitted.statusCode === 202,
        JSON.stringify(accepted.submitted));

  var badStage = null;
  try { await recovered.resubmit(inc2.id, "interim"); } catch (e) { badStage = e; }
  check("resubmit refuses a stage outside the three",
        !!badStage && badStage.code === "nis2-report/bad-stage",
        badStage && String(badStage.code));
  var unknown = null;
  try { await recovered.resubmit("no-such-incident", "final"); } catch (e) { unknown = e; }
  check("resubmit refuses an unknown incident",
        !!unknown && unknown.code === "nis2-report/unknown-incident",
        unknown && String(unknown.code));
  var notFiled = null;
  try { await recovered.resubmit(inc2.id, "final"); } catch (e) { notFiled = e; }
  check("resubmit refuses a stage that has not been filed",
        !!notFiled && notFiled.code === "nis2-report/stage-not-filed",
        notFiled && String(notFiled.code));

  console.log("OK — nis2.report tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
