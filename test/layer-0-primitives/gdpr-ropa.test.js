// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function run() {
  var ropa = b.gdpr.ropa.create({
    audit: false,
    controller: { name: "Acme", contact: "dpo@acme.example" },
  });
  ropa.register({
    id: "crm",
    name: "CRM tracking",
    purposes: ["lead-tracking"],
    legalBasis: "legitimate-interests",
    dataCategories: ["contact-info"],
  });
  check("ropa.register stored",      ropa.list().length === 1);
  check("ropa.get returns record",   ropa.get("crm").name === "CRM tracking");

  var json = ropa["export"]({ format: "json" });
  check("ropa.export json carries activities", json.activities.length === 1);
  check("ropa.export json includes regulation", json.regulation.indexOf("GDPR") !== -1);

  var md = ropa["export"]({ format: "markdown" });
  check("ropa.export markdown includes title", md.indexOf("Article 30") !== -1);

  var threwBadBasis = false;
  try {
    ropa.register({ id: "x", name: "x", purposes: ["x"], legalBasis: "made-up", dataCategories: ["x"] });
  } catch (e) { threwBadBasis = e.code === "gdpr-ropa/bad-legal-basis"; }
  check("ropa refuses bad legalBasis", threwBadBasis);

  ropa.update("crm", { retentionPeriod: "5y" });
  check("ropa.update merges patch", ropa.get("crm").retentionPeriod === "5y");

  // update() must validate legalBasis with the SAME rigor as register().
  // register() rejects a falsy-but-invalid legalBasis (""/0/false/undefined);
  // update() must too — otherwise a required Article 30 field can be silently
  // corrupted to a value the VALID_LEGAL_BASES enum would reject. A truthiness
  // guard (`if (patch.legalBasis && ...)`) skipped validation whenever the
  // incoming value was falsy, so an empty string sailed through where the enum
  // check would have caught "made-up".
  var basisRopa = b.gdpr.ropa.create({
    audit: false, controller: { name: "Acme", contact: "dpo@acme.example" },
  });
  basisRopa.register({ id: "a1", name: "A1", purposes: ["p"], legalBasis: "consent", dataCategories: ["c"] });

  var updEmptyRejected = false;
  try { basisRopa.update("a1", { legalBasis: "" }); }
  catch (e) { updEmptyRejected = e.code === "gdpr-ropa/bad-legal-basis"; }
  check("ropa.update rejects empty-string legalBasis (parity with register)", updEmptyRejected);
  check("ropa.update leaves legalBasis intact after rejecting empty",
        basisRopa.get("a1").legalBasis === "consent");

  var updZeroRejected = false;
  try { basisRopa.update("a1", { legalBasis: 0 }); }
  catch (e) { updZeroRejected = e.code === "gdpr-ropa/bad-legal-basis"; }
  check("ropa.update rejects falsy numeric legalBasis", updZeroRejected);
  check("ropa.update leaves legalBasis intact after rejecting 0",
        basisRopa.get("a1").legalBasis === "consent");

  // A valid legalBasis update still succeeds (fix must not over-reject).
  basisRopa.update("a1", { legalBasis: "contract" });
  check("ropa.update accepts a valid legalBasis change", basisRopa.get("a1").legalBasis === "contract");

  // update() validated only a changed legalBasis, so a patch clearing another
  // required field left the register exporting an activity missing an
  // Article 30 §1 field. The merged record is validated now.
  // A patch clears a field with undefined, with null, or with an empty value.
  // Only `undefined` was treated as missing, so `{ name: null }` replaced a
  // valid activity with one carrying no usable name.
  ["name", "purposes", "dataCategories", "legalBasis"].forEach(function (field) {
    [undefined, null].forEach(function (blank) {
      var patch = {};
      patch[field] = blank;
      var cleared = null;
      try { basisRopa.update("a1", patch); } catch (e) { cleared = e; }
      check("ropa.update refuses a patch setting " + field + " to " + String(blank),
            !!cleared && (cleared.code === "gdpr-ropa/missing-field" ||
                          cleared.code === "gdpr-ropa/bad-legal-basis"),
            field + "=" + String(blank) + " -> " + (cleared && cleared.code));
    });
  });
  // Present but unusable: an empty value, or the wrong type. `name` is a
  // non-empty string and the two lists are non-empty arrays of names, so a
  // record stored with `purposes: 42` no longer reaches the Markdown export
  // and throws an uncoded TypeError at `(e.purposes || []).join(", ")`.
  // `missing-field` stays for absent; `bad-field` is present-but-unusable.
  [["name", ""], ["name", 7], ["purposes", []], ["purposes", 42],
   ["purposes", [7]], ["dataCategories", []], ["dataCategories", {}],
  ].forEach(function (pair) {
    var patch = {};
    patch[pair[0]] = pair[1];
    var unusable = null;
    try { basisRopa.update("a1", patch); } catch (e) { unusable = e; }
    check("ropa.update refuses " + pair[0] + " = " + JSON.stringify(pair[1]),
          !!unusable && unusable.code === "gdpr-ropa/bad-field",
          pair[0] + " -> " + (unusable && unusable.code));
  });
  // The control: the stored activity is still exportable, so the refusals
  // above kept the register in a state the Markdown writer can read.
  check("and the register still exports after every refusal",
        typeof basisRopa["export"]({ format: "markdown" }) === "string");

  // The validation only holds if the record cannot be edited around it. The
  // register kept the caller's object and handed it back, so clearing the
  // array passed to register(), or assigning to a field of the returned
  // record, put an activity the validation had refused into the next export.
  var sealRopa = b.gdpr.ropa.create({ audit: false, controller: { name: "Acme" } });
  var callerPurposes = ["invoicing"];
  var returned = sealRopa.register({
    id: "sealed", name: "Billing", purposes: callerPurposes,
    legalBasis: "contract", dataCategories: ["name"],
  });
  callerPurposes.length = 0;
  check("clearing the array passed to register does not reach the register",
        sealRopa.get("sealed").purposes.length === 1,
        JSON.stringify(sealRopa.get("sealed").purposes));
  try { returned.name = null; } catch (_e) { /* frozen in strict mode */ }
  check("assigning to a field of the returned record does not reach it either",
        sealRopa.get("sealed").name === "Billing",
        String(sealRopa.get("sealed").name));
  try { sealRopa.get("sealed").purposes.length = 0; } catch (_e) { /* frozen */ }
  check("and the stored list cannot be emptied through what get() answers",
        sealRopa.get("sealed").purposes.length === 1);
  // update() returns a sealed record too, not the merged object it built.
  var updated = sealRopa.update("sealed", { name: "Billing v2" });
  try { updated.purposes.push("marketing"); } catch (_e) { /* frozen */ }
  check("the record update() answers is sealed as well",
        sealRopa.get("sealed").purposes.length === 1 &&
        sealRopa.get("sealed").name === "Billing v2");
  // Only `purposes` and `dataCategories` were copied, so every other field an
  // Article 30 record carries stayed shared with the caller: a recipients list
  // and a third-country transfer entry could be rewritten after the validation
  // had passed, and the next export carried the edit.
  var callerRecipients = ["processor-a"];
  var callerTransfers = [{ country: "US", safeguard: "SCCs" }];
  var nested = sealRopa.register({
    id: "nested", name: "Payroll", purposes: ["payroll"],
    legalBasis: "contract", dataCategories: ["salary"],
    recipients: callerRecipients, thirdCountryTransfers: callerTransfers,
  });
  callerRecipients.push("processor-b");
  callerTransfers[0].safeguard = "none";
  check("a list the register did not name is copied too",
        sealRopa.get("nested").recipients.length === 1,
        JSON.stringify(sealRopa.get("nested").recipients));
  check("and an object nested inside one is copied with it",
        sealRopa.get("nested").thirdCountryTransfers[0].safeguard === "SCCs",
        String(sealRopa.get("nested").thirdCountryTransfers[0].safeguard));
  try { nested.thirdCountryTransfers[0].safeguard = "none"; }
  catch (_e) { /* frozen in strict mode */ }
  check("the nested object the register answers with is frozen as well",
        sealRopa.get("nested").thirdCountryTransfers[0].safeguard === "SCCs",
        String(sealRopa.get("nested").thirdCountryTransfers[0].safeguard));

  // Freezing a record does not seal what its fields point at: Object.freeze
  // cannot stop Map.prototype.set, Date.prototype.setTime or a write through a
  // typed array. The register sealed once at write time and handed the stored
  // record back, so every such field was a shared handle and an activity the
  // validation had refused could be written into the next export through it.
  var liveRopa = b.gdpr.ropa.create({ audit: false, controller: { name: "Acme" } });
  liveRopa.register({
    id: "live", name: "Payments", purposes: ["billing"],
    legalBasis: "contract", dataCategories: ["iban"],
    recipients: new Map([["processor-a", { country: "DE" }]]),
    regions: new Set(["EU"]),
    reviewedAt: new Date(1700000000000),
    evidence: Buffer.from("ab"),
    fingerprint: Uint8Array.from([1, 2]),
  });
  var handed = liveRopa.get("live");
  handed.recipients.set("processor-evil", { country: "XX" });
  handed.recipients.delete("processor-a");
  handed.regions.clear();
  handed.reviewedAt.setTime(0);
  handed.evidence[0] = 0;
  handed.fingerprint[0] = 0xff;
  var after = liveRopa.get("live");
  check("a Map field of a stored activity cannot be rewritten through a read",
    after.recipients.size === 1 && after.recipients.has("processor-a"),
    JSON.stringify(Array.from(after.recipients.keys())));
  check("nor a Set field emptied through one",
    after.regions.size === 1, String(after.regions.size));
  check("nor a Date field moved",
    after.reviewedAt.getTime() === 1700000000000, after.reviewedAt.toISOString());
  check("nor a Buffer field overwritten",
    after.evidence.toString("utf8") === "ab", after.evidence.toString("utf8"));
  check("nor a typed-array field overwritten",
    after.fingerprint[0] === 1, String(after.fingerprint[0]));
  check("and the export carries the register's own values, not the edits",
    JSON.stringify(liveRopa["export"]({ format: "json" })).indexOf("processor-evil") === -1);

  // The export header is sealed the same way: the caller keeps its reference.
  var hdrController = { name: "Acme GmbH", contact: "dpo@acme.example" };
  var hdrRopa = b.gdpr.ropa.create({ audit: false, controller: hdrController });
  hdrController.name = "Not Acme";
  check("rewriting the controller object does not change the next export",
    JSON.stringify(hdrRopa["export"]({ format: "json" })).indexOf("Not Acme") === -1);

  var intact = basisRopa.get("a1");
  check("and the stored activity still carries every required field",
        intact.name !== undefined && intact.purposes !== undefined &&
        intact.dataCategories !== undefined && intact.legalBasis === "contract");
  // The control: an ordinary patch keeping every required field is applied.
  basisRopa.update("a1", { name: "Renamed activity" });
  check("ropa.update still applies a patch that keeps the required fields",
        basisRopa.get("a1").name === "Renamed activity");

  ropa.remove("crm", { reason: "deprecated", actor: "dpo" });
  check("ropa.remove deletes",       ropa.list().length === 0);

  console.log("OK — gdpr.ropa tests");
}

module.exports = { run: run };
if (require.main === module) run();
