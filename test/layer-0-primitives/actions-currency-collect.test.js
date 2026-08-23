// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/check-actions-currency.js — which pins the currency gate can see.
 *
 * The gate reported "N SHA-pinned action(s) inspected" and was telling the
 * truth about what it had looked at, which is exactly why the gap was quiet: a
 * `uses:` pinned to anything other than a 40-hex SHA matched no pattern, was
 * collected by nothing, and appeared in the run as neither current nor stale.
 * It was absent, and absence read as clean.
 *
 * The pin that fell through is the one least able to look after itself. A SHA
 * is immutable, so a stale SHA pin becomes visible the moment upstream cuts a
 * release; a tag can be repointed at new code with no diff here at all. This
 * repository carries exactly one tag pin and does so by necessity — the SLSA
 * generator refuses to run from a commit SHA — so the single exception to the
 * pinning discipline was also the single thing the gate never checked.
 *
 * These run against a FIXTURE directory rather than .github/workflows. A gate
 * asserted against the files it ships beside can only ever confirm today's
 * contents; what needs pinning down is that a whole kind of pin comes back.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

var currency = require("../../scripts/check-actions-currency.js");

function withFixture(files, fn) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-actions-currency-"));
  try {
    Object.keys(files).forEach(function (name) {
      fs.writeFileSync(path.join(dir, name), files[name], "utf8");
    });
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testTagPinnedReusableWorkflowIsCollected() {
  var SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";
  var collected = withFixture({
    "pins.yml":
      "jobs:\n" +
      "  a:\n" +
      "    steps:\n" +
      "      - uses: actions/checkout@" + SHA + "  # v5.0.1\n" +
      "  b:\n" +
      // The shape that was invisible: a reusable workflow at a subpath, pinned
      // to a tag, with a trailing comment explaining why it is not SHA-pinned.
      // The comment matters — anchoring the version at end-of-line matched
      // nothing here, which is the same blind spot one level down.
      "    uses: slsa-framework/slsa-github-generator/.github/workflows/gen.yml@v2.1.0" +
      "  # zizmor: ignore[unpinned-uses] allow:not-sha-pinned\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });

  check("actions-currency: the SHA-pinned action is still collected",
        Object.prototype.hasOwnProperty.call(collected, "actions/checkout"),
        Object.keys(collected).join(", "));
  check("actions-currency: a tag-pinned reusable workflow is collected at all",
        Object.prototype.hasOwnProperty.call(collected, "slsa-framework/slsa-github-generator"),
        Object.keys(collected).join(", "));

  var tag = collected["slsa-framework/slsa-github-generator"] || {};
  var sha = collected["actions/checkout"] || {};
  check("actions-currency: the tag pin carries its version",
        tag.version === "2.1.0", String(tag.version));
  check("actions-currency: the tag pin is marked as one, so --fix can leave it " +
        "alone and the report can say why",
        tag.tagPinned === true && tag.sha === null,
        "tagPinned=" + tag.tagPinned + " sha=" + String(tag.sha));
  check("actions-currency: a SHA pin is NOT marked as a tag pin",
        sha.tagPinned !== true && sha.sha === SHA,
        "tagPinned=" + sha.tagPinned);
  check("actions-currency: the tag pin records where it was found",
        (tag.refs || []).length === 1 && tag.refs[0].file.indexOf("pins.yml") !== -1 &&
        tag.refs[0].line === 6,
        JSON.stringify(tag.refs));
}

// A 40-hex SHA begins with digits often enough that a version pattern will
// happily read the leading run as one. Only requiring the number to END where
// it does keeps `@11bd7190...` from being collected as version "11".
function testAShaIsNeverReadAsAVersion() {
  var collected = withFixture({
    // Deliberately missing the `# vX.Y.Z` comment, so the SHA pattern does not
    // match either — this line must produce NOTHING rather than a bogus version.
    "bare.yml": "      - uses: actions/setup-node@11bd71901bbe5b1630ceea73d27597364c9af683\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });

  check("actions-currency: an uncommented SHA pin is not collected as a tag pin",
        !Object.prototype.hasOwnProperty.call(collected, "actions/setup-node"),
        JSON.stringify(collected));
}

// An action can be pinned by SHA in one workflow and by tag in another, and
// reading the entry's pin type off whichever line the walk reached first made
// both the report and `--fix` depend on file iteration order: seen tag-first
// the action was dropped from `--fix` entirely and its SHA references never
// bumped; seen SHA-first its tag reference vanished from the report. The two
// orders are asserted to produce the same answer, which is the only way a
// first-one-wins bug shows up as a failure rather than as a coin toss.
function testMixedPinsDoNotDependOnFileOrder() {
  var SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";
  var shaLine = "      - uses: actions/checkout@" + SHA + "  # v5.0.1\n";
  var tagLine = "    uses: actions/checkout/.github/workflows/reusable.yml@v5.0.1  # tag\n";

  function collect(first, second) {
    return withFixture({ "a-first.yml": first, "b-second.yml": second },
      function (dir) { return currency._collectPinnedActions(dir); });
  }

  var shaFirst = collect(shaLine, tagLine)["actions/checkout"];
  var tagFirst = collect(tagLine, shaLine)["actions/checkout"];

  check("actions-currency: a mixed-pin action reports the same regardless of " +
        "which workflow is read first",
        shaFirst.tagPinned === tagFirst.tagPinned &&
        shaFirst.mixedPins === tagFirst.mixedPins &&
        shaFirst.sha === tagFirst.sha,
        "shaFirst=" + JSON.stringify({ t: shaFirst.tagPinned, m: shaFirst.mixedPins, s: shaFirst.sha }) +
        " tagFirst=" + JSON.stringify({ t: tagFirst.tagPinned, m: tagFirst.mixedPins, s: tagFirst.sha }));
  check("actions-currency: a mixed-pin action is not marked wholly tag-pinned, " +
        "so its SHA references stay fixable",
        shaFirst.tagPinned === false && shaFirst.mixedPins === true,
        "tagPinned=" + shaFirst.tagPinned + " mixedPins=" + shaFirst.mixedPins);
  check("actions-currency: a mixed-pin action keeps a SHA to compare against",
        shaFirst.sha === SHA, String(shaFirst.sha));
  check("actions-currency: every reference records its own pin type",
        shaFirst.refs.length === 2 &&
        shaFirst.refs.filter(function (r) { return r.tagPinned; }).length === 1,
        JSON.stringify(shaFirst.refs.map(function (r) { return r.tagPinned; })));
}

// `--fix` and the printed advice answer the same question and have to answer it
// the same way. `--fix` decides per reference and skips a mixed action entirely;
// the report decided per ACTION, so a mixed one printed one SHA and then listed
// every place it was "used", the tag reference among them. Pasting the offered
// line there is the failure: the SLSA generator will not run from a SHA, so the
// advice breaks the one workflow that most needs to keep its tag, and the gate
// that printed it exits 0 either way.
function testStaleHintsNeverOfferAShaForATagReference() {
  var SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";
  function hintsFor(refs, extra) {
    var r = {
      action: "slsa-framework/slsa-github-generator", status: "stale",
      pinned: "2.1.0", latest: "2.2.0", latestSha: SHA, refs: refs,
    };
    Object.keys(extra || {}).forEach(function (k) { r[k] = extra[k]; });
    return currency._staleHints(r);
  }
  function pinLines(lines) {
    return lines.filter(function (l) { return l.indexOf("pin:") !== -1; });
  }

  var tagOnly = hintsFor([{ file: "a.yml", line: 3, tagPinned: true }],
                         { tagPinned: true });
  check("actions-currency: a tag-only action is never handed a SHA to paste",
        pinLines(tagOnly).length === 0, JSON.stringify(tagOnly));
  check("actions-currency: a tag-only action still says where it is used",
        tagOnly.length === 1 && tagOnly[0].indexOf("a.yml:3") !== -1,
        JSON.stringify(tagOnly));

  var mixed = hintsFor([
    { file: "sha.yml", line: 7,  tagPinned: false },
    { file: "tag.yml", line: 11, tagPinned: true  },
  ], { tagPinned: false, mixedPins: true });

  // The pin line is still worth printing — one of the two references CAN take
  // it. What must not happen is the tag reference sitting under it unmarked.
  check("actions-currency: a mixed action still gets the pin line its SHA " +
        "reference can use",
        pinLines(mixed).length === 1 && pinLines(mixed)[0].indexOf(SHA) !== -1,
        JSON.stringify(mixed));

  var tagLine = mixed.filter(function (l) { return l.indexOf("tag.yml:11") !== -1; })[0];
  var shaLine = mixed.filter(function (l) { return l.indexOf("sha.yml:7") !== -1; })[0];
  check("actions-currency: the tag reference under a mixed action is marked as " +
        "one, so the SHA above it is not read as applying to it",
        tagLine !== undefined && tagLine.indexOf("tag pin") !== -1, String(tagLine));
  check("actions-currency: the SHA reference carries no such warning",
        shaLine !== undefined && shaLine.indexOf("tag pin") === -1, String(shaLine));

  var shaOnly = hintsFor([{ file: "s.yml", line: 2, tagPinned: false }]);
  check("actions-currency: an ordinary SHA-pinned action is unchanged — pin " +
        "line plus a bare file:line",
        pinLines(shaOnly).length === 1 && shaOnly.length === 2 &&
        shaOnly[1].indexOf("tag pin") === -1,
        JSON.stringify(shaOnly));
}

async function run() {
  testTagPinnedReusableWorkflowIsCollected();
  testAShaIsNeverReadAsAVersion();
  testMixedPinsDoNotDependOnFileOrder();
  testStaleHintsNeverOfferAShaForATagReference();
  console.log("OK — actions-currency pin collection");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
