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

// The collector returns { actions, unparsed }. Most assertions below only care
// about the map, so this names that half; the tests that are ABOUT the other
// half reach for the whole thing.
function collectActions(dir) { return currency._collectPinnedActions(dir).actions; }

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
  }, collectActions);

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
// happily read the leading run as one, so `@11bd7190...` must never be
// collected as version "11". But not-collecting is only half an answer: a SHA
// states no version of its own, so without the trailing `# vX.Y.Z` there is
// nothing to compare upstream against, and silently dropping the line is the
// same blind spot this whole gate exists to close. It has to be NAMED.
function testAShaIsNeverReadAsAVersion() {
  var out = withFixture({
    "bare.yml": "      - uses: actions/setup-node@11bd71901bbe5b1630ceea73d27597364c9af683\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });

  check("actions-currency: an uncommented SHA pin is not collected as a tag pin",
        !Object.prototype.hasOwnProperty.call(out.actions, "actions/setup-node"),
        JSON.stringify(out.actions));
  check("actions-currency: an uncommented SHA pin is reported as unreadable " +
        "rather than dropped",
        out.unparsed.length === 1 &&
        out.unparsed[0].line === 1 &&
        out.unparsed[0].reason.indexOf("version comment") !== -1,
        JSON.stringify(out.unparsed));
}

// The three shapes Codex named on PR #624, plus the claim that makes chasing
// shapes unnecessary. The pattern had already been widened twice — once for a
// trailing comment, once to stop a SHA reading as a version — and each time the
// next shape along landed back in the same silence. So the assertion here is not
// only "these three parse"; it is that ANYTHING the gate cannot read is
// reported, which is a promise the gate can keep whatever turns up next.
function testEveryUsesIsEitherCheckedOrNamed() {
  var SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";
  var out = withFixture({
    "shapes.yml":
      // Quoted YAML scalars — ordinary YAML, invisible to a pattern that
      // expected the owner immediately after the whitespace.
      '      - uses: "actions/checkout@' + SHA + '"  # v5.0.1\n' +
      "      - uses: 'actions/cache@v4.2.0'\n" +
      // A prerelease tag is a valid version tag; refusing the suffix put it
      // back in the dark.
      "      - uses: owner/prerelease@v2.1.0-rc.1\n" +
      "      - uses: owner/build-meta@v1.2.3+20260823\n" +
      // Legitimately uncheckable: no upstream release exists for either.
      "      - uses: ./.github/actions/local-thing\n" +
      "      - uses: docker://alpine:3.22\n" +
      // Not a pin at all — a branch. Neither immutable nor a version.
      "      - uses: owner/floating@main\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });

  var a = out.actions;
  check("actions-currency: a double-quoted SHA pin is collected",
        (a["actions/checkout"] || {}).sha === SHA, JSON.stringify(a["actions/checkout"]));
  check("actions-currency: a single-quoted tag pin is collected",
        (a["actions/cache"] || {}).version === "4.2.0" &&
        a["actions/cache"].tagPinned === true, JSON.stringify(a["actions/cache"]));
  check("actions-currency: a prerelease tag is a tag pin, not a near-miss",
        (a["owner/prerelease"] || {}).tagPinned === true &&
        a["owner/prerelease"].version === "2.1.0-rc.1",
        JSON.stringify(a["owner/prerelease"]));
  check("actions-currency: a build-metadata tag is a tag pin too",
        (a["owner/build-meta"] || {}).tagPinned === true,
        JSON.stringify(a["owner/build-meta"]));

  check("actions-currency: a local action and a docker ref are skipped as a " +
        "decision, not flagged as unreadable",
        out.unparsed.filter(function (u) {
          return u.value.indexOf("./") === 0 || u.value.indexOf("docker://") === 0;
        }).length === 0, JSON.stringify(out.unparsed));

  var floating = out.unparsed.filter(function (u) { return u.value.indexOf("floating") !== -1; });
  check("actions-currency: a branch ref is NAMED as uncheckable rather than " +
        "quietly counting as clean",
        floating.length === 1 && floating[0].line === 7,
        JSON.stringify(out.unparsed));
}

// Making an unreadable reference fail the run is only right if the set of
// things counted as references is right. Inside a `run: |` the lines are shell,
// not YAML, so a script line beginning `uses:` is prose — and refusing a
// perfectly good workflow over it costs an operator a red gate on a file with
// nothing wrong in it. The over-refusal side of the same change.
function testBlockScalarTextIsNotReadAsAKey() {
  var SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";
  var out = withFixture({
    "blocks.yml":
      "jobs:\n" +
      "  a:\n" +
      "    steps:\n" +
      "      - uses: actions/checkout@" + SHA + "  # v5.0.1\n" +
      "      - run: |\n" +
      "          echo 'this step uses: temporary credentials'\n" +
      "          uses: not a workflow key at all\n" +
      "\n" +
      "          uses: neither is this, after a blank line\n" +
      "      - run: >-\n" +
      "          uses: folded scalars hide it too\n" +
      // Back out to step level — this one IS a key again, and must be seen.
      "      - uses: actions/cache@v4.2.0\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });

  check("actions-currency: script text inside a literal block is not a `uses:` key",
        out.unparsed.length === 0, JSON.stringify(out.unparsed));
  check("actions-currency: a folded block hides it too",
        Object.keys(out.actions).indexOf("folded") === -1,
        Object.keys(out.actions).join(", "));
  check("actions-currency: the real pins on either side of the blocks are " +
        "still collected, so the skip ends where the block does",
        Object.prototype.hasOwnProperty.call(out.actions, "actions/checkout") &&
        Object.prototype.hasOwnProperty.call(out.actions, "actions/cache"),
        Object.keys(out.actions).join(", "));

  // The control. "Zero unparsed" above is only evidence if the very same line
  // WOULD be reported when it is not inside a block — otherwise the assertion
  // passes for any reason at all, including the walker never looking. Same
  // text, no `run: |` above it.
  var control = withFixture({
    "control.yml": "      - uses: not a workflow key at all\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: control — the identical line OUTSIDE a block is " +
        "reported, so the block test is excluding something real",
        control.unparsed.length === 1, JSON.stringify(control.unparsed));

  // Skipping is right for a block BODY and wrong for a `uses:` that opens one.
  // An action reference is a single scalar, so `uses: |` is malformed — and a
  // skip that swallowed it would put the silence straight back, one shape over.
  var opener = withFixture({
    "opener.yml":
      "      - uses: |\n" +
      "          actions/checkout@v5.0.1\n" +
      "      - uses: actions/cache@v4.2.0\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a `uses:` that opens a block scalar is reported, " +
        "not stepped over",
        opener.unparsed.length === 1 && opener.unparsed[0].line === 1,
        JSON.stringify(opener.unparsed));
  check("actions-currency: its body is still treated as body, so the pin " +
        "inside it is not collected as a real reference",
        !Object.prototype.hasOwnProperty.call(opener.actions, "actions/checkout"),
        Object.keys(opener.actions).join(", "));
  check("actions-currency: and the next real key after the block is collected",
        Object.prototype.hasOwnProperty.call(opener.actions, "actions/cache"),
        Object.keys(opener.actions).join(", "));

  // YAML takes the indentation and chomping indicators in EITHER order, so
  // `|2-` and `|-2` are both valid headers. Missing a form does not merely skip
  // a block — it scans that block's shell body as YAML, and a script line
  // reading `uses:` then fails a workflow with nothing wrong in it.
  ["|", "|-", "|+", "|2", "|2-", "|-2", ">", ">-", ">2+", ">+2"].forEach(function (ind) {
    var got = withFixture({
      "ind.yml":
        "      - run: " + ind + "\n" +
        "          uses: this is shell, not a key\n" +
        "      - uses: actions/cache@v4.2.0\n",
    }, function (dir) { return currency._collectPinnedActions(dir); });
    check("actions-currency: `run: " + ind + "` opens a block, so its body is " +
          "not read as YAML",
          got.unparsed.length === 0, ind + " -> " + JSON.stringify(got.unparsed));
    check("actions-currency: `run: " + ind + "` still ends at the next key",
          Object.prototype.hasOwnProperty.call(got.actions, "actions/cache"),
          ind + " -> " + Object.keys(got.actions).join(", "));
  });
}

// Accepting prerelease tags is only useful if they COMPARE correctly. Reading
// `2.1.0-rc.1` as the triple 2.1.0 makes a release candidate that upstream has
// long since superseded compare EQUAL to the final release, so the gate reports
// current — the same "unchecked reads as fine" failure the rest of this file is
// about, one layer down in the comparison rather than the collection.
function testAPrereleaseRanksBelowItsRelease() {
  var cmp = currency._semverCompare;
  var p   = currency._semverParse;

  check("actions-currency: a release candidate is older than its release",
        cmp(p("2.1.0-rc.1"), p("2.1.0")) === -1,
        JSON.stringify([p("2.1.0-rc.1"), p("2.1.0")]));
  check("actions-currency: a release is newer than its own candidate",
        cmp(p("v2.1.0"), p("v2.1.0-rc.1")) === 1, "");
  check("actions-currency: two identical releases still compare equal",
        cmp(p("v2.1.0"), p("2.1.0")) === 0, "");
  check("actions-currency: build metadata carries no precedence, so it is not " +
        "mistaken for a prerelease",
        cmp(p("1.2.3+20260823"), p("1.2.3")) === 0, JSON.stringify(p("1.2.3+20260823")));
  check("actions-currency: the numeric triple still dominates the suffix",
        cmp(p("2.2.0-rc.1"), p("2.1.0")) === 1, "");

  // Collapsing the prerelease to a boolean gets the release comparison right
  // and every comparison BETWEEN prereleases wrong, which is the case a project
  // shipping release candidates actually lives in.
  check("actions-currency: rc.1 is older than rc.2 of the same version",
        cmp(p("2.1.0-rc.1"), p("2.1.0-rc.2")) === -1, "");
  check("actions-currency: prerelease identifiers compare as NUMBERS, so rc.9 " +
        "is older than rc.10 rather than newer by ASCII",
        cmp(p("2.1.0-rc.9"), p("2.1.0-rc.10")) === -1, "");
  check("actions-currency: alpha sorts below beta",
        cmp(p("1.0.0-alpha"), p("1.0.0-beta")) === -1, "");
  check("actions-currency: a numeric identifier ranks below an alphanumeric one",
        cmp(p("1.0.0-1"), p("1.0.0-alpha")) === -1, "");
  check("actions-currency: more identifiers outrank fewer when the shared ones match",
        cmp(p("1.0.0-alpha"), p("1.0.0-alpha.1")) === -1, "");
}

// Widening what the collector ACCEPTS without widening what `--fix` can rewrite
// turns a blind spot into something worse: the run reports the action fixed and
// exits 0 over a file it never changed. The replacement has to reach through
// the closing quote and put it back.
function testTheFixReplacementReachesThroughAQuote() {
  var OLD = "1111111111111111111111111111111111111111";
  var NEW = "2222222222222222222222222222222222222222";
  // The fixer's OWN pattern, not a copy of it — a copy passes happily while the
  // thing it stands in for rots.
  var re2 = currency._fixReplacementRe("actions/checkout");

  [
    ['      - uses: actions/checkout@' + OLD + "  # v5.0.1", "unquoted"],
    ['      - uses: "actions/checkout@' + OLD + '"  # v5.0.1', "double-quoted"],
    ["      - uses: 'actions/checkout@" + OLD + "'  # v5.0.1", "single-quoted"],
  ].forEach(function (pair) {
    var out = pair[0].replace(re2, "$1" + NEW + "$2" + "v6.0.0");
    check("actions-currency: a " + pair[1] + " SHA pin is actually rewritten",
          out.indexOf(NEW) !== -1 && out.indexOf(OLD) === -1, out);
    check("actions-currency: rewriting a " + pair[1] + " pin leaves the YAML " +
          "scalar intact",
          (out.match(/"/g) || []).length === (pair[0].match(/"/g) || []).length &&
          (out.match(/'/g) || []).length === (pair[0].match(/'/g) || []).length,
          out);
  });

  // The pattern is global, so ONE pass over a file rewrites every occurrence in
  // it. That is what makes running it a second time for a second reference to
  // the same action wrong: the second pass finds nothing left to change, and
  // reading that as a failed rewrite turns an ordinary duplicate into a false
  // failure. This repository has such a duplicate — cosign-installer appears
  // twice in one workflow — so the fixer walks distinct FILES, not references.
  var twice = "      - uses: actions/checkout@" + OLD + "  # v5.0.1\n" +
              "      - uses: actions/checkout@" + OLD + "  # v5.0.1\n";
  var once  = twice.replace(currency._fixReplacementRe("actions/checkout"),
                            "$1" + NEW + "$2" + "v6.0.0");
  check("actions-currency: a single pass rewrites BOTH occurrences in a file, " +
        "so a second pass would correctly find nothing and must not be run",
        (once.match(new RegExp(NEW, "g")) || []).length === 2 &&
        once.indexOf(OLD) === -1, once);
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
      collectActions);
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
  testEveryUsesIsEitherCheckedOrNamed();
  testBlockScalarTextIsNotReadAsAKey();
  testAPrereleaseRanksBelowItsRelease();
  testTheFixReplacementReachesThroughAQuote();
  testMixedPinsDoNotDependOnFileOrder();
  testStaleHintsNeverOfferAShaForATagReference();
  console.log("OK — actions-currency pin collection");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
