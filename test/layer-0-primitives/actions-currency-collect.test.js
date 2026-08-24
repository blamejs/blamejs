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

// Wraps step lines in the job structure a real workflow has. It matters: a
// `uses` is an action reference because of WHERE it sits (under `steps`, or as a
// job's own key), not because of how its value looks — so a fixture that is a
// bare list of `- uses:` lines is not testing the thing the collector decides.
// `body` lines are indented to step level by the caller.
function stepsDoc(body) {
  return "jobs:\n  build:\n    steps:\n" + body;
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
    "bare.yml": stepsDoc(
      "      - uses: actions/setup-node@11bd71901bbe5b1630ceea73d27597364c9af683\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });

  check("actions-currency: an uncommented SHA pin is not collected as a tag pin",
        !Object.prototype.hasOwnProperty.call(out.actions, "actions/setup-node"),
        JSON.stringify(out.actions));
  check("actions-currency: an uncommented SHA pin is reported as unreadable " +
        "rather than dropped",
        out.unparsed.length === 1 &&
        out.unparsed[0].line === 4 &&
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
    "shapes.yml": stepsDoc(
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
      "      - uses: owner/floating@main\n"),
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

  // The two paths have to describe a version the same way. A SHA carries none
  // of its own, so its trailing comment is the whole statement — and stopping
  // that comment at the numeric triple makes `# v2.1.0-rc.1` read as the final
  // 2.1.0, which reports a superseded candidate as current.
  var pre = withFixture({
    "pre.yml": stepsDoc("      - uses: owner/rc@" + SHA + "  # v2.1.0-rc.1\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a SHA pin's version comment keeps its prerelease",
        (pre.actions["owner/rc"] || {}).version === "2.1.0-rc.1",
        JSON.stringify(pre.actions["owner/rc"]));

  // Semver identifiers are dot-separated and NON-EMPTY. A loose character class
  // also accepted `rc.` and `build..oops`, and an empty prerelease identifier
  // is not merely odd: the comparison ranks it above a numeric one, so
  // `v1.2.3-rc.` reported current against a real `v1.2.3-rc.1`.
  var emptyIdents = withFixture({
    "emptyident.yml": stepsDoc(
      "      - uses: owner/trailingdot@v1.2.3-rc.\n" +
      "      - uses: owner/doubledot@v1.2.3+build..oops\n" +
      "      - uses: owner/wellformed@v1.2.3-rc.1\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a trailing-dot prerelease is not a version tag",
        !Object.prototype.hasOwnProperty.call(emptyIdents.actions, "owner/trailingdot"),
        JSON.stringify(emptyIdents.actions));
  check("actions-currency: nor is an empty build identifier",
        !Object.prototype.hasOwnProperty.call(emptyIdents.actions, "owner/doubledot"),
        JSON.stringify(emptyIdents.actions));
  check("actions-currency: both are NAMED rather than passed over",
        emptyIdents.unparsed.length === 2, JSON.stringify(emptyIdents.unparsed));
  check("actions-currency: while a well-formed prerelease is still a tag pin",
        (emptyIdents.actions["owner/wellformed"] || {}).version === "1.2.3-rc.1",
        JSON.stringify(emptyIdents.actions));

  // Semver forbids a leading zero on a NUMERIC prerelease identifier, because it
  // makes two spellings of one number and the ordering is then undefined. Build
  // identifiers carry no such rule — they are not ordered at all.
  var leadingZero = withFixture({
    "leadzero.yml": stepsDoc(
      "      - uses: owner/prezero@v1.2.3-rc.007\n" +
      "      - uses: owner/buildzero@v1.2.3+007\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a leading-zero prerelease identifier is refused",
        !Object.prototype.hasOwnProperty.call(leadingZero.actions, "owner/prezero") &&
        leadingZero.unparsed.length === 1,
        JSON.stringify(leadingZero));
  check("actions-currency: while a leading-zero BUILD identifier is fine, since " +
        "build metadata is unordered",
        (leadingZero.actions["owner/buildzero"] || {}).version === "1.2.3+007",
        JSON.stringify(leadingZero.actions));

  var coreZero = withFixture({
    "corezero.yml": stepsDoc(
      "      - uses: owner/corezero@v01.2.3\n" +
      "      - uses: owner/zeroalone@v0.36.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a leading zero in the core version is refused too",
        !Object.prototype.hasOwnProperty.call(coreZero.actions, "owner/corezero") &&
        coreZero.unparsed.length === 1,
        JSON.stringify(coreZero));
  check("actions-currency: while a bare zero component is ordinary",
        (coreZero.actions["owner/zeroalone"] || {}).version === "0.36.0",
        JSON.stringify(coreZero.actions));

  // A pin names all three components. `@v4` is a floating major that upstream
  // repoints whenever it likes, so its currency cannot be established — the same
  // thing a branch ref is, and it gets the same answer.
  var partialTags = withFixture({
    "floating.yml": stepsDoc(
      "      - uses: owner/floatmajor@v4\n" +
      "      - uses: owner/floatminor@v4.1\n" +
      "      - uses: owner/full@v4.1.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a floating major or minor tag is named, not counted " +
        "as a version pin",
        !Object.prototype.hasOwnProperty.call(partialTags.actions, "owner/floatmajor") &&
        !Object.prototype.hasOwnProperty.call(partialTags.actions, "owner/floatminor") &&
        partialTags.unparsed.length === 2,
        JSON.stringify(partialTags));
  check("actions-currency: while a full version tag is a pin",
        (partialTags.actions["owner/full"] || {}).version === "4.1.0",
        JSON.stringify(partialTags.actions));

  // Upstream may publish `v4` as a release. A repair that copied that verbatim
  // would write `# v4`, which the tightened pin grammar refuses on the very next
  // run — a fix that breaks the thing it fixed. The seam between the two
  // grammars is here, and it normalises.
  check("actions-currency: a partial upstream tag is written as a full version",
        currency._fullVersion("v4") === "4.0.0" &&
        currency._fullVersion("4.1") === "4.1.0",
        currency._fullVersion("v4") + " / " + currency._fullVersion("4.1"));
  check("actions-currency: and a suffix rides along unchanged",
        currency._fullVersion("v2-rc.1") === "2.0.0-rc.1" &&
        currency._fullVersion("v1.2.3+b") === "1.2.3+b",
        currency._fullVersion("v2-rc.1") + " / " + currency._fullVersion("v1.2.3+b"));
  check("actions-currency: what --fix writes is what the collector accepts",
        currency._collectPinnedActions !== undefined &&
        /^v/.test("v" + currency._fullVersion("v4")) &&
        withFixture({
          "roundtrip.yml": stepsDoc("      - uses: owner/rt@v" +
                                    currency._fullVersion("v4") + "\n"),
        }, function (dir) { return currency._collectPinnedActions(dir); }).unparsed.length === 0,
        "v" + currency._fullVersion("v4"));

  // A version that does not END at a boundary is malformed, and reading its
  // prefix is worse than refusing it: `# v2.1.0rc.1` would become `2.1.0` and
  // compare EQUAL to the final release, so a pin that really is a release
  // candidate reports current. Refusing to read it says so out loud.
  var mistyped = withFixture({
    "mistyped.yml": stepsDoc(
      "      - uses: owner/mistyped@" + SHA + "  # v2.1.0rc.1\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a version comment that does not end at a boundary " +
        "is refused, not truncated to its prefix",
        !Object.prototype.hasOwnProperty.call(mistyped.actions, "owner/mistyped") &&
        mistyped.unparsed.length === 1 &&
        mistyped.unparsed[0].reason.indexOf("version comment") !== -1,
        JSON.stringify(mistyped));

  // The boundary rejects only what could CONTINUE a version. Demanding
  // whitespace instead would refuse ordinary annotations.
  var annotated = withFixture({
    "annotated.yml": stepsDoc(
      "      - uses: owner/comma@" + SHA + "  # v5.0.1, pinned for compatibility\n" +
      "      - uses: owner/paren@" + SHA + "  # v6.0.1 (temporary)\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: punctuation may follow the version",
        (annotated.actions["owner/comma"] || {}).version === "5.0.1" &&
        (annotated.actions["owner/paren"] || {}).version === "6.0.1" &&
        annotated.unparsed.length === 0,
        JSON.stringify(annotated));

  // CRLF. Lines are split on "\n", so each keeps a trailing "\r" — and a
  // boundary written as `$` alone does not match before it, which silently
  // dropped every version comment in the repository the moment the boundary
  // was added. Its own workflows are CRLF, so this is the common case, not an
  // edge one.
  var crlf = withFixture({
    "crlf.yml":
      "jobs:\r\n  build:\r\n    steps:\r\n" +
      "      - uses: owner/crlf@" + SHA + "  # v5.0.1\r\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  // YAML nesting does not notice comments, so one at column zero between a job
  // and its `steps` must not close them. Popping on it gave the `uses` below
  // the wrong path, and a wrong path means neither collected nor named.
  var interleaved = withFixture({
    "comments.yml":
      "jobs:\n" +
      "  build:\n" +
      "# a column-zero note about the steps below\n" +
      "    steps:\n" +
      "# another one, between the steps key and its first entry\n" +
      "      - uses: owner/aftercomment@" + SHA + "  # v5.0.1\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a comment at a lower indent does not close the " +
        "nesting around it",
        (interleaved.actions["owner/aftercomment"] || {}).version === "5.0.1" &&
        interleaved.unparsed.length === 0,
        JSON.stringify(interleaved));

  // A BOM sits in front of the first key, so it is neither indentation nor part
  // of the name — the first line reads wrong and its `uses` goes missing, which
  // is this gate's original failure in miniature. Windows editors write one
  // without asking.
  var bom = withFixture({
    "bom.yml":
      // Built from its code point, never typed: a literal BOM here would be an
      // invisible byte in the source of the very test that exists to catch one.
      String.fromCharCode(0xFEFF) + "jobs:\n  build:\n    steps:\n" +
      "      - uses: owner/afterbom@" + SHA + "  # v5.0.1\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a leading BOM does not hide the document's keys",
        (bom.actions["owner/afterbom"] || {}).version === "5.0.1" &&
        bom.unparsed.length === 0,
        JSON.stringify(bom));

  check("actions-currency: a version comment on a CRLF line is read",
        (crlf.actions["owner/crlf"] || {}).version === "5.0.1" &&
        crlf.unparsed.length === 0,
        JSON.stringify(crlf));

  // And the fixer refuses it for the same reason: rewriting the `2.1.0` prefix
  // would leave `rc.1` dangling on a version that never existed.
  var oldSha = "1111111111111111111111111111111111111111";
  var newSha = "2222222222222222222222222222222222222222";
  var mistypedFix = ("      - uses: actions/checkout@" + oldSha + "  # v2.1.0rc.1")
    .replace(currency._fixReplacementRe("actions/checkout"), "$1" + newSha + "$2v3.0.0");
  check("actions-currency: --fix leaves a malformed version comment alone " +
        "rather than half-rewriting it",
        mistypedFix.indexOf(oldSha) !== -1 && mistypedFix.indexOf("v2.1.0rc.1") !== -1,
        mistypedFix);

  // A trailing comment may say more than the version, including things with
  // braces in them. The version is the FIRST thing in the comment and reading
  // it must not depend on what follows.
  var chatty = withFixture({
    "chatty.yml": stepsDoc(
      "      - uses: owner/chatty@" + SHA + "  # v5.0.1 pinned for ${{ github.ref }}\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a version comment followed by braces is still read",
        (chatty.actions["owner/chatty"] || {}).version === "5.0.1" &&
        chatty.unparsed.length === 0,
        JSON.stringify({ a: chatty.actions, u: chatty.unparsed }));

  check("actions-currency: a local action and a docker ref are skipped as a " +
        "decision, not flagged as unreadable",
        out.unparsed.filter(function (u) {
          return u.value.indexOf("./") === 0 || u.value.indexOf("docker://") === 0;
        }).length === 0, JSON.stringify(out.unparsed));

  var floating = out.unparsed.filter(function (u) { return u.value.indexOf("floating") !== -1; });
  check("actions-currency: a branch ref is NAMED as uncheckable rather than " +
        "quietly counting as clean",
        floating.length === 1 && floating[0].line === 10,
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
      // Text that WOULD be reported at step level, so the block is doing work.
      "          uses: owner/repo@some-branch\n" +
      "\n" +
      "          uses: owner/other@another-branch\n" +
      "      - run: >-\n" +
      "          uses: owner/folded@yet-another\n" +
      // Back out to step level — this one IS a key again, and must be seen.
      "      - uses: actions/cache@v4.2.0\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });

  check("actions-currency: script text inside a literal block is not a `uses:` key",
        out.unparsed.length === 0, JSON.stringify(out.unparsed));
  check("actions-currency: a folded block hides it too",
        Object.keys(out.actions).indexOf("owner/folded") === -1,
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
    "control.yml": stepsDoc("      - uses: owner/repo@some-branch\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: control — the identical line OUTSIDE a block is " +
        "reported, so the block test is excluding something real",
        control.unparsed.length === 1, JSON.stringify(control.unparsed));

  // `uses` is not reserved in YAML. Under `env` or `with` it is an ordinary
  // field that happens to share the name, and its value may look EXACTLY like a
  // reference — `owner/repo@main` is a perfectly normal string to hand an
  // action. Value shape therefore cannot decide it; only the enclosing key can,
  // which is what the scanner tracks and a pattern had nowhere to put.
  var notRefs = withFixture({
    "notrefs.yml":
      "jobs:\n" +
      "  a:\n" +
      "    steps:\n" +
      "      - uses: actions/checkout@" + SHA + "  # v5.0.1\n" +
      "        env:\n" +
      "          uses: owner/inenv@main\n" +
      "        with:\n" +
      "          uses: owner/inwith@main\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a `uses` under env or with is a field, not an " +
        "action reference, even when its value is shaped like one",
        !Object.prototype.hasOwnProperty.call(notRefs.actions, "owner/inenv") &&
        !Object.prototype.hasOwnProperty.call(notRefs.actions, "owner/inwith") &&
        notRefs.unparsed.length === 0,
        JSON.stringify(notRefs));
  check("actions-currency: and the step's own uses is still collected, so the " +
        "context test excludes the right thing",
        (notRefs.actions["actions/checkout"] || {}).sha === SHA,
        JSON.stringify(notRefs.actions));

  // The enclosing key must survive a collection that OPENS on the next line,
  // or the nested `uses` inherits the step's position and reads as an action.
  var lateOpen = withFixture({
    "lateopen.yml": stepsDoc(
      "      - { name: X, with:\n" +
      "          { uses: owner/latedata@main } }\n" +
      "      - uses: actions/cache@v4.2.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a nested collection opening on the NEXT line keeps " +
        "its enclosing key, so its `uses` stays data",
        !Object.prototype.hasOwnProperty.call(lateOpen.actions, "owner/latedata") &&
        lateOpen.unparsed.length === 0,
        JSON.stringify(lateOpen));
  check("actions-currency: and the step after it is read normally",
        Object.prototype.hasOwnProperty.call(lateOpen.actions, "actions/cache"),
        Object.keys(lateOpen.actions).join(", "));

  // There is exactly ONE `steps` that means steps, and it is three keys from
  // the root. Matrix data an operator happens to name `steps` is not it, and
  // matching only the last key would fail the gate on a sound workflow.
  var matrixSteps = withFixture({
    "matrix.yml":
      "jobs:\n" +
      "  build:\n" +
      "    strategy:\n" +
      "      matrix:\n" +
      "        steps:\n" +
      "          - uses: owner/matrixdata@main\n" +
      "        include:\n" +
      "          - uses: owner/includedata@main\n" +
      "    steps:\n" +
      "      - uses: actions/checkout@" + SHA + "  # v5.0.1\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: matrix data named `steps` is not a steps list",
        !Object.prototype.hasOwnProperty.call(matrixSteps.actions, "owner/matrixdata") &&
        !Object.prototype.hasOwnProperty.call(matrixSteps.actions, "owner/includedata") &&
        matrixSteps.unparsed.length === 0,
        JSON.stringify(matrixSteps));
  check("actions-currency: while the job's real steps list still is",
        (matrixSteps.actions["actions/checkout"] || {}).sha === SHA,
        JSON.stringify(matrixSteps.actions));

  // Flow style allows a delimiter straight after the colon, so `uses:,` and
  // `uses:}` are keys with an EMPTY value. Treating the delimiter as proof it
  // was not a key made a malformed-but-present reference absent again.
  var empties = withFixture({
    "empty.yml": stepsDoc(
      "      - { uses:, name: broken }\n" +
      "      - { uses:}\n" +
      "      - uses: actions/cache@v4.2.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a flow `uses` with an empty value is named, not " +
        "skipped for lacking one",
        empties.unparsed.length === 2, JSON.stringify(empties.unparsed));
  check("actions-currency: and the following step is unaffected",
        Object.prototype.hasOwnProperty.call(empties.actions, "actions/cache"),
        Object.keys(empties.actions).join(", "));

  // YAML 1.2 lets a colon follow a JSON-like QUOTED key directly, but a plain
  // scalar key needs separation after it — so `{ uses:owner/repo@main }` is one
  // scalar and names no key at all. That falls out of the scalar reader rather
  // than needing a rule: it breaks on a colon only when whitespace or a flow
  // delimiter follows, so the colon here is simply part of the value.
  var adjacent = withFixture({
    "adjacent.yml": stepsDoc(
      "      - { uses:owner/plain@main }\n" +
      '      - { "uses":owner/quoted@v1.0.0 }\n'),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a plain scalar with an adjacent colon is not a key, " +
        "so no reference is invented from it",
        !Object.prototype.hasOwnProperty.call(adjacent.actions, "owner/plain") &&
        adjacent.unparsed.length === 0,
        JSON.stringify(adjacent));
  check("actions-currency: while a quoted key may be followed directly, and is " +
        "read",
        (adjacent.actions["owner/quoted"] || {}).version === "1.0.0",
        JSON.stringify(adjacent.actions));

  // A YAML node property — an anchor or an explicit tag — may prefix the value.
  // It is not the scalar, so reading it AS the scalar refuses a valid workflow.
  var props = withFixture({
    "props.yml": stepsDoc(
      "      - uses: &checkout actions/checkout@v5.0.1\n" +
      "      - uses: !!str owner/tagged@v2.0.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an anchor before the value is skipped, not read as it",
        (props.actions["actions/checkout"] || {}).version === "5.0.1",
        JSON.stringify(props));
  check("actions-currency: and so is an explicit tag",
        (props.actions["owner/tagged"] || {}).version === "2.0.0" &&
        props.unparsed.length === 0,
        JSON.stringify(props));

  // A property may prefix the MAPPING as well as a value. Consuming the anchor
  // as an ordinary scalar clears the key position, and the `uses` after it then
  // reads as text — neither checked nor named, which is the silence again.
  var anchoredStep = withFixture({
    "anchorstep.yml": stepsDoc(
      "      - &checkout uses: owner/anchored@v1.2.3\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an anchor prefixing the STEP still leaves its `uses` " +
        "at a key position",
        (anchoredStep.actions["owner/anchored"] || {}).version === "1.2.3" &&
        anchoredStep.unparsed.length === 0,
        JSON.stringify(anchoredStep));

  // A step supplied as an ALIAS has no literal `uses` key to read, and its
  // anchored mapping may be defined anywhere — including outside the two
  // action-reference positions. Scanning finds nothing, so the gate would pass
  // having checked nothing at all. Resolving the alias means holding the whole
  // document; naming it is the answer a scanner can give, and it is the loud one.
  var aliasStep = withFixture({
    "aliasstep.yml":
      "jobs:\n" +
      "  build:\n" +
      "    strategy:\n" +
      "      matrix:\n" +
      "        include:\n" +
      "          - &checkout { uses: actions/checkout@v5.0.1 }\n" +
      "    steps:\n" +
      "      - *checkout\n" +
      "      - uses: actions/cache@v4.2.0\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an aliased step is named, so the gate cannot pass " +
        "having checked nothing",
        aliasStep.unparsed.length === 1 &&
        aliasStep.unparsed[0].reason.indexOf("*checkout") !== -1,
        JSON.stringify(aliasStep.unparsed));
  check("actions-currency: the anchored definition under matrix data is still " +
        "not counted as a reference",
        !Object.prototype.hasOwnProperty.call(aliasStep.actions, "actions/checkout"),
        Object.keys(aliasStep.actions).join(", "));
  check("actions-currency: and the ordinary step beside it is read",
        Object.prototype.hasOwnProperty.call(aliasStep.actions, "actions/cache"),
        Object.keys(aliasStep.actions).join(", "));

  // A JOB may be an alias too, and that one arrives as the job key's VALUE
  // rather than at a key position — a different branch entirely, so it needs
  // naming separately or the whole job goes unchecked.
  var aliasJob = withFixture({
    "aliasjob.yml":
      "jobs:\n" +
      "  setup:\n" +
      "    strategy:\n" +
      "      matrix:\n" +
      "        include:\n" +
      "          - &call { uses: owner/repo/.github/workflows/build.yml@v1.2.3 }\n" +
      "  call: *call\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a job supplied as an alias is named, not skipped",
        aliasJob.unparsed.length === 1 &&
        aliasJob.unparsed[0].reason.indexOf("*call") !== -1,
        JSON.stringify(aliasJob));

  // The explicit-key form: `? uses` on one line, `: value` on the next. Reading
  // `?` as an ordinary scalar clears the key position and the reference is then
  // neither checked nor named — silence, the one outcome this must not have.
  var explicitKey = withFixture({
    "explicit.yml": stepsDoc(
      "      - ? uses\n" +
      "        : owner/explicit@v3.1.0\n" +
      // The `:` may equally follow on the SAME line.
      "      - ? uses : owner/sameline@v3.2.0\n" +
      "      - uses: actions/cache@v4.2.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an explicit mapping key is read, not stepped over",
        (explicitKey.actions["owner/explicit"] || {}).version === "3.1.0" &&
        explicitKey.unparsed.length === 0,
        JSON.stringify(explicitKey));
  check("actions-currency: including the same-line form of it",
        (explicitKey.actions["owner/sameline"] || {}).version === "3.2.0",
        JSON.stringify(explicitKey.actions));
  check("actions-currency: and the ordinary step after it is unaffected",
        Object.prototype.hasOwnProperty.call(explicitKey.actions, "actions/cache"),
        Object.keys(explicitKey.actions).join(", "));

  // An explicit key nests like any other. `- ? with` / `: { uses: ... }` puts
  // that data under `with`, not at the step's own position.
  var explicitNest = withFixture({
    "explicitnest.yml": stepsDoc(
      "      - ? with\n" +
      "        : { uses: owner/explicitdata@main }\n" +
      "      - uses: actions/cache@v4.2.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an explicit key other than `uses` still supplies the " +
        "enclosing path for what nests under it",
        !Object.prototype.hasOwnProperty.call(explicitNest.actions, "owner/explicitdata") &&
        explicitNest.unparsed.length === 0,
        JSON.stringify(explicitNest));

  // And one whose `:` never arrives is a malformed reference, exactly as an
  // ordinary `uses:` with no value is. Leaving it pending forever would put the
  // silence back in the shape that had just been closed.
  var explicitNoValue = withFixture({
    "explicitnovalue.yml": stepsDoc(
      "      - ? uses\n" +
      "        name: no value ever arrives\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an explicit `uses` key with no value is named",
        explicitNoValue.unparsed.length === 1,
        JSON.stringify(explicitNoValue));

  var explicitAtEof = withFixture({
    "expliciteof.yml": stepsDoc("      - ? uses\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: and one still waiting at end of file is named too",
        explicitAtEof.unparsed.length === 1,
        JSON.stringify(explicitAtEof));

  // Node properties may prefix any node, so all FOUR places that read one skip
  // them: an ordinary value, a mapping, an explicit key, and an explicit key's
  // value. Written inline the skip reached two of the four.
  var explicitProps = withFixture({
    "explicitprops.yml": stepsDoc(
      "      - ? &key uses\n" +
      "        : &val owner/bothprops@v6.0.0\n" +
      "      - ? uses\n" +
      "        : !!str owner/tagvalue@v7.0.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an anchor on the explicit KEY does not become the " +
        "key name",
        (explicitProps.actions["owner/bothprops"] || {}).version === "6.0.0",
        JSON.stringify(explicitProps));
  check("actions-currency: and a property on its VALUE does not become the " +
        "reference",
        (explicitProps.actions["owner/tagvalue"] || {}).version === "7.0.0" &&
        explicitProps.unparsed.length === 0,
        JSON.stringify(explicitProps));

  // A workflow parser resolves double-quote escapes before it ever sees a
  // reference, so handing back the raw text refuses valid YAML.
  var escaped = withFixture({
    "escaped.yml": stepsDoc(
      '      - uses: "actions\\u002fcheckout@v5.0.1"\n' +
      '      - "uses": "owner\\x2fhex@v2.0.0"\n' +
      "      - uses: 'owner/single\\u002fnot-an-escape@v3.0.0'\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a \\u escape in a double-quoted reference is decoded",
        (escaped.actions["actions/checkout"] || {}).version === "5.0.1",
        JSON.stringify(escaped));
  check("actions-currency: and a \\x escape, including in the key",
        (escaped.actions["owner/hex"] || {}).version === "2.0.0",
        JSON.stringify(escaped.actions));
  check("actions-currency: a SINGLE-quoted scalar takes no escapes, so the " +
        "backslash stays literal and the reference is named, not invented",
        !Object.prototype.hasOwnProperty.call(escaped.actions, "owner/single/not-an-escape") &&
        escaped.unparsed.length === 1,
        JSON.stringify(escaped));

  // A SHA states no version of its own, so its trailing comment is the whole
  // claim — and in a flow mapping the rest of the mapping sits between the two,
  // sometimes onto another line. Reading the comment from the text after the
  // VALUE could not see past those fields; the scanner knows where the comment
  // began, so it hands it over and the occurrence waits for its mapping to
  // close.
  var trailing = withFixture({
    "trailing.yml": stepsDoc(
      "      - { uses: owner/sameline@" + SHA + ", name: A }  # v1.2.3\n" +
      "      - { uses: owner/nextline@" + SHA + ",\n" +
      "          name: B }  # v4.5.6\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a version comment after later flow fields is found",
        (trailing.actions["owner/sameline"] || {}).version === "1.2.3",
        JSON.stringify({ a: trailing.actions, u: trailing.unparsed }));
  check("actions-currency: and one on the line where the mapping CLOSES",
        (trailing.actions["owner/nextline"] || {}).version === "4.5.6" &&
        trailing.unparsed.length === 0,
        JSON.stringify({ a: trailing.actions, u: trailing.unparsed }));

  // A pin's own line may carry the comment while its mapping closes much later,
  // and a collection may hold more than one pin. Taking the closing line's
  // comment for all of them loses the first version and gives every pin the
  // last, so each occurrence keeps its own and only falls back.
  var perLine = withFixture({
    "perline.yml":
      "jobs:\n" +
      "  build:\n" +
      "    steps: [\n" +
      "      { uses: owner/first@" + SHA + " },  # v1.0.0\n" +
      "      { uses: owner/second@" + SHA + " },  # v2.0.0\n" +
      "    ]\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  // A pin's version may sit on the line its OWN mapping closes, several lines
  // before the surrounding sequence does. Taking only the outer closing line's
  // comment threw it away and reported the pin as having none.
  var innerClose = withFixture({
    "innerclose.yml":
      "jobs:\n" +
      "  build:\n" +
      "    steps: [\n" +
      "      { uses: owner/innerclose@" + SHA + "\n" +
      "      },  # v3.4.5\n" +
      "    ]\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a version comment on the line the pin's OWN mapping " +
        "closes is kept",
        (innerClose.actions["owner/innerclose"] || {}).version === "3.4.5" &&
        innerClose.unparsed.length === 0,
        JSON.stringify(innerClose));

  // And it belongs to that pin ALONE. A shared "most recent comment" gives every
  // pending pin the LAST version seen, so two mappings closing `# v1.0.0` and
  // `# v2.0.0` would both read as 2.0.0 — a wrong version is worse than none,
  // because `--fix` would act on it.
  var twoInner = withFixture({
    "twoinner.yml":
      "jobs:\n" +
      "  build:\n" +
      "    steps: [\n" +
      "      { uses: owner/firstinner@" + SHA + "\n" +
      "      },  # v1.0.0\n" +
      "      { uses: owner/secondinner@" + SHA + "\n" +
      "      },  # v2.0.0\n" +
      "    ]\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  // The depth belongs to the OCCURRENCE, not to wherever the line ends up. A
  // line that opens a nested collection after `uses` finishes deeper than the
  // pin sits, so the `}` closing that nested collection would look like the
  // pin's own mapping closing — and the pin would take that line's comment
  // (none) while the real version further down went unseen.
  var opensAfter = withFixture({
    "opensafter.yml":
      "jobs:\n" +
      "  build:\n" +
      "    steps: [\n" +
      "      { uses: owner/opensafter@" + SHA + ", with: {\n" +
      "          a: 1 },\n" +
      "      },  # v7.8.9\n" +
      "    ]\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a nested collection opened AFTER the pin does not " +
        "steal its closing comment",
        (opensAfter.actions["owner/opensafter"] || {}).version === "7.8.9" &&
        opensAfter.unparsed.length === 0,
        JSON.stringify(opensAfter));

  check("actions-currency: each inner mapping keeps the version from its own " +
        "closing line, not the last one in the collection",
        JSON.stringify([(twoInner.actions["owner/firstinner"] || {}).version,
                        (twoInner.actions["owner/secondinner"] || {}).version]) ===
        JSON.stringify(["1.0.0", "2.0.0"]),
        JSON.stringify({ a: twoInner.actions, u: twoInner.unparsed }));

  check("actions-currency: each pin in a multi-line collection keeps the " +
        "version from its OWN line",
        JSON.stringify([(perLine.actions["owner/first"] || {}).version,
                        (perLine.actions["owner/second"] || {}).version]) ===
        JSON.stringify(["1.0.0", "2.0.0"]),
        JSON.stringify({ a: perLine.actions, u: perLine.unparsed }));

  // The other side of that line: `owner/repo` with no ref at all IS an action
  // reference, and a floating one is exactly the pin whose currency nothing can
  // establish. Passing over it by shape would be the original bug again.
  var unpinned = withFixture({
    "unpinned.yml": stepsDoc("      - uses: actions/checkout\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: an entirely unpinned action reference is reported",
        unpinned.unparsed.length === 1 &&
        unpinned.unparsed[0].reason.indexOf("not a pinned action reference") !== -1,
        JSON.stringify(unpinned.unparsed));

  // Anything sitting in an action-reference position IS one, whatever it looks
  // like. Filtering by shape here would drop an alias or a typo in silence —
  // the exact failure the unparsed list exists to end — and it was only ever
  // needed while POSITION was unknown and shape was the only signal available.
  var odd = withFixture({
    "odd.yml": stepsDoc(
      "      - uses: *checkout-anchor\n" +
      "      - uses: not-even-close\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a YAML alias in a uses position is named, not dropped",
        odd.unparsed.filter(function (u) {
          return u.value.indexOf("*checkout-anchor") !== -1;
        }).length === 1, JSON.stringify(odd.unparsed));
  check("actions-currency: and so is a value that resembles no reference at all",
        odd.unparsed.length === 2 && Object.keys(odd.actions).length === 0,
        JSON.stringify(odd));

  // Whether a `uses` token is a KEY is a question about YAML structure, and no
  // pattern answers it. Ten review rounds each produced a shape the previous
  // pattern could not see or saw wrongly, in BOTH directions: real references
  // missed, and quoted script text read as a reference that does not exist.
  //
  // The collector scans instead — walking characters and tracking quoting,
  // comments and flow depth — so all of it falls out at once. Every shape from
  // those rounds is asserted here, both the ones that must be FOUND and the
  // ones that must be TEXT.
  var scanned = withFixture({
    "scan.yml":
      "jobs:\n" +
      "  a:\n" +
      "    steps:\n" +
      // Found: block, flow-first-key, flow-late-key, quoted key, quoted value.
      "      - uses: actions/checkout@" + SHA + "  # v5.0.1\n" +
      "      - { uses: owner/flowfirst@v1.0.0 }\n" +
      "      - { name: X, with: { n: 1 }, uses: owner/flowlate@v2.0.0 }\n" +
      '      - { "uses": owner/quotedkey@v3.0.0 }\n' +
      "      - uses: 'owner/quotedval@v4.0.0'\n" +
      // Text: inside quotes, inside a comment, inside a block-scalar body.
      '      - run: echo "a, uses: owner/inquotes@main"\n' +
      '      - { run: "echo a, uses: owner/inflowquotes@main" }\n' +
      "      - name: N  # uses: owner/incomment@main\n" +
      "      - run: |\n" +
      "          uses: owner/inblock@main\n" +
      "          { uses: owner/inblockflow@main }\n",
  }, function (dir) { return currency._collectPinnedActions(dir); });

  var got = Object.keys(scanned.actions).sort().join(",");
  check("actions-currency: every real key is found — block, flow first, flow " +
        "late, quoted key, quoted value",
        got === "actions/checkout,owner/flowfirst,owner/flowlate," +
                "owner/quotedkey,owner/quotedval",
        got + "  unparsed=" + JSON.stringify(scanned.unparsed));
  check("actions-currency: and nothing inside quotes, a comment or a block " +
        "body is mistaken for one",
        got.indexOf("inquotes") === -1 && got.indexOf("inflowquotes") === -1 &&
        got.indexOf("incomment") === -1 && got.indexOf("inblock") === -1,
        got);
  check("actions-currency: so a workflow of ordinary shapes produces no " +
        "unreadable references at all",
        scanned.unparsed.length === 0, JSON.stringify(scanned.unparsed));

  // The values must survive the scan intact — a flow scalar stopping at the
  // comma rather than swallowing it, a quoted one losing its quotes.
  check("actions-currency: a flow-mapping value ends at the comma",
        (scanned.actions["owner/flowlate"] || {}).version === "2.0.0",
        JSON.stringify(scanned.actions["owner/flowlate"]));
  check("actions-currency: a quoted value is unwrapped",
        (scanned.actions["owner/quotedval"] || {}).version === "4.0.0",
        JSON.stringify(scanned.actions["owner/quotedval"]));

  // A flow collection may span lines. Structural state carried between them is
  // the thing a pattern has nowhere to put; resetting it per line reads the
  // continuation as block context, so the comma closing the value is swallowed
  // into the ref and a valid entry fails.
  var multiline = withFixture({
    "multi.yml": stepsDoc(
      "      - { name: Checkout,\n" +
      "          uses: owner/spanning@v1.2.3,\n" +
      "          id: c }\n" +
      "      - uses: actions/cache@v4.2.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a flow mapping spanning lines is read, with the " +
        "value ending at the comma rather than absorbing it",
        (multiline.actions["owner/spanning"] || {}).version === "1.2.3" &&
        multiline.unparsed.length === 0,
        JSON.stringify({ a: multiline.actions, u: multiline.unparsed }));
  check("actions-currency: and block context resumes after the mapping closes",
        Object.prototype.hasOwnProperty.call(multiline.actions, "actions/cache"),
        Object.keys(multiline.actions).join(", "));

  check("actions-currency: the scope is stated rather than inferred, so a " +
        "reader is told what was looked at",
        typeof currency.SCOPE_NOTE === "string" &&
        currency.SCOPE_NOTE.indexOf("scanned") !== -1,
        String(currency.SCOPE_NOTE));

  // Skipping is right for a block BODY and wrong for a `uses:` that opens one.
  // An action reference is a single scalar, so `uses: |` is malformed — and a
  // skip that swallowed it would put the silence straight back, one shape over.
  var opener = withFixture({
    "opener.yml": stepsDoc(
      "      - uses: |\n" +
      "          actions/checkout@v5.0.1\n" +
      "      - uses: actions/cache@v4.2.0\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a `uses:` that opens a block scalar is reported, " +
        "not stepped over",
        opener.unparsed.length === 1 && opener.unparsed[0].line === 4,
        JSON.stringify(opener.unparsed));
  check("actions-currency: its body is still treated as body, so the pin " +
        "inside it is not collected as a real reference",
        !Object.prototype.hasOwnProperty.call(opener.actions, "actions/checkout"),
        Object.keys(opener.actions).join(", "));
  check("actions-currency: and the next real key after the block is collected",
        Object.prototype.hasOwnProperty.call(opener.actions, "actions/cache"),
        Object.keys(opener.actions).join(", "));

  // The position decision travels with the block-scalar case too. A data field
  // named `uses` under `with` may hold a block scalar quite legitimately.
  var dataBlock = withFixture({
    "datablock.yml": stepsDoc(
      "      - uses: actions/checkout@" + SHA + "  # v5.0.1\n" +
      "        with:\n" +
      "          uses: |\n" +
      "            some multi-line value\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  check("actions-currency: a data `uses` opening a block scalar is not " +
        "reported — position decides here as everywhere else",
        dataBlock.unparsed.length === 0, JSON.stringify(dataBlock.unparsed));
  check("actions-currency: and the step's real pin is untouched by it",
        (dataBlock.actions["actions/checkout"] || {}).sha === SHA,
        JSON.stringify(dataBlock.actions));

  // YAML takes the indentation and chomping indicators in EITHER order, so
  // `|2-` and `|-2` are both valid headers. Missing a form does not merely skip
  // a block — it scans that block's shell body as YAML, and a script line
  // reading `uses:` then fails a workflow with nothing wrong in it.
  ["|", "|-", "|+", "|2", "|2-", "|-2", ">", ">-", ">2+", ">+2"].forEach(function (ind) {
    var got = withFixture({
      "ind.yml": stepsDoc(
        "      - run: " + ind + "\n" +
        "          uses: owner/repo@some-branch\n" +
        "      - uses: actions/cache@v4.2.0\n"),
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

  // A prerelease identifier has no upper bound. Past Number.MAX_SAFE_INTEGER two
  // different ones round to the same double, so comparing them as numbers
  // reports a stale pin as current — the failure this comparison exists to
  // catch, reappearing at the far end of the range.
  check("actions-currency: numeric identifiers beyond the safe-integer range " +
        "still order correctly",
        cmp(p("1.0.0-9007199254740992"), p("1.0.0-9007199254740993")) === -1,
        JSON.stringify([p("1.0.0-9007199254740992").pre,
                        p("1.0.0-9007199254740993").pre]));
  check("actions-currency: a longer digit run is the larger identifier",
        cmp(p("1.0.0-9"), p("1.0.0-10")) === -1, "");
  check("actions-currency: and leading zeros do not change the value",
        cmp(p("1.0.0-007"), p("1.0.0-7")) === 0, "");

  // Build metadata is explicitly UNORDERED in semver, so two builds of one
  // version rank equally and ordering them would invent a rule the spec
  // forbids. They can still name different code, which is why the gate says so
  // in its report rather than pretending one is newer.
  check("actions-currency: two builds of one version rank equally, as semver " +
        "requires",
        cmp(p("1.2.3+20260823"), p("1.2.3+20260824")) === 0, "");
  check("actions-currency: and build metadata never outranks the plain version",
        cmp(p("1.2.3+build"), p("1.2.3")) === 0, "");

  // The core components are unbounded too, and past the safe-integer range two
  // different majors round to the same double — the same precision trap the
  // prerelease identifiers had, one field over.
  check("actions-currency: core components beyond the safe-integer range order " +
        "correctly",
        cmp(p("9007199254740992.0.0"), p("9007199254740993.0.0")) === -1,
        JSON.stringify([p("9007199254740992.0.0").coreStr,
                        p("9007199254740993.0.0").coreStr]));
  check("actions-currency: and an ordinary comparison is unchanged by it",
        cmp(p("1.2.3"), p("1.10.0")) === -1 && cmp(p("2.0.0"), p("1.99.99")) === 1,
        "");
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

  // A prerelease comment must be replaced WHOLE. The collector reads
  // `# v2.1.0-rc.1` as that entire version, so a fixer stopping at the numeric
  // triple leaves `-rc.1` glued to the new tag and exits 0 having written a
  // version that never existed. Collected and rewritable have to be the same
  // set, which is why the grammar is defined once and shared.
  var preLine = "      - uses: actions/checkout@" + OLD + "  # v2.1.0-rc.1";
  var preOut  = preLine.replace(currency._fixReplacementRe("actions/checkout"),
                                "$1" + NEW + "$2" + "v2.2.0");
  check("actions-currency: --fix replaces a prerelease version comment whole, " +
        "leaving no suffix behind",
        preOut.indexOf("v2.2.0") !== -1 && preOut.indexOf("rc.1") === -1,
        preOut);

  var buildLine = "      - uses: actions/checkout@" + OLD + "  # v1.2.3+20260823";
  var buildOut  = buildLine.replace(currency._fixReplacementRe("actions/checkout"),
                                    "$1" + NEW + "$2" + "v1.3.0");
  check("actions-currency: and a build-metadata comment likewise",
        buildOut.indexOf("v1.3.0") !== -1 && buildOut.indexOf("20260823") === -1,
        buildOut);

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

  // `--fix` verifies by RE-COLLECTING with this same scanner, rather than by
  // asking whether the file changed (too weak — one occurrence matching is
  // enough) or by matching raw text (too strong — `owner/repo@<sha>` in a
  // comment or a matrix value is not a pin). The property it relies on is
  // asserted here: the collector reports each reference's own SHA, so a file
  // that is only partly rewritten still shows the stale one.
  var partly = withFixture({
    "partly.yml": stepsDoc(
      "      - uses: actions/checkout@" + NEW + "  # v6.0.0\n" +
      '      - uses: "actions/checkout@' + OLD + '"  # v5.0.1\n' +
      "      - run: echo 'actions/checkout@" + OLD + " is only text here'\n"),
  }, function (dir) { return currency._collectPinnedActions(dir); });
  var shas = ((partly.actions["actions/checkout"] || {}).refs || [])
    .map(function (r) { return r.sha; });
  check("actions-currency: the collector reports each reference's own SHA, so " +
        "a half-rewritten file still shows the stale one",
        shas.length === 2 && shas.indexOf(NEW) !== -1 && shas.indexOf(OLD) !== -1,
        JSON.stringify(shas));
  check("actions-currency: and the same text inside a script is not counted, " +
        "so a finished rewrite is not reported as failed",
        shas.length === 2, JSON.stringify(partly.actions));
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
  var shaLine = stepsDoc("      - uses: actions/checkout@" + SHA + "  # v5.0.1\n");
  var tagLine = "jobs:\n  a:\n" +
                "    uses: actions/checkout/.github/workflows/reusable.yml@v5.0.1  # tag\n";

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
