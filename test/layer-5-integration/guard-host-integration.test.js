// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-host-integration — adaptive table-driven integration harness
 * for the guard-* family.
 *
 * Discovers every guard primitive registered in `b.guardAll.allGuards()`
 * (registered content guards + standalone non-content guards) and
 * exercises the gate decisions through the appropriate host wiring per
 * `KIND`:
 *
 *   kind="content"  — ctx.bytes consumer. Tests:
 *                     1. direct gate (benign → serve; hostile → refuse)
 *                     2. b.guardAll.gate contentTypeMux dispatch
 *                     3. b.staticServe.create({ contentSafety }) GET round-trip
 *                     4. b.fileUpload chunk → finalize round-trip
 *                     5. exceptFor opt-out path on b.guardAll
 *                     6. audit-chain verification (guard row + host row)
 *
 *   kind="entries"  — ctx.entries consumer (b.guardArchive). Tests:
 *                     1. direct gate (benign entries → serve; hostile → refuse)
 *                     2. registered in b.guardAll's content-type dispatch but
 *                        ctx.bytes path returns refuse with no-entry-list
 *
 *   kind="filename" — ctx.filename consumer (b.guardFilename). Tests:
 *                     1. direct gate (benign name → serve; hostile → refuse)
 *                     2. NOT in b.guardAll content-type dispatch (standalone)
 *
 * Adding a new guard:
 *   - export NAME, KIND ("content" | "entries" | "filename"),
 *     MIME_TYPES, EXTENSIONS (when KIND="content"), PROFILES,
 *     COMPLIANCE_POSTURES, gate(opts)
 *   - export INTEGRATION_FIXTURES with kind-appropriate sample
 *     payloads (benignBytes/hostileBytes for content; benignEntries/
 *     hostileEntries for entries; benignFilename/hostileFilename for
 *     filename)
 *   - register in lib/guard-all.js GUARDS or STANDALONE_GUARDS
 *
 * The harness picks them up automatically.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- Fixture-discovery + assertion helpers ----

function _hasFixture(g) {
  return g && g.INTEGRATION_FIXTURES &&
         typeof g.INTEGRATION_FIXTURES === "object";
}

function _capturingAudit() {
  // Host primitives (staticServe / fileUpload) call audit.safeEmit
  // with a single `{ action, actor, resource, outcome, ... }` object.
  // Guard primitives' onAudit hook expects emit() with a similar
  // shape. Capture both into one rows array; downstream checks key
  // off the `action` field (host) or `event` field (guard).
  var rows = [];
  return {
    rows: rows,
    audit: {
      emit:     function (e) { rows.push(e); },
      safeEmit: function (e) {
        if (!e || typeof e !== "object") return;
        rows.push(e);
      },
    },
  };
}

// A guard that reports one issue per offending attribute, cell, key or tag
// allocates one object per offense. Inside the size cap that is hundreds of
// thousands of objects for a body the verdict decided on the first of them.
// Every content guard routes its findings through one reporter that keeps
// MAX_ISSUES_PER_KIND of each kind, so this drives each with a document of
// many offenses and reads the count per kind.
function testEveryGuardBoundsIssuesPerKind() {
  var N = 20000;
  var cap = b.gateContract.MAX_ISSUES_PER_KIND;
  var cases = [
    { name: "guardSvg non-allowlisted attributes", guard: "guardSvg", profile: "strict",
      doc: '<svg xmlns="http://www.w3.org/2000/svg"><rect ' + "a ".repeat(N) + "/></svg>" },
    { name: "guardSvg event handlers", guard: "guardSvg", profile: "balanced",
      doc: '<svg xmlns="http://www.w3.org/2000/svg"><rect ' +
        Array.from({ length: N }, function (_, i) { return "onx" + i + "=1"; }).join(" ") + "/></svg>" },
    { name: "guardSvg dangerous schemes", guard: "guardSvg", profile: "balanced",
      doc: '<svg xmlns="http://www.w3.org/2000/svg">' + '<a href="javascript:1"/>'.repeat(N) + "</svg>" },
    { name: "guardHtml event handlers", guard: "guardHtml", profile: "balanced",
      doc: "<div " + Array.from({ length: N }, function (_, i) { return "onx" + i + "=1"; }).join(" ") + ">x</div>" },
    { name: "guardHtml dangerous schemes", guard: "guardHtml", profile: "balanced",
      doc: '<a href="javascript:1">x</a>'.repeat(N) },
    { name: "guardCsv dangerous functions", guard: "guardCsv", profile: "balanced",
      doc: "=HYPERLINK(1),a\n".repeat(N) },
    { name: "guardJson pollution keys", guard: "guardJson", profile: "balanced",
      doc: "[" + Array.from({ length: N }, function () { return '{"__proto__":1}'; }).join(",") + "]" },
    { name: "guardYaml dangerous tags", guard: "guardYaml", profile: "balanced",
      doc: "- !!python/object x\n".repeat(N) },
    { name: "guardMarkdown dangerous links", guard: "guardMarkdown", profile: "balanced",
      doc: "[x](javascript:1)\n".repeat(N) },
  ];
  cases.forEach(function (c) {
    var r = b[c.guard].validate(c.doc, { profile: c.profile });
    var byKind = Object.create(null);
    r.issues.forEach(function (i) { byKind[i.kind] = (byKind[i.kind] || 0) + 1; });
    var worst = 0;
    Object.keys(byKind).forEach(function (k) { if (byKind[k] > worst) worst = byKind[k]; });
    check("[" + c.name + "] reports at most " + cap + " issues of one kind",
          worst <= cap, JSON.stringify(byKind));
    check("[" + c.name + "] is still refused", r.ok === false);
  });
}

// ---- Per-kind harness ----

var GATE_PROFILES = ["strict", "balanced", "permissive"];

// A content gate returns the repaired body in `sanitized`. Reading any other
// field returns null for every sanitize verdict, which makes the assertions
// below pass without ever looking at what the gate would serve.
function _gateBody(verdict) {
  if (Buffer.isBuffer(verdict.sanitized)) return verdict.sanitized.toString("utf8");
  if (typeof verdict.sanitized === "string") return verdict.sanitized;
  if (Buffer.isBuffer(verdict.bytes)) return verdict.bytes.toString("utf8");
  if (typeof verdict.text === "string") return verdict.text;
  return null;
}

function _criticalKinds(validateFn, text, profile) {
  var after;
  try { after = validateFn(text, { profile: profile }); }
  catch (_e) { return []; }
  return (after.issues || [])
    .filter(function (i) { return i.severity === "critical"; })
    .map(function (i) { return i.kind; });
}

function _gateBodyCarriesNoCritical(verdict, validateFn, profile) {
  var body = _gateBody(verdict);
  if (body === null) return true;
  return _criticalKinds(validateFn, body, profile).length === 0;
}

function _gateDoesNotServeCritical(verdict, validateFn, profile, hostileText) {
  if (verdict.action !== "serve") return true;
  if (_gateBody(verdict) !== null && _gateBody(verdict) !== hostileText) return true;
  return _criticalKinds(validateFn, hostileText, profile).length === 0;
}

async function _runContentGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var capA = _capturingAudit();

  // 1. Direct gate, benign + hostile.
  var gate = g.gate({ profile: "strict", audit: capA.audit });
  var rvBenign = await gate.check({
    contentType: fx.contentType, bytes: fx.benignBytes,
  });
  check("[" + g.NAME + "] direct gate: benign → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  var rvHostile = await gate.check({
    contentType: fx.contentType, bytes: fx.hostileBytes,
  });
  check("[" + g.NAME + "] direct gate: hostile → not serve",
        rvHostile.action !== "serve");

  // 2. b.guardAll.gate contentTypeMux dispatch — benign payload routed
  // by Content-Type to the right guard.
  var allGate = b.guardAll.gate({ profile: "strict", audit: capA.audit });
  var rvDispBenign = await allGate.check({
    contentType: fx.contentType, bytes: fx.benignBytes,
  });
  check("[" + g.NAME + "] guardAll dispatch: benign → serve",
        rvDispBenign.ok === true && rvDispBenign.action === "serve");

  var rvDispHostile = await allGate.check({
    contentType: fx.contentType, bytes: fx.hostileBytes,
  });
  check("[" + g.NAME + "] guardAll dispatch: hostile → not serve",
        rvDispHostile.action !== "serve");

  // 3. exceptFor opt-out — guardAll dispatches to bypass when this
  // guard's NAME is in exceptFor, audit row records the skip.
  var capB = _capturingAudit();
  var optOutMap = {};
  optOutMap[g.NAME] = { reason: "operator opt-out for integration test" };
  var optOutGate = b.guardAll.gate({
    profile:   "strict",
    audit:     capB.audit,
    exceptFor: optOutMap,
  });
  var rvOptOut = await optOutGate.check({
    contentType: fx.contentType, bytes: fx.hostileBytes,
  });
  check("[" + g.NAME + "] guardAll exceptFor: opt-out bypasses (hostile → serve)",
        rvOptOut.ok === true && rvOptOut.action === "serve");
  var creationRow = capB.rows.filter(function (r) {
    return r.event === "guardAll.gate.created";
  })[0];
  check("[" + g.NAME + "] exceptFor: audit creation row records skip",
        creationRow &&
        creationRow.metadata.skipped.some(function (s) { return s.name === g.NAME; }));

  // 3b. Whatever body the gate hands back must not still carry a critical
  // issue. `action !== "serve"` above passes when the action is "sanitize"
  // and the sanitized body still holds the payload, which is the shape that
  // reached an operator in b.guardMarkdown: sanitize returned its input.
  // Every profile, since the loosened policies live in balanced/permissive.
  var repaired = 0;
  var repairedRead = 0;
  for (var pi = 0; pi < GATE_PROFILES.length; pi += 1) {
    var profile = GATE_PROFILES[pi];
    var pv = await g.gate({ profile: profile }).check({
      contentType: fx.contentType, bytes: fx.hostileBytes,
    });
    if (pv.action === "sanitize") {
      repaired += 1;
      if (_gateBody(pv) !== null) repairedRead += 1;
    }
    check("[" + g.NAME + "/" + profile + "] gate body carries no critical issue",
          _gateBodyCarriesNoCritical(pv, g.validate, profile));
    check("[" + g.NAME + "/" + profile + "] gate does not serve a critical payload unchanged",
          _gateDoesNotServeCritical(pv, g.validate, profile,
            fx.hostileBytes.toString("utf8")));
  }
  // The two checks above pass vacuously when the body cannot be read, which is
  // what reading the wrong field produces. A refusal has no body by design, so
  // the claim is only about a verdict that hands back a repaired one.
  check("[" + g.NAME + "] every sanitize verdict returned a body to inspect",
        repairedRead === repaired, repairedRead + " of " + repaired);

  // 4. b.staticServe.create({ contentSafety }) GET round-trip.
  await _runStaticServeRoundTrip(g, fx);

  // 5. b.fileUpload chunk → finalize round-trip.
  await _runFileUploadRoundTrip(g, fx);
}

async function _runStaticServeRoundTrip(g, fx) {
  var os    = require("os");
  var path  = require("path");
  var fs    = require("fs");

  var dir = fs.mkdtempSync(path.join(os.tmpdir(),
    "guard-host-static-" + g.NAME + "-"));
  fs.mkdirSync(dir, { recursive: true });
  var benignPath  = path.join(dir, "benign" + fx.extension);
  var hostilePath = path.join(dir, "hostile" + fx.extension);
  fs.writeFileSync(benignPath, fx.benignBytes);
  fs.writeFileSync(hostilePath, fx.hostileBytes);

  var capA = _capturingAudit();
  var safetyMap = {};
  safetyMap[fx.extension] = g.gate({ profile: "strict", audit: capA.audit });
  var assets = b.staticServe.create({
    root:          dir,
    audit:         capA.audit,
    contentSafety: safetyMap,
  });

  // Benign request → 200 + body delivered. staticServe expects req
  // to be EventEmitter-shaped (it listens for "aborted"); bodyReq
  // returns an EventEmitter, mockReq does not.
  var benignReq = b.testing.bodyReq("GET", { host: "test.local" }, "");
  benignReq.url = "/benign" + fx.extension;
  benignReq.pathname = "/benign" + fx.extension;
  var benignRes = b.testing.streamingRes();
  await new Promise(function (resolve) {
    assets(benignReq, benignRes, function (err) { resolve(err); });
    benignRes.on("finish", resolve);
  });
  // streamingRes captures statusCode AND body bytes.
  var benignStatus = benignRes._statusCode;
  check("[" + g.NAME + "] staticServe: benign GET → 2xx",
        benignStatus >= 200 && benignStatus < 300);

  // Hostile request → 415 (or non-2xx) per gate refusal.
  var hostileReq = b.testing.bodyReq("GET", { host: "test.local" }, "");
  hostileReq.url = "/hostile" + fx.extension;
  hostileReq.pathname = "/hostile" + fx.extension;
  var hostileRes = b.testing.streamingRes();
  await new Promise(function (resolve) {
    assets(hostileReq, hostileRes, function (err) { resolve(err); });
    hostileRes.on("finish", resolve);
  });
  var hostileStatus = hostileRes._statusCode;
  check("[" + g.NAME + "] staticServe: hostile GET → non-2xx",
        hostileStatus >= 400 && hostileStatus < 600);

  // Cleanup.
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

async function _runFileUploadRoundTrip(g, fx) {
  var os    = require("os");
  var path  = require("path");

  var capA = _capturingAudit();
  var safetyMap = {};
  safetyMap[fx.extension] = g.gate({ profile: "strict", audit: capA.audit });
  var stagingDir = path.join(os.tmpdir(),
    "guard-host-upload-" + g.NAME + "-" + Date.now());
  var finalizedCount = 0;
  var uploads = b.fileUpload.create({
    stagingDir:    stagingDir,
    audit:         capA.audit,
    contentSafety: safetyMap,
    onFinalize: async function (info) {
      finalizedCount += 1;
      return { ok: true, key: info.uploadId };
    },
  });

  // Benign upload — init + chunk + finalize. Single-chunk uploads use
  // the chunk sha3 as the total sha3; manifest declares chunk metadata.
  var actor = { kind: "user", id: "u1" };
  var benignSha = b.crypto.sha3Hash(fx.benignBytes).toString("hex");
  var benignId  = "guardhost-benign-" + g.NAME + "-" + Date.now();
  await uploads.init({ uploadId: benignId, actor: actor,
    metadata: { filename: "benign" + fx.extension } });
  await uploads.acceptChunk({ uploadId: benignId, actor: actor,
    index: 0, body: fx.benignBytes, sha3: benignSha });
  var benignFinalize = null;
  try {
    benignFinalize = await uploads.finalize({ uploadId: benignId, actor: actor,
      manifest: {
        chunks:     [{ index: 0, sha3: benignSha, size: fx.benignBytes.length }],
        totalBytes: fx.benignBytes.length,
        sha3:       benignSha,
      } });
  } catch (e) {
    benignFinalize = { error: e };
  }
  check("[" + g.NAME + "] fileUpload: benign finalize → succeeds",
        benignFinalize && benignFinalize.ok === true);

  // Hostile upload — finalize throws content-safety error.
  var hostileSha = b.crypto.sha3Hash(fx.hostileBytes).toString("hex");
  var hostileId  = "guardhost-hostile-" + g.NAME + "-" + Date.now();
  await uploads.init({ uploadId: hostileId, actor: actor,
    metadata: { filename: "hostile" + fx.extension } });
  await uploads.acceptChunk({ uploadId: hostileId, actor: actor,
    index: 0, body: fx.hostileBytes, sha3: hostileSha });
  var hostileError = null;
  try {
    await uploads.finalize({ uploadId: hostileId, actor: actor,
      manifest: {
        chunks:     [{ index: 0, sha3: hostileSha, size: fx.hostileBytes.length }],
        totalBytes: fx.hostileBytes.length,
        sha3:       hostileSha,
      } });
  } catch (e) {
    hostileError = e;
  }
  check("[" + g.NAME + "] fileUpload: hostile finalize → throws content-safety error",
        hostileError && /CONTENT_SAFETY_REFUSED|content-safety|guard|refuse/i
                          .test(hostileError.code || hostileError.message || ""));
  void finalizedCount;

  // Audit chain has host-level rows. Host primitives use `action`;
  // guard primitives use `event` (when wired through onAudit hook).
  var hasHostRow = capA.rows.some(function (r) {
    var name = r.action || r.event || "";
    return /fileUpload|file-upload|upload/i.test(name);
  });
  check("[" + g.NAME + "] fileUpload: audit captured host-level rows",
        hasHostRow);

  // Cleanup uploads staging dir.
  try {
    var fs = require("fs");
    fs.rmSync(stagingDir, { recursive: true, force: true });
  } catch (_e) { /* best-effort */ }
}

async function _runEntriesGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var gate = g.gate({ profile: "strict" });

  // Benign entries → serve.
  var rvBenign = await gate.check({ entries: fx.benignEntries });
  check("[" + g.NAME + "] direct gate: benign entries → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  // Hostile entries → refuse.
  var rvHostile = await gate.check({ entries: fx.hostileEntries });
  check("[" + g.NAME + "] direct gate: hostile entries → refuse",
        rvHostile.action === "refuse");

  // ctx.bytes without ctx.entries → refuse with no-entry-list issue
  // (operator must enumerate entries via their archive library).
  var rvBytesOnly = await gate.check({
    bytes: Buffer.from([0x50, 0x4B, 0x03, 0x04]),
  });
  check("[" + g.NAME + "] direct gate: bytes without entries → refuse",
        rvBytesOnly.action === "refuse");
}

async function _runFilenameGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var gate = g.gate({ profile: "strict" });

  // Benign filename → serve.
  var rvBenign = await gate.check({ filename: fx.benignFilename });
  check("[" + g.NAME + "] direct gate: benign filename → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  // Hostile filename → not serve.
  var rvHostile = await gate.check({ filename: fx.hostileFilename });
  check("[" + g.NAME + "] direct gate: hostile filename → not serve",
        rvHostile.action !== "serve");

  // Standalone primitives don't register in guardAll's content-type
  // dispatch — confirm absence.
  check("[" + g.NAME + "] NOT registered in guardAll content-type dispatch",
        !b.guardAll.list().some(function (entry) { return entry.name === g.NAME; }));
}

async function _runIdentifierGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var gate = g.gate({ profile: "strict" });

  // Benign identifier → serve.
  var rvBenign = await gate.check({ identifier: fx.benignIdentifier });
  check("[" + g.NAME + "] direct gate: benign identifier → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  // Hostile identifier → not serve.
  var rvHostile = await gate.check({ identifier: fx.hostileIdentifier });
  check("[" + g.NAME + "] direct gate: hostile identifier → not serve",
        rvHostile.action !== "serve");

  // Standalone primitives don't register in guardAll's content-type
  // dispatch — confirm absence.
  check("[" + g.NAME + "] NOT registered in guardAll content-type dispatch",
        !b.guardAll.list().some(function (entry) { return entry.name === g.NAME; }));
}

async function _runSqlGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var gate = g.gate({ profile: "strict" });

  // Benign parameterized fragment → serve.
  var rvBenign = await gate.check({ sql: fx.benignSql });
  check("[" + g.NAME + "] direct gate: benign SQL → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  // Hostile fragment (stacked statement) → not serve.
  var rvHostile = await gate.check({ sql: fx.hostileSql });
  check("[" + g.NAME + "] direct gate: hostile SQL → not serve",
        rvHostile.action !== "serve");

  // Standalone primitive — not in guardAll's content-type dispatch.
  check("[" + g.NAME + "] NOT registered in guardAll content-type dispatch",
        !b.guardAll.list().some(function (entry) { return entry.name === g.NAME; }));
}

async function _runAuthBundleGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var gate = g.gate({ profile: "strict" });

  var rvBenign = await gate.check({ authBundle: fx.benignAuthBundle });
  check("[" + g.NAME + "] direct gate: benign authBundle → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  var rvHostile = await gate.check({ authBundle: fx.hostileAuthBundle });
  check("[" + g.NAME + "] direct gate: hostile authBundle → not serve",
        rvHostile.action !== "serve");

  check("[" + g.NAME + "] NOT registered in guardAll content-type dispatch",
        !b.guardAll.list().some(function (entry) { return entry.name === g.NAME; }));
}

async function _runMetadataGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var gate = g.gate({ profile: "strict" });

  var rvBenign = await gate.check({ metadata: fx.benignMetadata });
  check("[" + g.NAME + "] direct gate: benign metadata → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  var rvHostile = await gate.check({ metadata: fx.hostileMetadata });
  check("[" + g.NAME + "] direct gate: hostile metadata → not serve",
        rvHostile.action !== "serve");

  check("[" + g.NAME + "] NOT registered in guardAll content-type dispatch",
        !b.guardAll.list().some(function (entry) { return entry.name === g.NAME; }));
}

async function _runGraphqlGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  var gate = g.gate({ profile: "strict" });

  var rvBenign = await gate.check({ graphqlRequest: fx.benignGraphqlRequest });
  check("[" + g.NAME + "] direct gate: benign graphqlRequest → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  var rvHostile = await gate.check({ graphqlRequest: fx.hostileGraphqlRequest });
  check("[" + g.NAME + "] direct gate: hostile graphqlRequest → not serve",
        rvHostile.action !== "serve");

  check("[" + g.NAME + "] NOT registered in guardAll content-type dispatch",
        !b.guardAll.list().some(function (entry) { return entry.name === g.NAME; }));
}

async function _runOauthFlowGuard(g) {
  var fx = g.INTEGRATION_FIXTURES;
  // A guard may declare the opts a CONFIGURED deployment supplies. Without
  // them the benign case measures the harness's own under-configuration
  // rather than the guard: guard-oauth's strict profile requires a
  // redirect_uri allowlist, and reports that it has none.
  var gate = g.gate(Object.assign({ profile: "strict" }, fx.gateOpts || {}));

  var rvBenign = await gate.check({ oauthFlow: fx.benignOauthFlow });
  check("[" + g.NAME + "] direct gate: benign oauthFlow → serve",
        rvBenign.ok === true && rvBenign.action === "serve");

  // ...and UNCONFIGURED, the same benign flow must still say so rather than
  // pass silently — the configuration gap is a finding, not a non-event.
  if (fx.gateOpts) {
    var bare = await g.gate({ profile: "strict" }).check({ oauthFlow: fx.benignOauthFlow });
    check("[" + g.NAME + "] an unconfigured gate reports the gap",
          (bare.issues || []).length > 0);
  }

  var rvHostile = await gate.check({ oauthFlow: fx.hostileOauthFlow });
  check("[" + g.NAME + "] direct gate: hostile oauthFlow → not serve",
        rvHostile.action !== "serve");

  check("[" + g.NAME + "] NOT registered in guardAll content-type dispatch",
        !b.guardAll.list().some(function (entry) { return entry.name === g.NAME; }));
}

// ---- Discovery + dispatcher ----

async function testGuardHostIntegrationAdaptive() {
  var allGuards = b.guardAll.allGuards();
  check("guardAll.allGuards() returns at least one primitive",
        allGuards.length >= 1);

  var skipped = [];
  for (var i = 0; i < allGuards.length; i += 1) {
    var g = allGuards[i];
    if (!_hasFixture(g)) {
      skipped.push(g.NAME);
      continue;
    }
    if (g.KIND === "content") {
      await _runContentGuard(g);
    } else if (g.KIND === "entries") {
      await _runEntriesGuard(g);
    } else if (g.KIND === "filename") {
      await _runFilenameGuard(g);
    } else if (g.KIND === "identifier") {
      await _runIdentifierGuard(g);
    } else if (g.KIND === "sql") {
      await _runSqlGuard(g);
    } else if (g.KIND === "oauth-flow") {
      await _runOauthFlowGuard(g);
    } else if (g.KIND === "graphql-request") {
      await _runGraphqlGuard(g);
    } else if (g.KIND === "metadata") {
      await _runMetadataGuard(g);
    } else if (g.KIND === "auth-bundle") {
      await _runAuthBundleGuard(g);
    } else {
      check("[" + g.NAME + "] unknown KIND " + JSON.stringify(g.KIND), false);
    }
  }
  check("every guard has INTEGRATION_FIXTURES (none skipped: " +
        JSON.stringify(skipped) + ")",
        skipped.length === 0);
}

// ---- Default-on verification ----
// Per v0.7.12 — b.fileUpload + b.staticServe wire b.guardAll on by
// default at strict profile. These tests verify the default-on path
// AND the explicit opt-out path (audit emission on contentSafety: null
// / filenameSafety: null).

async function testFileUploadDefaultOn() {
  var fs = require("fs");
  var os = require("os");
  var path = require("path");
  var capA = _capturingAudit();
  var stagingDir = path.join(os.tmpdir(), "guard-default-on-fu-" + Date.now());
  // No contentSafety / filenameSafety opts — relying on strict default.
  var uploads = b.fileUpload.create({
    stagingDir: stagingDir,
    audit:      capA.audit,
    onFinalize: async function (info) { return { ok: true, key: info.uploadId }; },
  });
  // Hostile filename triggers default-on filenameSafety refuse.
  var actor = { kind: "user", id: "u1" };
  var bytes = Buffer.from("safe content", "utf8");
  var sha   = b.crypto.sha3Hash(bytes).toString("hex");
  var uid   = "default-on-hostile-" + Date.now();
  await uploads.init({ uploadId: uid, actor: actor,
    metadata: { filename: "../etc/passwd" } });
  await uploads.acceptChunk({ uploadId: uid, actor: actor,
    index: 0, body: bytes, sha3: sha });
  var threwHostileFn = null;
  try {
    await uploads.finalize({ uploadId: uid, actor: actor,
      manifest: { chunks: [{ index: 0, sha3: sha, size: bytes.length }],
                  totalBytes: bytes.length, sha3: sha } });
  } catch (e) { threwHostileFn = e; }
  check("default-on: fileUpload refuses path-traversal filename without explicit opt",
        threwHostileFn && /FILENAME_SAFETY|filename/i.test(threwHostileFn.code || ""));

  try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

async function testFileUploadOptOutEmitAudit() {
  var fs = require("fs");
  var os = require("os");
  var path = require("path");
  var capA = _capturingAudit();
  var stagingDir = path.join(os.tmpdir(), "guard-optout-fu-" + Date.now());
  // Explicit opt-out of both safety gates.
  b.fileUpload.create({
    stagingDir:    stagingDir,
    audit:         capA.audit,
    contentSafety: null,
    filenameSafety: null,
    contentSafetyDisabledReason:  "integration-test: verifying opt-out audit emission",
    filenameSafetyDisabledReason: "integration-test: verifying opt-out audit emission",
    onFinalize: async function () { return { ok: true }; },
  });
  var contentDisabledRow = capA.rows.filter(function (r) {
    return (r.action || r.event) === "fileUpload.contentSafety.disabled";
  })[0];
  var filenameDisabledRow = capA.rows.filter(function (r) {
    return (r.action || r.event) === "fileUpload.filenameSafety.disabled";
  })[0];
  check("opt-out: fileUpload contentSafety: null → audit row emitted",
        !!contentDisabledRow);
  check("opt-out: fileUpload filenameSafety: null → audit row emitted",
        !!filenameDisabledRow);
  check("opt-out: contentSafety audit carries operator reason",
        contentDisabledRow && /verifying opt-out/.test(
          (contentDisabledRow.metadata && contentDisabledRow.metadata.reason) || ""));

  try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

async function testStaticServeDefaultOn() {
  var fs = require("fs");
  var os = require("os");
  var path = require("path");
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-default-on-ss-"));
  fs.mkdirSync(dir, { recursive: true });
  // Hostile HTML — default-on contentSafety refuses.
  fs.writeFileSync(path.join(dir, "hostile.html"),
    '<p>hi</p><script>alert(1)</script>');
  var capA = _capturingAudit();
  var assets = b.staticServe.create({
    root:  dir,
    audit: capA.audit,
    // No contentSafety opt — relying on strict default.
  });
  var req = b.testing.bodyReq("GET", { host: "test.local" }, "");
  req.url = "/hostile.html";
  req.pathname = "/hostile.html";
  var res = b.testing.streamingRes();
  await new Promise(function (resolve) {
    assets(req, res, function () { resolve(); });
    res.on("finish", resolve);
  });
  check("default-on: staticServe refuses hostile HTML (script tag) → non-2xx",
        res._statusCode >= 400 && res._statusCode < 600);

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

async function testStaticServeOptOutEmitAudit() {
  var fs = require("fs");
  var os = require("os");
  var path = require("path");
  var dir = path.join(os.tmpdir(), "guard-optout-ss-" + Date.now());
  fs.mkdirSync(dir, { recursive: true });
  var capA = _capturingAudit();
  b.staticServe.create({
    root:                          dir,
    audit:                         capA.audit,
    contentSafety:                 null,
    contentSafetyDisabledReason:   "integration-test: verifying staticServe opt-out audit",
  });
  var disabledRow = capA.rows.filter(function (r) {
    return (r.action || r.event) === "staticServe.contentSafety.disabled";
  })[0];
  check("opt-out: staticServe contentSafety: null → audit row emitted",
        !!disabledRow);
  check("opt-out: staticServe audit carries operator reason",
        disabledRow && /verifying staticServe/.test(
          (disabledRow.metadata && disabledRow.metadata.reason) || ""));

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

// ---- Run ----

async function run() {
  testEveryGuardBoundsIssuesPerKind();
  await testGuardHostIntegrationAdaptive();
  await testFileUploadDefaultOn();
  await testFileUploadOptOutEmitAudit();
  await testStaticServeDefaultOn();
  await testStaticServeOptOutEmitAudit();
}

module.exports = { run: run };

// CLI entry: `node test/layer-5-integration/guard-host-integration.test.js`
if (require.main === module) {
  run().then(function () {
    process.stdout.write("OK — guard-host-integration passed\n");
  }, function (e) {
    process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
    process.exit(1);
  });
}
