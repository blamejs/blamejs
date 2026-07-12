// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.selfUpdate — poll / verify / swap / rollback tests.
 *
 * Run standalone: `node test/layer-0-primitives/self-update.test.js`
 * Or via smoke:   `node test/smoke.js`
 *
 * The poll() path runs against a local http.Server fixture (no live
 * GitHub interaction). The releasesUrl is http://127.0.0.1:<port> so
 * we pass allowedProtocols + allowInternal through to the framework
 * SSRF guard. Production callers default to https-only with no
 * internal addresses.
 *
 * verify() / swap() / rollback() exercise the full atomic-swap +
 * rollback flow against on-disk artifacts under os.tmpdir().
 */

var fs = require("fs");
var os = require("os");
var http = require("http");
var path = require("path");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var _tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-selfupdate-"));
function _tmp(name) {
  return path.join(_tmpBase, Date.now() + "-" +
    Math.random().toString(36).slice(2, 8) + "-" + name);
}

function _newSigningKeys() {
  return nodeCrypto.generateKeyPairSync("ed25519");
}

function _detachedSign(privateKey, bytes) {
  return nodeCrypto.sign(null, bytes, privateKey);
}

function testSurface() {
  check("b.selfUpdate namespace present",      typeof b.selfUpdate === "object");
  check("b.selfUpdate.poll is a function",     typeof b.selfUpdate.poll === "function");
  check("b.selfUpdate.verify is a function",   typeof b.selfUpdate.verify === "function");
  check("b.selfUpdate.swap is a function",     typeof b.selfUpdate.swap === "function");
  check("b.selfUpdate.rollback is a function", typeof b.selfUpdate.rollback === "function");
  check("SelfUpdateError class exposed",       typeof b.selfUpdate.SelfUpdateError === "function");
  check("DEFAULT_HASH_ALG = sha3-512",         b.selfUpdate.DEFAULT_HASH_ALG === "sha3-512");
}

function testPollRejectsBadOpts() {
  return Promise.resolve()
    .then(function () { return b.selfUpdate.poll(); })
    .then(function () { check("poll() with no opts should throw", false); },
          function (e) { check("poll: rejects empty",
            e && /selfupdate\/bad-opts/.test(e.code || "")); })
    .then(function () { return b.selfUpdate.poll({ releasesUrl: "ftp://x", currentVersion: "1.0.0" }); })
    .then(function () { check("poll() ftp:// should throw", false); },
          function (e) { check("poll: rejects ftp protocol",
            e && /selfupdate\/bad-releases-url/.test(e.code || "")); });
}

function testPollRejectsUnsafeAssetPattern() {
  // A wrapped nested quantifier is catastrophic-backtracking (ReDoS)
  // shaped; it must be refused at config-time, before any request runs.
  // The releasesUrl is well-formed so the assetPattern screen is what
  // fails — and the refusal happens before any .test() so nothing ever
  // backtracks.
  return Promise.resolve()
    .then(function () {
      return b.selfUpdate.poll({
        releasesUrl:    "https://example.invalid/releases",
        currentVersion: "1.0.0",
        assetPattern:   /((a)+)+$/,
      });
    })
    .then(function () { check("poll() ReDoS assetPattern should throw", false); },
          function (e) { check("poll: rejects ReDoS-shaped assetPattern",
            e && /selfupdate\/unsafe-asset-pattern/.test(e.code || "")); });
}

function testCompareTags() {
  var cmp = b.selfUpdate.compareTags;
  check("compareTags: public surface exposed",  typeof cmp === "function");
  check("compareTags: identical to internal",   cmp === b.selfUpdate._compareTags);
  check("compareTags: v0.7.30 < v0.7.31",       cmp("v0.7.30", "v0.7.31") === -1);
  check("compareTags: v0.7.31 > v0.7.30",       cmp("v0.7.31", "v0.7.30") === 1);
  check("compareTags: v0.7.31 == 0.7.31",       cmp("v0.7.31", "0.7.31") === 0);
  check("compareTags: v0.8.0 > v0.7.99",        cmp("v0.8.0", "v0.7.99") === 1);
  check("compareTags: v1.0.0 > v0.99.0",        cmp("v1.0.0", "v0.99.0") === 1);
  check("compareTags: case-insensitive leading v", cmp("V1.0.0", "1.0.0") === 0);
  check("compareTags: missing components treated as 0", cmp("1.0", "1.0.0") === 0);
  check("compareTags: non-numeric falls back to lex", cmp("1.0.0-rc.1", "1.0.0-rc.2") === -1);
  check("compareTags: bad input (non-string) safe",   cmp(null, "1.0.0") === -1);
  check("compareTags: bad input both safe",           cmp(null, undefined) === 0);
  // SemVer 2.0.0 §11 strict precedence — the lex-only ordering would
  // sort "10" < "9" as strings, allowing an attacker pivot of
  // publishing `1.0.0-alpha.10` to leapfrog `1.0.0-alpha.9`. The
  // strict implementation forces numeric compare per §11.4.1.
  check("compareTags §11.4.1: alpha.9 < alpha.10 (numeric, not lex)",
        cmp("1.0.0-alpha.9", "1.0.0-alpha.10") === -1);
  check("compareTags §11.4.1: alpha.10 > alpha.9",
        cmp("1.0.0-alpha.10", "1.0.0-alpha.9") === 1);
  // §11.4.2 — alphanumeric identifiers compare lexicographically.
  check("compareTags §11.4.2: alpha < beta (lex)",
        cmp("1.0.0-alpha", "1.0.0-beta") === -1);
  // §11.4.3 — numeric identifier < alphanumeric.
  check("compareTags §11.4.3: 1 < alpha (numeric < alphanum)",
        cmp("1.0.0-1", "1.0.0-alpha") === -1);
  // §11.3 — version WITHOUT pre-release > version WITH one.
  check("compareTags §11.3: 1.0.0-rc.1 < 1.0.0 (release > pre-release)",
        cmp("1.0.0-rc.1", "1.0.0") === -1);
  check("compareTags §11.3: 1.0.0 > 1.0.0-rc.1",
        cmp("1.0.0", "1.0.0-rc.1") === 1);
  // §11.4.4 — longer pre-release list > shorter when prefix matches.
  check("compareTags §11.4.4: alpha < alpha.1 (shorter < longer)",
        cmp("1.0.0-alpha", "1.0.0-alpha.1") === -1);
  // §10 — build metadata ignored.
  check("compareTags §10: 1.0.0+sha-abc = 1.0.0+sha-def (build ignored)",
        cmp("1.0.0+sha-abc", "1.0.0+sha-def") === 0);
}

function _serveJson(payload) {
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  });
  return server;
}

async function testPollAvailableAndUpToDate() {
  // Newer release available.
  var s1 = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs-2.0.0.tar.gz",     browser_download_url: "https://example.invalid/asset.tgz", size: 1024 },
      { name: "blamejs-2.0.0.tar.gz.sig", browser_download_url: "https://example.invalid/asset.sig", size: 64 },
    ],
  });
  var port1 = await b.testing.listenOnRandomPort(s1);
  try {
    var r1 = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port1 + "/releases/latest",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: available=true",                 r1.available === true);
    check("poll: latestTag=v2.0.0",               r1.latestTag === "v2.0.0");
    check("poll: asset selected",                 r1.asset && r1.asset.name === "blamejs-2.0.0.tar.gz");
    check("poll: signature selected",             r1.signature && r1.signature.name === "blamejs-2.0.0.tar.gz.sig");
  } finally { s1.close(); }

  // Up-to-date — no newer tag.
  var s2 = _serveJson({ tag_name: "v1.0.0", assets: [] });
  var port2 = await b.testing.listenOnRandomPort(s2);
  try {
    var r2 = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port2 + "/releases/latest",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: up-to-date available=false",     r2.available === false);
    check("poll: up-to-date latestTag=v1.0.0",    r2.latestTag === "v1.0.0");
  } finally { s2.close(); }
}

async function testPollArrayShape() {
  var s = _serveJson([
    { tag_name: "v1.0.0", assets: [] },
    { tag_name: "v2.0.0", assets: [{ name: "x.tar.gz", browser_download_url: "https://example.invalid/x.tgz" }] },
    { tag_name: "v1.5.0", assets: [] },
  ]);
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port + "/releases",
      currentVersion:   "v0.5.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: array picks max tag",            r.latestTag === "v2.0.0");
  } finally { s.close(); }
}

async function testPollNon2xxRefused() {
  var s = http.createServer(function (req, res) { res.writeHead(503); res.end(""); });
  var port = await b.testing.listenOnRandomPort(s);
  var threw = null;
  try {
    await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port + "/releases",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
  } catch (e) { threw = e; }
  s.close();
  check("poll: 503 raises selfupdate error",
        threw && /selfupdate\/poll-non-2xx|selfupdate\/poll-failed/.test(threw.code || ""));
}

async function testVerifyPassFail() {
  var keys = _newSigningKeys();
  var pubPem = keys.publicKey.export({ type: "spki", format: "pem" });
  var assetBytes = Buffer.from("hello blamejs payload");
  var sigBytes   = _detachedSign(keys.privateKey, assetBytes);

  var assetPath = _tmp("asset.bin");
  var sigPath   = _tmp("asset.sig");
  fs.writeFileSync(assetPath, assetBytes);
  fs.writeFileSync(sigPath,   sigBytes);

  try {
    var ok = await b.selfUpdate.verify({
      assetPath:     assetPath,
      signaturePath: sigPath,
      pubkeyPem:     pubPem,
    });
    check("verify: passed",                       ok.verified === true);
    check("verify: hash returned",                typeof ok.hash === "string" && ok.hash.length > 0);
    check("verify: alg = sha3-512",               ok.alg === "sha3-512");

    // Tamper the signature — verify must throw.
    var badSig = Buffer.from(sigBytes);
    badSig[0] ^= 0xFF;
    fs.writeFileSync(sigPath, badSig);
    var threw = null;
    try {
      await b.selfUpdate.verify({
        assetPath:     assetPath,
        signaturePath: sigPath,
        pubkeyPem:     pubPem,
      });
    } catch (e) { threw = e; }
    check("verify: tampered sig is refused",
          threw && /selfupdate\/(signature-mismatch|verify-failed)/.test(threw.code || ""));
  } finally {
    try { fs.unlinkSync(assetPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sigPath);   } catch (_e) { /* best-effort */ }
  }
}

async function testSwapAndRollback() {
  var dir = _tmp("dir");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "blamejs.bin");
  var backupTo = path.join(dir, "blamejs.bin.bak");
  var newPath  = path.join(dir, "blamejs.bin.new");

  fs.writeFileSync(to,      Buffer.from("OLD-BINARY"));
  fs.writeFileSync(newPath, Buffer.from("NEW-BINARY"));

  var newHash = nodeCrypto.createHash("sha3-512").update(Buffer.from("NEW-BINARY")).digest("hex");
  var rs = await b.selfUpdate.swap({ from: newPath, to: to, backupTo: backupTo, expectedHash: newHash });
  check("swap: ok=true",                           rs.ok === true);
  check("swap: to has new bytes",                  fs.readFileSync(to, "utf8") === "NEW-BINARY");
  check("swap: backup has old bytes",              fs.readFileSync(backupTo, "utf8") === "OLD-BINARY");
  check("swap: from removed (renamed)",            !fs.existsSync(newPath));

  var rr = await b.selfUpdate.rollback({ to: to, backupTo: backupTo });
  check("rollback: ok=true",                       rr.ok === true);
  check("rollback: to has old bytes again",        fs.readFileSync(to, "utf8") === "OLD-BINARY");

  // Cleanup.
  try { fs.unlinkSync(to);       } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);       } catch (_e) { /* best-effort */ }
}

async function testSwapMissingFromRefused() {
  var dir = _tmp("dir2");
  fs.mkdirSync(dir, { recursive: true });
  var threw = null;
  try {
    await b.selfUpdate.swap({
      from:         path.join(dir, "absent.bin"),
      to:           path.join(dir, "to.bin"),
      backupTo:     path.join(dir, "to.bin.bak"),
      expectedHash: "00",   // present so validation passes; the existsSync(from) check fires first
    });
  } catch (e) { threw = e; }
  check("swap: missing-from refused",
        threw && /selfupdate\/missing-from/.test(threw.code || ""));
  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

async function testSwapHashMismatchRefused() {
  // RED before the fix: swap() renamed `from` into place with no re-check, so an
  // attacker who swapped `from` after selfUpdate.verify passed (or pointed verify
  // at a different inode via a symlink) installed unverified bytes. swap() now
  // re-hashes `from` against expectedHash (verify's hash) immediately before the
  // install and refuses a mismatch.
  var dir = _tmp("dir-tamper");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "blamejs.bin");
  var backupTo = path.join(dir, "blamejs.bin.bak");
  var newPath  = path.join(dir, "blamejs.bin.new");
  fs.writeFileSync(to, Buffer.from("OLD-BINARY"));
  // verify() checked these bytes...
  var verifiedHash = nodeCrypto.createHash("sha3-512").update(Buffer.from("GOOD-BINARY")).digest("hex");
  // ...but `from` was swapped to different bytes after verify.
  fs.writeFileSync(newPath, Buffer.from("TAMPERED-BINARY"));
  var threw = null;
  try {
    await b.selfUpdate.swap({ from: newPath, to: to, backupTo: backupTo, expectedHash: verifiedHash });
  } catch (e) { threw = e; }
  check("swap: from tampered after verify is refused (hash mismatch)",
        threw && /selfupdate\/swap-hash-mismatch/.test(threw.code || ""));
  check("swap: tampered bytes NOT installed", fs.readFileSync(to, "utf8") === "OLD-BINARY");
  try { fs.unlinkSync(to);      } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(newPath); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);      } catch (_e) { /* best-effort */ }
}

async function testSwapSymlinkedFromRefused() {
  // A symlinked `from` must be refused at read (O_NOFOLLOW): hashing the link
  // TARGET while installing the link itself would let an attacker point the link
  // at verified bytes, pass expectedHash, then repoint the installed link at
  // unverified bytes. POSIX-only — Windows symlink creation needs privileges.
  var dir = _tmp("dir-symlink");
  fs.mkdirSync(dir, { recursive: true });
  var real = path.join(dir, "real.bin");
  var link = path.join(dir, "link.bin");
  var to   = path.join(dir, "to.bin");
  fs.writeFileSync(real, Buffer.from("REAL-BYTES"));
  var madeLink = false;
  try { fs.symlinkSync(real, link); madeLink = true; } catch (_e) { /* no symlink privilege */ }
  if (!madeLink) {
    check("swap: symlinked-from test skipped (no symlink privilege)", true);
    try { fs.unlinkSync(real); fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
    return;
  }
  var realHash = nodeCrypto.createHash("sha3-512").update(Buffer.from("REAL-BYTES")).digest("hex");
  var threw = null;
  try {
    await b.selfUpdate.swap({ from: link, to: to, backupTo: path.join(dir, "to.bin.bak"), expectedHash: realHash });
  } catch (e) { threw = e; }
  check("swap: a symlinked from is refused (read with O_NOFOLLOW)",
        threw && /selfupdate\/swap-read-failed/.test(threw.code || ""));
  check("swap: symlinked from did not install", !fs.existsSync(to));
  try { fs.unlinkSync(link); fs.unlinkSync(real); fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

async function testRollbackMissingBackupRefused() {
  var dir = _tmp("dir3");
  fs.mkdirSync(dir, { recursive: true });
  var threw = null;
  try {
    await b.selfUpdate.rollback({
      to:       path.join(dir, "to.bin"),
      backupTo: path.join(dir, "absent.bak"),
    });
  } catch (e) { threw = e; }
  check("rollback: missing backup refused",
        threw && /selfupdate\/missing-backup/.test(threw.code || ""));
  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

// ---- Additional coverage: poll / verify / swap / rollback error,
// adversarial, and option-default branches ----

function _serveStatus(status, body, headers, onReq) {
  return http.createServer(function (req, res) {
    if (onReq) onReq(req);
    res.writeHead(status, headers || {});
    res.end(body == null ? "" : body);
  });
}

async function _pollLocal(port, extra) {
  return b.selfUpdate.poll(Object.assign({
    releasesUrl:      "http://127.0.0.1:" + port + "/releases",
    currentVersion:   "v1.0.0",
    allowedProtocols: ["http:"],
    allowInternal:    true,
  }, extra || {}));
}

async function testPoll304FastPath() {
  // RED before the fix: httpClient.request rejects EVERY non-2xx (304
  // included) as HTTP_ERROR, so poll() never reached its own
  // statusCode===304 branch — the documented If-None-Match "fast no-update"
  // path was dead code and a conditional poll that correctly received a 304
  // threw selfupdate/poll-failed instead of reporting "no update". poll() now
  // passes responseMode:"always-resolve" so it owns status handling.
  var etag = "W/\"cafe-f00d\"";
  var seenHeader = null;
  var s = _serveStatus(304, "", { ETag: etag }, function (req) {
    seenHeader = req.headers["if-none-match"];
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port, { etag: etag });
    check("poll 304: If-None-Match header was sent",   seenHeader === etag);
    check("poll 304: fast-path returns (no throw)",    r && r.available === false);
    check("poll 304: statusCode surfaced",             r.statusCode === 304);
    check("poll 304: etag echoed back",                r.etag === etag);
    check("poll 304: latestTag null on 304",           r.latestTag === null);
  } finally { s.close(); }
}

async function testPollNon2xxSurfacesTypedCode() {
  // With poll owning status handling, a real non-2xx surfaces the intended
  // typed selfupdate/poll-non-2xx branch rather than the generic
  // request-failed catch (also previously dead behind httpClient's throw).
  var s = _serveStatus(503, "busy");
  var port = await b.testing.listenOnRandomPort(s);
  var threw = null;
  try { await _pollLocal(port); } catch (e) { threw = e; }
  s.close();
  check("poll: 503 surfaces selfupdate/poll-non-2xx",
        threw && /selfupdate\/poll-non-2xx/.test(threw.code || ""));
}

async function testPollEmptyArrayFeed() {
  var s = _serveJson([]);
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port);
    check("poll: empty-array feed available=false", r.available === false);
    check("poll: empty-array latestTag null",       r.latestTag === null);
  } finally { s.close(); }
}

async function testPollMalformedBodies() {
  // Malformed JSON body.
  var s1 = _serveStatus(200, "{ not json", { "Content-Type": "application/json" });
  var p1 = await b.testing.listenOnRandomPort(s1);
  var t1 = null;
  try { await _pollLocal(p1); } catch (e) { t1 = e; }
  s1.close();
  check("poll: malformed JSON -> selfupdate/bad-json",
        t1 && /selfupdate\/bad-json/.test(t1.code || ""));

  // Valid JSON but a bare primitive — neither object nor array.
  var s2 = _serveStatus(200, "42", { "Content-Type": "application/json" });
  var p2 = await b.testing.listenOnRandomPort(s2);
  var t2 = null;
  try { await _pollLocal(p2); } catch (e) { t2 = e; }
  s2.close();
  check("poll: JSON primitive -> selfupdate/bad-shape",
        t2 && /selfupdate\/bad-shape/.test(t2.code || ""));

  // Object with no tag_name.
  var s3 = _serveJson({ assets: [] });
  var p3 = await b.testing.listenOnRandomPort(s3);
  var t3 = null;
  try { await _pollLocal(p3); } catch (e) { t3 = e; }
  s3.close();
  check("poll: object missing tag_name -> selfupdate/bad-shape",
        t3 && /selfupdate\/bad-shape/.test(t3.code || ""));
}

async function testPollAvailableNoAssetMatch() {
  // Newer tag but nothing matches the well-known asset/signature shapes.
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [{ name: "NOTES.md", browser_download_url: "https://example.invalid/notes" }],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port);
    check("poll: newer tag with no matching asset -> available=true", r.available === true);
    check("poll: no matching asset -> asset null",     r.asset === null);
    check("poll: no matching signature -> signature null", r.signature === null);
  } finally { s.close(); }
}

async function testPollDigestPassthrough() {
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs.tar.gz",     browser_download_url: "https://example.invalid/a.tgz", size: 100, digest: "sha256:abc123" },
      { name: "blamejs.tar.gz.sig", browser_download_url: "https://example.invalid/a.sig", size: 64,  digest: "sha256:sigdig" },
    ],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port);
    check("poll: asset digest passed through verbatim",     r.asset && r.asset.digest === "sha256:abc123");
    check("poll: signature digest passed through verbatim", r.signature && r.signature.digest === "sha256:sigdig");
    check("poll: asset size surfaced",                      r.asset && r.asset.size === 100);
  } finally { s.close(); }
}

async function testPollStringPatterns() {
  // assetPattern / signaturePattern as substrings — matched via indexOf,
  // never compiled, so no ReDoS surface.
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "custom-runtime.pkg",     browser_download_url: "https://example.invalid/rt" },
      { name: "custom-runtime.pkg.sig", browser_download_url: "https://example.invalid/rt.sig" },
    ],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port, { assetPattern: ".pkg", signaturePattern: ".pkg.sig" });
    check("poll: string signaturePattern selects the sig", r.signature && r.signature.name === "custom-runtime.pkg.sig");
    check("poll: string assetPattern selects the asset",   r.asset && r.asset.name === "custom-runtime.pkg");
  } finally { s.close(); }
}

function testPollOptValidation() {
  // Config-time refusals — each throws before any request is issued.
  var cases = [
    [{ currentVersion: "1.0.0" },                                                       "bad-releases-url",      "missing releasesUrl"],
    [{ releasesUrl: "https://x/r" },                                                    "bad-current-version",   "missing currentVersion"],
    [{ releasesUrl: "::::not a url", currentVersion: "1.0.0" },                         "bad-releases-url",      "unparseable releasesUrl"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", maxBytes: -1 },             "bad-max-bytes",         "negative maxBytes"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", maxBytes: Infinity },       "bad-max-bytes",         "Infinity maxBytes"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", timeoutMs: 0 },             "bad-timeout",           "zero timeoutMs"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", headers: [] },              "bad-headers",           "array headers"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", etag: 123 },                "bad-etag",              "numeric etag"],
    [{ releasesUrl: "http://x/r",  currentVersion: "1.0.0", allowedProtocols: ["http:", 1] }, "bad-allowed-protocols", "non-string protocol element"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", assetPattern: 5 },          "bad-asset-pattern",     "numeric assetPattern"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", signaturePattern: 5 },      "bad-sig-pattern",       "numeric signaturePattern"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", signaturePattern: /((a)+)+$/ }, "unsafe-sig-pattern", "ReDoS signaturePattern"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", bogusOpt: 1 },              "bad-opts",              "unknown opt"],
  ];
  return cases.reduce(function (chain, c) {
    return chain.then(function () {
      return b.selfUpdate.poll(c[0]).then(
        function () { check("poll validation (" + c[2] + ") should throw", false); },
        function (e) {
          check("poll validation: " + c[2] + " -> selfupdate/" + c[1],
                e && new RegExp("selfupdate/" + c[1]).test(e.code || ""));
        });
    });
  }, Promise.resolve());
}

async function testVerifyErrorPaths() {
  // Missing asset file -> read-failed.
  var t1 = null;
  try {
    await b.selfUpdate.verify({
      assetPath:     _tmp("absent-asset.bin"),
      signaturePath: _tmp("absent.sig"),
      pubkeyPem:     "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
    });
  } catch (e) { t1 = e; }
  check("verify: missing asset file -> selfupdate/read-failed",
        t1 && /selfupdate\/read-failed/.test(t1.code || ""));

  var keys  = _newSigningKeys();
  var pubPem = keys.publicKey.export({ type: "spki", format: "pem" });
  var asset = Buffer.from("verify-error-path payload");
  var sig   = _detachedSign(keys.privateKey, asset);
  var aPath = _tmp("verr-asset.bin");
  var sPath = _tmp("verr-asset.sig");
  fs.writeFileSync(aPath, asset);
  fs.writeFileSync(sPath, sig);
  try {
    // Garbage PEM makes crypto.verify throw -> verify-failed (typed).
    var t2 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: "not a valid pem" });
    } catch (e) { t2 = e; }
    check("verify: garbage pubkey -> selfupdate/verify-failed",
          t2 && /selfupdate\/verify-failed/.test(t2.code || ""));

    // Unsupported digest algorithm -> config-time bad-hash-algo.
    var t3 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, hashAlgo: "md5" });
    } catch (e) { t3 = e; }
    check("verify: unsupported hashAlgo -> selfupdate/bad-hash-algo",
          t3 && /selfupdate\/bad-hash-algo/.test(t3.code || ""));

    // Missing required pubkeyPem -> bad-pubkey.
    var t4 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath });
    } catch (e) { t4 = e; }
    check("verify: missing pubkeyPem -> selfupdate/bad-pubkey",
          t4 && /selfupdate\/bad-pubkey/.test(t4.code || ""));

    // A valid non-default digest algorithm is honored end-to-end.
    var vv = await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, hashAlgo: "sha-256" });
    check("verify: custom hashAlgo verified",       vv.verified === true);
    check("verify: custom hashAlgo reported back",  vv.alg === "sha-256");
    check("verify: sha-256 digest is 64 lc hex",    /^[0-9a-f]{64}$/.test(vv.hash));
  } finally {
    try { fs.unlinkSync(aPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sPath); } catch (_e) { /* best-effort */ }
  }
}

async function testSwapFreshInstall() {
  // No pre-existing `to` — hadOriginal=false, so no backup is written and the
  // verified bytes are installed from memory.
  var dir = _tmp("dir-fresh");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "app.bin");
  var backupTo = path.join(dir, "app.bin.bak");
  var from     = path.join(dir, "app.bin.new");
  var bytes    = Buffer.from("FRESH-INSTALL-BYTES");
  fs.writeFileSync(from, bytes);
  var hash = nodeCrypto.createHash("sha3-512").update(bytes).digest("hex");
  var rs = await b.selfUpdate.swap({ from: from, to: to, backupTo: backupTo, expectedHash: hash });
  check("swap fresh: ok=true",             rs.ok === true);
  check("swap fresh: installed bytes",     fs.readFileSync(to, "utf8") === "FRESH-INSTALL-BYTES");
  check("swap fresh: no backup written",   !fs.existsSync(backupTo));
  check("swap fresh: from consumed",       !fs.existsSync(from));
  try { fs.unlinkSync(to); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

async function testSwapCustomHashAlgoRoundTrip() {
  var dir = _tmp("dir-algo");
  fs.mkdirSync(dir, { recursive: true });
  var to    = path.join(dir, "bin");
  var from  = path.join(dir, "bin.new");
  var bytes = Buffer.from("ALGO-ROUNDTRIP");
  fs.writeFileSync(to, Buffer.from("OLD"));
  fs.writeFileSync(from, bytes);
  var h256 = nodeCrypto.createHash("sha-256").update(bytes).digest("hex");
  var rs = await b.selfUpdate.swap({ from: from, to: to, backupTo: path.join(dir, "bin.bak"),
    expectedHash: h256, hashAlgo: "sha-256" });
  check("swap sha-256: ok=true",     rs.ok === true);
  check("swap sha-256: installed",   fs.readFileSync(to, "utf8") === "ALGO-ROUNDTRIP");

  // A sha-256 expectedHash checked against swap's default sha3-512 re-hash
  // fails closed (algo divergence must never install).
  fs.writeFileSync(to, Buffer.from("OLD2"));
  fs.writeFileSync(from, bytes);
  var t2 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: to, backupTo: path.join(dir, "bin.bak"), expectedHash: h256 });
  } catch (e) { t2 = e; }
  check("swap: algo-divergent expectedHash refused",
        t2 && /selfupdate\/swap-hash-mismatch/.test(t2.code || ""));
  check("swap: algo-divergence left original intact", fs.readFileSync(to, "utf8") === "OLD2");
  try { fs.unlinkSync(to);   } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(from); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);   } catch (_e) { /* best-effort */ }
}

async function testSwapRollbackOptValidation() {
  var dir = _tmp("dir-optval");
  fs.mkdirSync(dir, { recursive: true });
  var from = path.join(dir, "src.bin");
  fs.writeFileSync(from, Buffer.from("X"));

  // The verify->swap integrity binding is mandatory: omitting expectedHash
  // is refused at config-time (never an opt-in security check).
  var t1 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"), backupTo: path.join(dir, "to.bak") });
  } catch (e) { t1 = e; }
  check("swap: missing expectedHash -> selfupdate/bad-expected-hash",
        t1 && /selfupdate\/bad-expected-hash/.test(t1.code || ""));

  var t2 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), expectedHash: "00", hashAlgo: "md5" });
  } catch (e) { t2 = e; }
  check("swap: unsupported hashAlgo -> selfupdate/bad-hash-algo",
        t2 && /selfupdate\/bad-hash-algo/.test(t2.code || ""));

  var t3 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), expectedHash: "00", bogus: 1 });
  } catch (e) { t3 = e; }
  check("swap: unknown opt -> selfupdate/bad-opts",
        t3 && /selfupdate\/bad-opts/.test(t3.code || ""));

  // maxBytes is a DECLARED swap opt (the body re-reads the from-bytes under it,
  // matching what selfUpdate.verify accepted): a bad value is refused with the
  // specific bad-max-bytes code, not the generic unknown-opt bad-opts.
  var t3b = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), expectedHash: "00", maxBytes: -1 });
  } catch (e) { t3b = e; }
  check("swap: bad maxBytes -> selfupdate/bad-max-bytes (declared opt, matches verify)",
        t3b && /selfupdate\/bad-max-bytes/.test(t3b.code || ""));

  // maxBytes is NOT a rollback opt (rollback re-reads nothing), so it stays
  // unknown there — the declaration is swap-only.
  var t3c = null;
  try {
    await b.selfUpdate.rollback({ to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), maxBytes: 999 });
  } catch (e) { t3c = e; }
  check("rollback: maxBytes is not a rollback opt -> selfupdate/bad-opts",
        t3c && /selfupdate\/bad-opts/.test(t3c.code || ""));

  var t4 = null;
  try {
    await b.selfUpdate.rollback({ backupTo: path.join(dir, "to.bak") });
  } catch (e) { t4 = e; }
  check("rollback: missing to -> selfupdate/bad-to",
        t4 && /selfupdate\/bad-to/.test(t4.code || ""));

  try { fs.unlinkSync(from); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);   } catch (_e) { /* best-effort */ }
}

// selfUpdate.poll dials the releases endpoint through the shared httpClient
// keep-alive transport pool; a cached client socket finalizes its destroy on a
// later event-loop turn, past the forked worker's grace window. Reset the pool,
// then poll until every TCP handle (client sockets + any fixture-server accept
// socket) has actually drained so none outlives run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "self-update: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    testSurface();
    testCompareTags();
    await testPollRejectsBadOpts();
    await testPollRejectsUnsafeAssetPattern();
    await testPollAvailableAndUpToDate();
    await testPollArrayShape();
    await testPollNon2xxRefused();
    await testPoll304FastPath();
    await testPollNon2xxSurfacesTypedCode();
    await testPollEmptyArrayFeed();
    await testPollMalformedBodies();
    await testPollAvailableNoAssetMatch();
    await testPollDigestPassthrough();
    await testPollStringPatterns();
    await testPollOptValidation();
    await testVerifyPassFail();
    await testVerifyErrorPaths();
    await testSwapAndRollback();
    await testSwapMissingFromRefused();
    await testSwapHashMismatchRefused();
    await testSwapSymlinkedFromRefused();
    await testSwapFreshInstall();
    await testSwapCustomHashAlgoRoundTrip();
    await testSwapRollbackOptValidation();
    await testRollbackMissingBackupRefused();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e.message); process.exit(1); }
  );
}
