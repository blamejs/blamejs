"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _captureCtx() {
  var stdout = [];
  var stderr = [];
  return {
    stdout: { write: function (s) { stdout.push(String(s)); } },
    stderr: { write: function (s) { stderr.push(String(s)); } },
    env:    {},
    cwd:    process.cwd(),
    out:    function () { return stdout.join(""); },
    err:    function () { return stderr.join(""); },
  };
}

async function run() {
  var dataDir = _tmpDir("blamejs-cli-mtls");
  var base = ["--data-dir", dataDir, "--vault-mode", "plaintext"];

  // ---- arg validation up front ----
  var ctxA = _captureCtx();
  var cA = await cli.main(["mtls"], ctxA);
  check("no subcommand: usage on stderr, returns 2",
        cA === 2 && /Usage: blamejs mtls/.test(ctxA.err()));

  var ctxB = _captureCtx();
  var cB = await cli.main(["mtls", "frobnicate"], ctxB);
  check("unknown subcommand: returns 2",
        cB === 2 && /unknown subcommand/.test(ctxB.err()));

  var ctxC = _captureCtx();
  var cC = await cli.main(["help", "mtls"], ctxC);
  check("help mtls: prints MTLS_USAGE",
        cC === 0 && /Usage: blamejs mtls/.test(ctxC.out()));

  var ctxD = _captureCtx();
  var cD = await cli.main(["mtls", "status"], ctxD);
  check("status without --data-dir: returns 2",
        cD === 2 && /--data-dir/.test(ctxD.err()));

  // ---- status against a fresh data-dir (no CA on disk) ----
  var ctx1 = _captureCtx();
  var c1 = await cli.main(["mtls", "status"].concat(base), ctx1);
  check("status (no CA): returns 0",                 c1 === 0);
  check("status (no CA): announces 'CA exists: no'", /CA exists:\s+no/.test(ctx1.out()));
  check("status (no CA): hints at init",             /run 'blamejs mtls init'/.test(ctx1.out()));

  // ---- show-cert against a fresh data-dir errors clearly ----
  var ctx2 = _captureCtx();
  var c2 = await cli.main(["mtls", "show-cert"].concat(base), ctx2);
  check("show-cert (no CA): non-zero",                c2 !== 0);
  check("show-cert (no CA): points at the missing path",
        /no CA on disk/.test(ctx2.err()));

  // ---- init (engine not bundled) fails loud with the diagnostic ----
  var ctx3 = _captureCtx();
  var c3 = await cli.main(["mtls", "init"].concat(base), ctx3);
  check("init (no engine): non-zero",                 c3 !== 0);
  check("init (no engine): names the engine requirement",
        /requires opts\.engine/.test(ctx3.err()));
  check("init (no engine): mentions the future-slice plan",
        /future slice|@peculiar\/x509/.test(ctx3.err()));

  // ---- issue (engine not bundled) requires both --subject and engine ----
  var ctx4 = _captureCtx();
  var c4 = await cli.main(["mtls", "issue"].concat(base), ctx4);
  check("issue without --subject: returns 2",
        c4 === 2 && /--subject/.test(ctx4.err()));

  var ctx5 = _captureCtx();
  var c5 = await cli.main(["mtls", "issue"].concat(base).concat(["--subject", "CN=client-1"]), ctx5);
  check("issue with --subject (no engine): non-zero",  c5 !== 0);
  check("issue (no engine): names the engine requirement",
        /requires opts\.engine/.test(ctx5.err()));

  // ---- issue-p12 demands both --subject and --password ----
  var ctx6 = _captureCtx();
  var c6 = await cli.main(["mtls", "issue-p12"].concat(base).concat(["--subject", "CN=x"]), ctx6);
  check("issue-p12 without --password: returns 2",
        c6 === 2 && /--password/.test(ctx6.err()));

  // ---- bad --vault-mode ----
  var ctx7 = _captureCtx();
  var c7 = await cli.main(["mtls", "status", "--data-dir", dataDir, "--vault-mode", "yolo"], ctx7);
  check("bad --vault-mode: returns 2",
        c7 === 2 && /--vault-mode/.test(ctx7.err()));

  // ---- bad --sealed-mode ----
  var ctx8 = _captureCtx();
  var c8 = await cli.main(["mtls", "status"].concat(base).concat(["--sealed-mode", "yolo"]), ctx8);
  check("bad --sealed-mode: returns 2",
        c8 === 2 && /--sealed-mode/.test(ctx8.err()));

  fs.rmSync(dataDir, { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
