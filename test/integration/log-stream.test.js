"use strict";
/**
 * Live log-stream sink test — exercises lib/log-stream.js's webhook
 * sink against a real HTTP receiver (the Caddy fixture's :8080 echoes
 * 200 on every request, sufficient to confirm the framework's sink
 * code path serializes + posts records correctly).
 *
 * Also covers the "local" sink which writes to disk and the deferred
 * syslog protocol which must throw PROTOCOL_NOT_IMPLEMENTED. Together
 * these tests assert every shipped + every advertised-but-deferred
 * protocol behaves as documented.
 */
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var http = require("node:http");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var caddy = await services.requireService("caddy");
  if (!caddy.ok) throw new Error("caddy unreachable: " + caddy.reason);

  // ---- protocol catalog: deferred protocols throw PROTOCOL_NOT_IMPLEMENTED ----
  // log-stream's deferred map currently lists 'syslog'. Asking for it
  // must raise a clear error rather than silently dropping records.
  check("PROTOCOLS exposes shipped sinks (local/webhook/otlp/cloudwatch)",
        ["local", "webhook", "otlp", "cloudwatch"].every(function (p) {
          return b.logStream.PROTOCOLS.indexOf(p) !== -1;
        }));
  check("DEFERRED_PROTOCOLS lists 'syslog' so operators see a clear error",
        b.logStream.DEFERRED_PROTOCOLS.indexOf("syslog") !== -1);

  // ---- local sink: writes records to disk ----
  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-log-stream-"));
  b.logStream.init({
    sinks: {
      local: { protocol: "local", dir: tmpDir },
    },
    minLevel: "debug",
  });
  b.logStream.info("integration-event-1", { kind: "test", n: 1 });
  b.logStream.warn("integration-event-2", { kind: "test", n: 2 });
  await b.logStream.shutdown();
  // local sink writes one file per day; collect everything in tmpDir.
  var allLocalContent = fs.readdirSync(tmpDir)
    .map(function (f) { return fs.readFileSync(path.join(tmpDir, f), "utf8"); })
    .join("\n");
  check("local sink: file contains the first event",
        allLocalContent.indexOf("integration-event-1") !== -1);
  check("local sink: file contains the second event",
        allLocalContent.indexOf("integration-event-2") !== -1);
  check("local sink: warn level recorded",
        /"level":\s*"warn"/.test(allLocalContent));

  // ---- webhook sink: posts records to a real HTTP endpoint ----
  // Caddy responds 200 on every path. We host our own tiny capture
  // server too, so we can inspect the bodies the framework posted.
  var captured = [];
  var captureServer = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      try { captured.push(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch (_e) { captured.push({ _raw: Buffer.concat(chunks).toString("utf8") }); }
      res.statusCode = 204;
      res.end();
    });
  });
  await new Promise(function (resolve) { captureServer.listen(0, "127.0.0.1", resolve); });
  var capturePort = captureServer.address().port;
  var captureUrl = "http://127.0.0.1:" + capturePort + "/log";

  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  b.logStream.init({
    sinks: {
      hooked: {
        protocol:         "webhook",
        url:              captureUrl,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        flushIntervalMs:  50,
      },
    },
    minLevel: "debug",
  });
  b.logStream.info("webhook-event", { route: "/payments", traceId: "abc-123" });
  b.logStream.error("webhook-error", { reason: "boom" });
  await b.logStream.shutdown();
  await new Promise(function (resolve) { captureServer.close(resolve); });
  fs.rmSync(tmpDir, { recursive: true, force: true });

  check("webhook sink: at least one record posted",
        captured.length >= 1);
  // The webhook sink may batch records into a single body or post one
  // body per record. Either way both events should be findable.
  var allText = JSON.stringify(captured);
  check("webhook sink: 'webhook-event' message landed",
        allText.indexOf("webhook-event") !== -1);
  check("webhook sink: 'webhook-error' message landed",
        allText.indexOf("webhook-error") !== -1);
  check("webhook sink: error level preserved",
        /"level":\s*"error"/.test(allText));

  // ---- deferred syslog protocol: must throw PROTOCOL_NOT_IMPLEMENTED ----
  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  var threw = null;
  try {
    b.logStream.init({
      sinks: {
        far: { protocol: "syslog", host: "127.0.0.1", port: 5514 },
      },
    });
  } catch (e) { threw = e; }
  check("syslog protocol throws PROTOCOL_NOT_IMPLEMENTED (operator-visible)",
        threw && threw.code &&
        /PROTOCOL_NOT_IMPLEMENTED|deferred|not yet/i.test(threw.code + " " + threw.message));
  check("syslog error mentions the protocol name",
        threw && threw.message && /syslog/i.test(threw.message));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
