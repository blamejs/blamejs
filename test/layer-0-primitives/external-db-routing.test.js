"use strict";
/**
 * b.externalDb v0.6.3 additions:
 *   - configurePool(name, opts) — runtime pool resize
 *   - adapters.connectAs(connect, opts) — Postgres role-aware connect wrapper
 *   - read/write namespace + replica routing
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var _makeFakeDriver = helpers._makeFakeDriver;

function _initWithSingle(driver) {
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      main: { connect: driver.connect, query: driver.query, close: driver.close, ping: driver.ping },
    },
  });
}

async function run() {
  // ---- configurePool ----
  var d = _makeFakeDriver();
  _initWithSingle(d);
  b.externalDb.configurePool("main", { min: 2, max: 50, idleTimeoutMs: 60000 });
  // No throw — happy path. The new bounds take effect on next acquire.
  check("configurePool: happy path",  true);

  // Tier-A on bad opts.
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("configurePool rejects: " + label,
          threw && codeRe.test(threw.code || ""));
  }
  rejects("unknown backend",      function () { b.externalDb.configurePool("nope", { max: 10 }); }, /UNKNOWN_BACKEND/);
  rejects("unknown opt",          function () { b.externalDb.configurePool("main", { bogus: 1 }); }, /INVALID_CONFIG/);
  rejects("non-positive max",     function () { b.externalDb.configurePool("main", { max: 0 }); },  /INVALID_CONFIG/);
  rejects("non-integer max",      function () { b.externalDb.configurePool("main", { max: 1.5 }); }, /INVALID_CONFIG/);
  rejects("min > max",            function () { b.externalDb.configurePool("main", { min: 50, max: 10 }); }, /INVALID_CONFIG/);
  rejects("Infinity max",         function () { b.externalDb.configurePool("main", { max: Infinity }); }, /INVALID_CONFIG/);
  rejects("non-string name",      function () { b.externalDb.configurePool(42, {}); }, /INVALID_CONFIG/);

  // ---- adapters.connectAs ----
  // Track every SQL the driver sees so we can assert SET statements.
  function _instrumentingDriver() {
    var seen = [];
    return {
      seen: seen,
      connect: async function () { return { id: "client" }; },
      query:   async function (_client, sql, _params) {
        seen.push(sql);
        return { rows: [], rowCount: 0 };
      },
      close:   async function () {},
    };
  }
  var d2 = _instrumentingDriver();
  var wrappedConnect = b.externalDb.adapters.connectAs(d2.connect, {
    query:              d2.query,
    role:               "analytics_user",
    searchPath:         ["analytics", "public"],
    applicationName:    "wiki:analytics",
    statementTimeoutMs: 30000,
    gucs: { idle_in_transaction_session_timeout: "60s" },
  });
  await wrappedConnect();
  check("connectAs: SET ROLE issued",
        d2.seen.some(function (s) { return s === 'SET ROLE "analytics_user"'; }));
  check("connectAs: SET search_path issued",
        d2.seen.some(function (s) { return s === 'SET search_path TO "analytics", "public"'; }));
  check("connectAs: SET application_name issued",
        d2.seen.some(function (s) { return s === "SET application_name TO 'wiki:analytics'"; }));
  check("connectAs: SET statement_timeout issued",
        d2.seen.some(function (s) { return s === "SET statement_timeout TO 30000"; }));
  check("connectAs: SET custom GUC issued",
        d2.seen.some(function (s) { return s === 'SET "idle_in_transaction_session_timeout" TO \'60s\''; }));

  // Identifier validation rejects bad shape at config time.
  function rejectsCa(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("connectAs rejects: " + label,
          threw && (codeRe.test(threw.code || "") || codeRe.test(threw.message || "")));
  }
  var rawConnect = function () {};
  var rawQuery   = function () {};
  rejectsCa("bad role identifier",
    function () { b.externalDb.adapters.connectAs(rawConnect,
      { query: rawQuery, role: "bad name with spaces" }); }, /sql\/bad-shape|INVALID/);
  rejectsCa("bad searchPath segment",
    function () { b.externalDb.adapters.connectAs(rawConnect,
      { query: rawQuery, searchPath: ["1bad"] }); }, /sql\/bad-shape|INVALID/);
  rejectsCa("non-positive statementTimeoutMs",
    function () { b.externalDb.adapters.connectAs(rawConnect,
      { query: rawQuery, statementTimeoutMs: 0 }); }, /INVALID_CONFIG/);
  rejectsCa("missing query fn",
    function () { b.externalDb.adapters.connectAs(rawConnect, { role: "x" }); }, /INVALID_CONFIG/);
  // SQL-standard single-quote escaping for application_name string literal.
  d2.seen.length = 0;
  var wcEsc = b.externalDb.adapters.connectAs(d2.connect, {
    query: d2.query, applicationName: "wiki'with'quotes",
  });
  await wcEsc();
  check("connectAs: applicationName single-quotes escaped per SQL standard",
        d2.seen.some(function (s) { return s === "SET application_name TO 'wiki''with''quotes'"; }));

  // ---- Read-replica routing ----
  // Two replicas + primary. read.query must round-robin across replicas.
  b.externalDb._resetForTest();
  function _trackingDriver(label) {
    var seen = [];
    return {
      label: label,
      seen:  seen,
      connect: async function () { return { id: label + "-client" }; },
      query:   async function (_c, sql, _p) {
        seen.push(sql);
        if (/^SELECT 1$/i.test(sql)) return { rows: [], rowCount: 0 };
        return { rows: [{ from: label }], rowCount: 1 };
      },
      close:   async function () {},
      ping:    async function () { return true; },
    };
  }
  var primary  = _trackingDriver("primary");
  var replica1 = _trackingDriver("replica1");
  var replica2 = _trackingDriver("replica2");
  b.externalDb.init({
    backends: {
      main: {
        connect: primary.connect, query: primary.query, close: primary.close, ping: primary.ping,
        replicas: [
          { connect: replica1.connect, query: replica1.query, close: replica1.close, weight: 1 },
          { connect: replica2.connect, query: replica2.query, close: replica2.close, weight: 1 },
        ],
      },
    },
  });

  // 2 reads should hit both replicas at least once (weights are equal).
  await b.externalDb.read.query("SELECT 1");
  await b.externalDb.read.query("SELECT 1");
  await b.externalDb.read.query("SELECT 1");
  await b.externalDb.read.query("SELECT 1");
  check("read.query: hit replica1",
        replica1.seen.length > 0);
  check("read.query: hit replica2",
        replica2.seen.length > 0);
  check("read.query: did NOT hit primary on healthy replicas",
        primary.seen.length === 0);

  // write.query goes to primary.
  await b.externalDb.write.query("INSERT INTO x (a) VALUES (1)");
  check("write.query: routes to primary",
        primary.seen.some(function (s) { return /INSERT INTO x/.test(s); }));

  // legacy externalDb.query() unchanged — primary.
  await b.externalDb.query("INSERT INTO y (b) VALUES (2)");
  check("externalDb.query: primary unchanged",
        primary.seen.some(function (s) { return /INSERT INTO y/.test(s); }));

  // Read on a backend with NO replicas falls back to primary.
  b.externalDb._resetForTest();
  var solo = _trackingDriver("solo");
  b.externalDb.init({
    backends: {
      single: { connect: solo.connect, query: solo.query, close: solo.close, ping: solo.ping },
    },
  });
  await b.externalDb.read.query("SELECT 1");
  check("read.query: no replicas configured → primary",
        solo.seen.some(function (s) { return /SELECT 1/.test(s); }));

  // ---- Tier-A on replicas config ----
  b.externalDb._resetForTest();
  function rejectsReplicas(label, replicasCfg, codeRe) {
    var threw = null;
    try {
      b.externalDb.init({
        backends: {
          x: {
            connect: primary.connect, query: primary.query, close: primary.close,
            replicas: replicasCfg,
          },
        },
      });
    } catch (e) { threw = e; }
    check("replicas rejects: " + label,
          threw && codeRe.test(threw.code || ""));
    b.externalDb._resetForTest();
  }
  rejectsReplicas("empty array", [], /INVALID_CONFIG/);
  rejectsReplicas("missing connect",
    [{ query: replica1.query }], /INVALID_CONFIG/);
  rejectsReplicas("missing query",
    [{ connect: replica1.connect }], /INVALID_CONFIG/);
  rejectsReplicas("non-positive weight",
    [{ connect: replica1.connect, query: replica1.query, weight: 0 }], /INVALID_CONFIG/);
  rejectsReplicas("non-integer weight",
    [{ connect: replica1.connect, query: replica1.query, weight: 1.5 }], /INVALID_CONFIG/);

  // ---- Final clean ----
  b.externalDb._resetForTest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
