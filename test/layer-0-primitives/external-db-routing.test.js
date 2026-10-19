// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

  // configurePool rejects bad opts at the call site.
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("configurePool rejects: " + label,
          threw && codeRe.test(threw.code || ""));
  }
  rejects("unknown backend",      function () { b.externalDb.configurePool("nope", { max: 10 }); }, /external-db\/unknown-backend/);
  rejects("unknown opt",          function () { b.externalDb.configurePool("main", { bogus: 1 }); }, /external-db\/invalid-config/);
  rejects("non-positive max",     function () { b.externalDb.configurePool("main", { max: 0 }); },  /external-db\/invalid-config/);
  rejects("non-integer max",      function () { b.externalDb.configurePool("main", { max: 1.5 }); }, /external-db\/invalid-config/);
  rejects("min > max",            function () { b.externalDb.configurePool("main", { min: 50, max: 10 }); }, /external-db\/invalid-config/);
  rejects("Infinity max",         function () { b.externalDb.configurePool("main", { max: Infinity }); }, /external-db\/invalid-config/);
  rejects("non-string name",      function () { b.externalDb.configurePool(42, {}); }, /external-db\/invalid-config/);

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
      { query: rawQuery, statementTimeoutMs: 0 }); }, /external-db\/invalid-config/);
  rejectsCa("missing query fn",
    function () { b.externalDb.adapters.connectAs(rawConnect, { role: "x" }); }, /external-db\/invalid-config/);
  // SQL-standard single-quote escaping for application_name string literal.
  d2.seen.length = 0;
  var wcEsc = b.externalDb.adapters.connectAs(d2.connect, {
    query: d2.query, applicationName: "wiki'with'quotes",
  });
  await wcEsc();
  check("connectAs: applicationName single-quotes escaped per SQL standard",
        d2.seen.some(function (s) { return s === "SET application_name TO 'wiki''with''quotes'"; }));

  // A client whose session SETs fail is disposed, not leaked and not
  // recycled. SET ROLE succeeds, SET search_path is rejected: the client now
  // carries a half-configured session, so it must be destroyed. pg-pool
  // destroys a connection when release() receives a truthy argument.
  function _failingSetDriver() {
    var st = { released: [], ended: 0, closed: [] };
    st.client = {
      release: function (arg) { st.released.push(arg); },
      end:     async function () { st.ended += 1; },
    };
    st.connect = async function () { return st.client; };
    st.setErr = new Error('schema "nope" does not exist');
    st.setErr.code = "3F000";
    st.query = async function (_c, sql) {
      if (/^SET search_path/.test(sql)) throw st.setErr;
      return { rows: [], rowCount: 0 };
    };
    return st;
  }
  var fd1 = _failingSetDriver();
  var wcFail = b.externalDb.adapters.connectAs(fd1.connect, {
    query: fd1.query, role: "analytics_user", searchPath: ["nope"],
  });
  var fail1 = null;
  try { await wcFail(); } catch (e) { fail1 = e; }
  check("connectAs: a failed SET rejects with the SET error", fail1 === fd1.setErr);
  check("connectAs: a client whose SET failed is released exactly once with a truthy argument",
        fd1.released.length === 1 && !!fd1.released[0], JSON.stringify(fd1.released));
  check("connectAs: release(err) is used rather than end() when the client has release",
        fd1.ended === 0);

  var fd2 = _failingSetDriver();
  var closeCalls = [];
  var wcClose = b.externalDb.adapters.connectAs(fd2.connect, {
    query: fd2.query, role: "analytics_user", searchPath: ["nope"],
    close: function (client, err) { closeCalls.push({ client: client, err: err }); },
  });
  var fail2 = null;
  try { await wcClose(); } catch (e) { fail2 = e; }
  check("connectAs: opts.close receives (client, err) for a client whose SET failed",
        closeCalls.length === 1 && closeCalls[0].client === fd2.client &&
        closeCalls[0].err === fd2.setErr && fail2 === fd2.setErr);
  check("connectAs: opts.close replaces the default release(err)",
        fd2.released.length === 0 && fd2.ended === 0);

  var fd3 = _failingSetDriver();
  var wcCloseThrows = b.externalDb.adapters.connectAs(fd3.connect, {
    query: fd3.query, searchPath: ["nope"],
    close: async function () { throw new Error("close failed"); },
  });
  var fail3 = null;
  try { await wcCloseThrows(); } catch (e) { fail3 = e; }
  check("connectAs: a throwing opts.close does not replace the SET error", fail3 === fd3.setErr);

  var fd4 = _failingSetDriver();
  delete fd4.client.release;
  var wcEnd = b.externalDb.adapters.connectAs(fd4.connect, { query: fd4.query, searchPath: ["nope"] });
  var fail4 = null;
  try { await wcEnd(); } catch (e) { fail4 = e; }
  check("connectAs: a client with no release() is ended", fail4 === fd4.setErr && fd4.ended === 1);

  // Disposal does not hold back the rejection: a client whose end() never
  // settles, or an operator close() that never settles, still lets the
  // wrapped connect reject with the SET error.
  async function _settlesWithin(promise, ms) {
    var outcome = { settled: false, err: null };
    promise.then(function () { outcome.settled = true; },
      function (e) { outcome.settled = true; outcome.err = e; });
    try {
      await helpers.waitUntil(function () { return outcome.settled; },
        { timeoutMs: ms, label: "connectAs: wrapped connect settles" });
    } catch (_e) { /* outcome.settled stays false */ }
    return outcome;
  }
  var fd5 = _failingSetDriver();
  delete fd5.client.release;
  fd5.client.end = function () { fd5.ended += 1; return new Promise(function () {}); };
  var hung5 = await _settlesWithin(
    b.externalDb.adapters.connectAs(fd5.connect, { query: fd5.query, searchPath: ["nope"] })(), 2000);
  check("connectAs: a client whose end() never settles does not hold back the SET error",
        hung5.settled && hung5.err === fd5.setErr && fd5.ended === 1, JSON.stringify(hung5));
  var fd6 = _failingSetDriver();
  var hung6 = await _settlesWithin(b.externalDb.adapters.connectAs(fd6.connect, {
    query: fd6.query, searchPath: ["nope"],
    close: function () { return new Promise(function () {}); },
  })(), 2000);
  check("connectAs: an opts.close that never settles does not hold back the SET error",
        hung6.settled && hung6.err === fd6.setErr, JSON.stringify(hung6));
  var fd7 = _failingSetDriver();
  var fail7 = null;
  try {
    await b.externalDb.adapters.connectAs(fd7.connect, {
      query: fd7.query, searchPath: ["nope"],
      close: function () { throw new Error("close threw synchronously"); },
    })();
  } catch (e) { fail7 = e; }
  check("connectAs: an opts.close that throws synchronously does not replace the SET error",
        fail7 === fd7.setErr, fail7 && fail7.message);

  rejectsCa("non-function close",
    function () { b.externalDb.adapters.connectAs(rawConnect,
      { query: rawQuery, close: "nope" }); }, /external-db\/invalid-config/);

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

  // ---- replicas config validation rejects bad shapes at init ----
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
  rejectsReplicas("empty array", [], /external-db\/invalid-config/);
  rejectsReplicas("missing connect",
    [{ query: replica1.query }], /external-db\/invalid-config/);
  rejectsReplicas("missing query",
    [{ connect: replica1.connect }], /external-db\/invalid-config/);
  rejectsReplicas("non-positive weight",
    [{ connect: replica1.connect, query: replica1.query, weight: 0 }], /external-db\/invalid-config/);
  rejectsReplicas("non-integer weight",
    [{ connect: replica1.connect, query: replica1.query, weight: 1.5 }], /external-db\/invalid-config/);

  // ---- dbRoleBackends + ALS-routed backend pick (v0.6.6) ----
  b.externalDb._resetForTest();
  var appDriver       = _trackingDriver("app");
  var analyticsDriver = _trackingDriver("analytics");
  b.externalDb.init({
    backends: {
      appMain:       {
        connect: appDriver.connect,       query: appDriver.query,
        close:   appDriver.close,         ping:  appDriver.ping,
      },
      analyticsMain: {
        connect: analyticsDriver.connect, query: analyticsDriver.query,
        close:   analyticsDriver.close,   ping:  analyticsDriver.ping,
      },
    },
    defaultBackend:  "appMain",
    dbRoleBackends:  {
      app_user:       "appMain",
      analytics_user: "analyticsMain",
    },
  });

  // Default: no ALS role → defaultBackend.
  await b.externalDb.query("SELECT 1");
  check("dbRoleBackends: no role → defaultBackend",
    appDriver.seen.length > 0 && analyticsDriver.seen.length === 0);

  // runAs("analytics_user") routes read.query to analyticsMain.
  appDriver.seen.length = 0;
  analyticsDriver.seen.length = 0;
  await b.externalDb.runAs("analytics_user", async function () {
    await b.externalDb.read.query("SELECT 1");
    check("runAs: currentRole inside scope",
      b.externalDb.currentRole() === "analytics_user");
  });
  check("runAs: read.query routed by ALS role",
    analyticsDriver.seen.length > 0 && appDriver.seen.length === 0);
  check("runAs: ALS clears outside scope",
    b.externalDb.currentRole() === null);

  // Explicit { backend: ... } always wins over ALS role.
  appDriver.seen.length = 0;
  analyticsDriver.seen.length = 0;
  await b.externalDb.runAs("analytics_user", async function () {
    await b.externalDb.query("SELECT 1", [], { backend: "appMain" });
  });
  check("dbRoleBackends: explicit backend overrides ALS role",
    appDriver.seen.length > 0 && analyticsDriver.seen.length === 0);

  // Unmapped role → defaultBackend.
  appDriver.seen.length = 0;
  analyticsDriver.seen.length = 0;
  await b.externalDb.runAs("admin_user", async function () {
    await b.externalDb.query("SELECT 1");
  });
  check("dbRoleBackends: unmapped role → defaultBackend",
    appDriver.seen.length > 0 && analyticsDriver.seen.length === 0);

  // bad role identifier shape rejected at init.
  function rejectsInit(label, opts, codeRe) {
    b.externalDb._resetForTest();
    var threw = null;
    try { b.externalDb.init(opts); } catch (e) { threw = e; }
    check("dbRoleBackends rejects: " + label,
      threw && (codeRe.test(threw.code || "") || codeRe.test(threw.message || "")));
    b.externalDb._resetForTest();
  }
  rejectsInit("non-object map",
    { backends: { x: { connect: appDriver.connect, query: appDriver.query } },
      dbRoleBackends: ["a"] },
    /external-db\/invalid-config/);
  rejectsInit("malformed role identifier",
    { backends: { x: { connect: appDriver.connect, query: appDriver.query } },
      dbRoleBackends: { "bad name": "x" } },
    /external-db\/invalid-config/);
  rejectsInit("backend reference does not exist",
    { backends: { x: { connect: appDriver.connect, query: appDriver.query } },
      dbRoleBackends: { app_user: "missing" } },
    /external-db\/invalid-config/);

  // ---- runAs input validation ----
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      x: { connect: appDriver.connect, query: appDriver.query },
    },
  });
  function rejectsRunAs(label, fn, re) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("runAs rejects: " + label, threw && re.test(threw.code || "") || re.test((threw && threw.message) || ""));
  }
  rejectsRunAs("non-fn body",
    function () { b.externalDb.runAs("x", "not a fn"); },
    /external-db\/invalid-fn/);
  rejectsRunAs("malformed role identifier",
    function () { b.externalDb.runAs("bad name", function () {}); },
    /sql\/bad-shape|INVALID/);

  // ---- transaction sessionGucs (v0.6.6 D4b) ----
  b.externalDb._resetForTest();
  var txDriver = _trackingDriver("tx");
  b.externalDb.init({
    backends: {
      main: { connect: txDriver.connect, query: txDriver.query, close: txDriver.close },
    },
  });

  txDriver.seen.length = 0;
  await b.externalDb.transaction(async function (tx) {
    await tx.query("SELECT 1");
  }, {
    sessionGucs: {
      "app.tenant_id":  "abc-123",
      "app.scale":      42,
      "app.dryRun":     false,
    },
  });
  check("sessionGucs: SET LOCAL string literal escaped",
    txDriver.seen.indexOf("SET LOCAL \"app\".\"tenant_id\" = 'abc-123'") !== -1);
  check("sessionGucs: SET LOCAL numeric value emitted raw",
    txDriver.seen.indexOf('SET LOCAL "app"."scale" = 42') !== -1);
  check("sessionGucs: SET LOCAL boolean rendered as true/false",
    txDriver.seen.indexOf('SET LOCAL "app"."dryRun" = false') !== -1);
  check("sessionGucs: SET LOCAL emitted AFTER BEGIN",
    txDriver.seen.indexOf("BEGIN") < txDriver.seen.indexOf("SET LOCAL \"app\".\"tenant_id\" = 'abc-123'"));

  // SQL-string escaping for embedded quotes.
  txDriver.seen.length = 0;
  await b.externalDb.transaction(async function (tx) {
    await tx.query("SELECT 1");
  }, {
    sessionGucs: { "app.note": "alice's tenant" },
  });
  check("sessionGucs: embedded single quote doubled per SQL standard",
    txDriver.seen.indexOf("SET LOCAL \"app\".\"note\" = 'alice''s tenant'") !== -1);

  // bad sessionGucs shapes throw at the call site.
  async function rejectsTx(label, gucs, re) {
    var threw = null;
    try {
      await b.externalDb.transaction(async function () {}, { sessionGucs: gucs });
    } catch (e) { threw = e; }
    check("sessionGucs rejects: " + label,
      threw && (re.test(threw.code || "") || re.test(threw.message || "")));
  }
  await rejectsTx("array shape",        ["a"],                    /external-db\/invalid-session-gucs/);
  await rejectsTx("bad name",           { "bad name": "x" },      /external-db\/invalid-session-gucs|sql\//);
  await rejectsTx("null value",         { "app.x": null },        /external-db\/invalid-session-gucs/);
  await rejectsTx("Infinity number",    { "app.x": Infinity },    /external-db\/invalid-session-gucs/);
  await rejectsTx("object value",       { "app.x": { y: 1 } },    /external-db\/invalid-session-gucs/);

  // ---- default BEGIN / COMMIT / ROLLBACK use the transaction's own backend ----
  // Two backends, neither supplying beginTx / commit / rollback. Every
  // transaction statement must go through the chosen backend's query function
  // with that backend's client, including the defaults built for it.
  b.externalDb._resetForTest();
  var txRows = [];
  function _ownedDriver(label) {
    return {
      connect: async function () { return { owner: label }; },
      query:   async function (client, sql) {
        txRows.push({ via: label, client: client && client.owner, sql: sql });
        return { rows: [], rowCount: 0 };
      },
      close:   async function () {},
    };
  }
  var txPrimary   = _ownedDriver("primary");
  var txAnalytics = _ownedDriver("analytics");
  b.externalDb.init({
    backends: {
      primary:   { connect: txPrimary.connect,   query: txPrimary.query,   close: txPrimary.close },
      analytics: { connect: txAnalytics.connect, query: txAnalytics.query, close: txAnalytics.close },
    },
    defaultBackend: "primary",
  });
  async function _txOn(backendName) {
    txRows.length = 0;
    await b.externalDb.transaction(async function (tx) {
      await tx.query("SELECT 1");
    }, { backend: backendName });
    try {
      await b.externalDb.transaction(async function (tx) {
        await tx.query("SELECT 2");
        throw new Error("abort");
      }, { backend: backendName });
    } catch (_e) { void _e; }
    return txRows.slice();
  }
  var primaryRows = await _txOn("primary");
  var primaryCtl = primaryRows.filter(function (r) { return /^(BEGIN|COMMIT|ROLLBACK)$/.test(r.sql); });
  check("default tx hooks: BEGIN, COMMIT and ROLLBACK all issued on primary",
        primaryCtl.map(function (r) { return r.sql; }).join(",") === "BEGIN,COMMIT,BEGIN,ROLLBACK",
        JSON.stringify(primaryRows));
  check("default tx hooks: every statement of a primary transaction goes through primary's query function",
        primaryRows.every(function (r) { return r.via === "primary" && r.client === "primary"; }),
        JSON.stringify(primaryRows));
  var analyticsRows = await _txOn("analytics");
  check("default tx hooks: every statement of an analytics transaction goes through analytics' query function",
        analyticsRows.length > 0 &&
        analyticsRows.every(function (r) { return r.via === "analytics" && r.client === "analytics"; }),
        JSON.stringify(analyticsRows));

  // ---- v0.6.7: role-tagged metrics + 42501 denied detection ----
  b.externalDb._resetForTest();
  var obs = b.testing.captureObservability();

  // Replace observability for the duration; restore at the end.
  var obsModule = require("../../lib/observability");
  var origEvent = obsModule.event;
  obsModule.event = obs.event;

  function _metricDriver(label) {
    var seen = [];
    return {
      label: label,
      seen:  seen,
      connect: async function () { return { id: label + "-c" }; },
      query:   async function (_c, sql, _p) {
        seen.push(sql);
        if (/PERMISSION_DENIED/i.test(sql)) {
          var e = new Error("permission denied for table sessions");
          e.code = "42501";
          throw e;
        }
        if (/^SELECT 1$/i.test(sql)) return { rows: [], rowCount: 0 };
        if (/^BEGIN/i.test(sql) || /^COMMIT/i.test(sql) || /^ROLLBACK/i.test(sql)) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [{ from: label }], rowCount: 1 };
      },
      close: async function () {},
      ping:  async function () { return true; },
    };
  }

  var driverApp = _metricDriver("app");
  var driverAna = _metricDriver("ana");
  b.externalDb.init({
    backends: {
      appMain:       { connect: driverApp.connect, query: driverApp.query, close: driverApp.close },
      analyticsMain: { connect: driverAna.connect, query: driverAna.query, close: driverAna.close },
    },
    defaultBackend: "appMain",
    dbRoleBackends: { app_user: "appMain", analytics_user: "analyticsMain" },
  });

  obs.clear();
  await b.externalDb.runAs("analytics_user", async function () {
    await b.externalDb.query("SELECT 1");
  });
  var successEvents = obs.byName("externaldb.query.success");
  check("metrics: query.success tagged with role label",
    successEvents.length === 1 && successEvents[0].labels.role === "analytics_user");
  var durationEvents = obs.byName("externaldb.query.duration_ms");
  check("metrics: query.duration_ms tagged with role label",
    durationEvents.length === 1 && durationEvents[0].labels.role === "analytics_user" &&
    typeof durationEvents[0].value === "number");

  // 42501 → db.role.denied
  obs.clear();
  var threwDenied = null;
  try {
    await b.externalDb.runAs("app_user", async function () {
      await b.externalDb.query("PERMISSION_DENIED test");
    });
  } catch (e) { threwDenied = e; }
  check("42501 propagates as caller error",  threwDenied && threwDenied.code === "42501");
  var deniedEvents = obs.byName("db.role.denied");
  check("42501: db.role.denied counter emitted with role label",
    deniedEvents.length === 1 && deniedEvents[0].labels.role === "app_user");

  // No role → "(none)" label fallback
  obs.clear();
  await b.externalDb.query("SELECT 1");
  var noRoleEvents = obs.byName("externaldb.query.success");
  check("metrics: no role bound → labels.role=(none)",
    noRoleEvents.length === 1 && noRoleEvents[0].labels.role === "(none)");

  // ---- v0.6.7: pool acquire-wait emitted under contention ----
  // Force a wait by holding all connections + queueing a second request.
  obs.clear();
  b.externalDb._resetForTest();
  var slowDriver = _metricDriver("slow");
  b.externalDb.init({
    backends: {
      x: {
        connect: slowDriver.connect, query: slowDriver.query, close: slowDriver.close,
        pool:    { min: 1, max: 1, idleTimeoutMs: 60000 },
      },
    },
  });
  // Hold the only client, then start a second query in parallel.
  // The second has to wait — emits acquire_wait.
  var holdResolve;
  var holdingDriver = {
    connect: async function () { return { id: "held" }; },
    query:   async function (_c, sql) {
      if (sql === "HOLD") return new Promise(function (r) { holdResolve = r; });
      return { rows: [], rowCount: 0 };
    },
    close:   async function () {},
  };
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      x: {
        connect: holdingDriver.connect, query: holdingDriver.query, close: holdingDriver.close,
        pool:    { min: 1, max: 1, idleTimeoutMs: 60000 },
      },
    },
  });
  obs.clear();
  // First call acquires the only slot.
  var first = b.externalDb.query("HOLD");
  // Wait a tick so the first acquire definitely landed.
  await new Promise(function (r) { setImmediate(r); });
  // Second call waits.
  var second = b.externalDb.query("SELECT 1");
  // Brief real-time gap so the second query's promise enters the
  // pool's wait queue before we release the first. acquire_wait is
  // emitted on release (when the waiter unblocks), not on wait-start,
  // so we can't poll for it pre-release.
  await helpers.passiveObserve(5, "externaldb: enter pool wait queue before release");
  // Release the held call.
  holdResolve({ rows: [], rowCount: 0 });
  await first;
  await second;
  var acquireWaitEvents = obs.byName("externaldb.pool.acquire_wait");
  check("acquire_wait: emitted when waiter blocks at max capacity",
    acquireWaitEvents.length >= 1 &&
    typeof acquireWaitEvents[0].value === "number" &&
    acquireWaitEvents[0].labels.backend === "x");

  // ---- v0.6.7: runAs emits db.role.switched audit ----
  // Swap audit module's safeEmit for capture; restore after.
  b.externalDb._resetForTest();
  var auditModule = require("../../lib/audit");
  var origSafeEmit = auditModule.safeEmit;
  var captured = [];
  auditModule.safeEmit = function (e) { captured.push(e); };
  try {
    b.externalDb.init({
      backends: {
        x: { connect: holdingDriver.connect, query: async function () { return { rows: [], rowCount: 0 }; } },
      },
    });
    await b.externalDb.runAs("analytics_user", async function () { /* no-op */ });
    var runAsAudit = captured.filter(function (e) { return e && e.action === "db.role.switched"; });
    check("runAs: db.role.switched audit emitted",
      runAsAudit.length === 1 &&
      runAsAudit[0].metadata.newRole === "analytics_user" &&
      runAsAudit[0].metadata.source === "runAs");

    // No-op transition (same role) → no emission.
    captured.length = 0;
    await b.externalDb.runAs(null, async function () { /* no role -> still no role */ });
    check("runAs: same-role transition does NOT emit",
      captured.filter(function (e) { return e && e.action === "db.role.switched"; }).length === 0);
  } finally {
    auditModule.safeEmit = origSafeEmit;
  }

  // Restore observability
  obsModule.event = origEvent;

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
