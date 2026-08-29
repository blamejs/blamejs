// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.chainWriter
 * @nav    Observability
 * @title  Chain Writer
 *
 * @intro
 *   Race-safe append to a hash-chained log table. Both `audit_log` and
 *   `consent_log` share the same row shape — take next monotonic
 *   counter, read previous row's `rowHash`, seal the logical row via
 *   field-crypto, materialize null entries for every hashable column
 *   so canonicalization sees the same key set at write-time and
 *   verify-time, compute `rowHash` over the sealed content, INSERT
 *   with `prevHash` / `rowHash` / `nonce` / `fencingToken`.
 *
 *   The chain-writer extracts that pattern so every consumer gets the
 *   same race protection. Each instance owns a per-chain Mutex
 *   serializing read-prev → compute-hash → insert (without it,
 *   concurrent appends hash against the same prev-tip and fork the
 *   chain), plus a Once initializing the in-process counter from
 *   `MAX(monotonicCounter)` on first use.
 *
 *   Writes route through the cluster-storage dispatcher so the same
 *   chain definition works on single-node SQLite and on cluster-mode
 *   external Postgres. `cluster.requireLeader()` runs before the
 *   mutex; followers reject with `NotLeaderError`. Table names are
 *   restricted to the `ALLOWED_CHAIN_TABLES` allowlist so a misconfig
 *   can't point a writer at a non-chain table and corrupt the chain
 *   semantics.
 *
 *   Operators usually don't construct chain-writers directly — `b.audit`
 *   and `b.consent` each construct one at module load. Direct use is
 *   for new chain-backed tables registered in `ALLOWED_CHAIN_TABLES`.
 *
 * @card
 *   Race-safe append to a hash-chained log table.
 */

var { generateToken, generateBytes } = require("./crypto");
var auditChain = require("./audit-chain");
var cryptoField = require("./crypto-field");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var C = require("./constants");
var boundedMap = require("./bounded-map");
var numericBounds = require("./numeric-bounds");
var time = require("./time");
var { FrameworkError } = require("./framework-error");

// Allowlist of chain table names. The two framework chains ship registered; a
// consumer's own append-only hash-chained table is added at config time via
// registerTable() BEFORE create() accepts it. The allowlist is never bypassed
// — an unregistered table throws at create(), so a misconfig can't point a
// chain-writer at a non-chain table and corrupt the chain semantics.
var ALLOWED_CHAIN_TABLES = new Set(["audit_log", "consent_log"]);
// SHA3-512 hex width — the shape every chain link has, and the only shape a
// resolved origin hash may take. Routed through C.BYTES so the arithmetic has
// one source of truth.
var ORIGIN_HASH_HEX_LEN = C.BYTES.bytes(64) * 2;

var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

// b.sql opts for every chain-table statement: thread the ACTIVE backend
// dialect (clusterStorage.dialect() — "sqlite" single-node, "postgres" |
// "mysql" in cluster mode) so the emitted identifier quoting + dialect
// idioms match the backend the SQL dispatches to. Defaulting to "sqlite"
// works on Postgres only by accident (both double-quote identifiers) and
// emits the wrong quoting on MySQL. clusterStorage.execute still rewrites
// table names + translates `?` placeholders at dispatch; this controls only
// the builder-side quoting + idiom selection.
function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

class ChainWriterError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "ChainWriterError";
    this.code = code || "chain-writer/invalid";
    this.isChainWriterError = true;
  }
}

/**
 * @primitive b.chainWriter.registerTable
 * @signature b.chainWriter.registerTable(table)
 * @since     0.15.13
 * @status    stable
 * @related   b.chainWriter.create, b.safeSql.validateIdentifier
 *
 * Register a consumer-owned append-only table as chain-writable so
 * `b.chainWriter.create({ table })` accepts it. Call once at boot (config
 * time) for each app table carrying the chain columns (`monotonicCounter`,
 * `recordedAt`, `nonce`, `prevHash`, `rowHash` — plus `fencingToken` in
 * cluster mode). The framework chains (`audit_log`, `consent_log`) are
 * pre-registered. Throws `ChainWriterError` (`chain-writer/invalid-config`) on
 * a non-identifier name; the name is validated against the SQL identifier
 * rules because it is interpolated into the chain SQL. Idempotent. Returns the
 * registered name.
 *
 * Operator footgun to avoid on a MULTI-chain table (one configured with a
 * `chainKey`): the per-key writer restarts `monotonicCounter` at 1 for each
 * key, so a UNIQUE index on `monotonicCounter` ALONE (the shape the framework
 * `audit_log` uses for its single chain) will reject the second key's first
 * row. A keyed chain's uniqueness must be the composite
 * `(chainKey, monotonicCounter)`, never `monotonicCounter` by itself.
 *
 * @example
 *   b.chainWriter.registerTable("device_event_log");
 *   var writer = b.chainWriter.create({
 *     table:            "device_event_log",
 *     chainKey:         "deviceId",
 *     columnsForInsert: ["_id", "deviceId", "monotonicCounter", "recordedAt",
 *                        "kind", "payload",
 *                        "prevHash", "rowHash", "nonce", "fencingToken"],
 *     hashableColumns:  ["_id", "deviceId", "monotonicCounter", "recordedAt",
 *                        "kind", "payload"],
 *   });
 */
function registerTable(table) {
  if (typeof table !== "string" || table.length === 0) {
    throw new ChainWriterError(
      "registerTable requires a non-empty table name",
      "chain-writer/invalid-config"
    );
  }
  // Identifier-validate before admitting to the allowlist — the name is
  // interpolated into the chain SQL, so the same shape rules create() relies
  // on must hold here, at the config-time entry point.
  safeSql.validateIdentifier(table);
  ALLOWED_CHAIN_TABLES.add(table);
  return table;
}

/**
 * @primitive b.chainWriter.create
 * @signature b.chainWriter.create(opts)
 * @since     0.8.48
 * @status    stable
 * @related   b.audit, b.consent, b.auditChain, b.chainWriter.registerTable
 *
 * Build a chain-writer bound to a single hash-chained table. Returns
 * `{ table, chainKey, append, _resetForTest, _getMutexForTest }`.
 * `append(logical)` is the public surface — async, leader-gated,
 * mutex-serialized; on success it returns the logical row decorated with the
 * computed `rowHash` and `prevHash`.
 *
 * A `chainKey` makes one table hold many independent chains (one per account /
 * device / tenant): tip-read, counter monotonicity, and the append Mutex all
 * scope per key, so concurrent appends to DIFFERENT keys run in parallel while
 * same-key appends serialize. Bind `chainKey` into `hashableColumns` so the
 * partition is tamper-evident in the row hash, and key the table's uniqueness
 * constraint on `(chainKey, monotonicCounter)`, never `monotonicCounter` alone.
 *
 * @opts
 *   table:            string,    // a registered chain table (audit_log | consent_log | registerTable name)
 *   chainKey:         string,    // optional partition column — one independent chain per key value
 *   columnsForInsert: string[],  // INSERT column order (every name is identifier-validated)
 *   hashableColumns:  string[],  // columns that participate in the rowHash canonicalization
 *   validateInput:    Function,  // optional; (logical) -> throws on invalid shape
 *
 * @example
 *   var writer = b.chainWriter.create({
 *     table:            "audit_log",
 *     columnsForInsert: ["_id", "monotonicCounter", "recordedAt",
 *                        "action", "outcome",
 *                        "prevHash", "rowHash", "nonce", "fencingToken"],
 *     hashableColumns:  ["_id", "monotonicCounter", "recordedAt",
 *                        "action", "outcome"],
 *   });
 *
 *   var row = await writer.append({
 *     action:  "user.login",
 *     outcome: "success",
 *   });
 *   row.rowHash;     // → "<hex sha3-512 digest>"
 *   row.prevHash;    // → "<previous tip rowHash, or zero-hash on first row>"
 */
function create(opts) {
  if (!opts || !opts.table || !Array.isArray(opts.columnsForInsert) ||
      !Array.isArray(opts.hashableColumns)) {
    throw new ChainWriterError(
      "create requires { table, columnsForInsert, hashableColumns }",
      "chain-writer/invalid-config"
    );
  }
  // Validate table name shape AND require it's in the chain-table allowlist.
  safeSql.validateIdentifier(opts.table);
  safeSql.assertOneOf(opts.table, ALLOWED_CHAIN_TABLES);

  // Validate every column name against the SQL identifier rules — we
  // interpolate them into the INSERT SQL.
  for (var i = 0; i < opts.columnsForInsert.length; i++) {
    safeSql.validateIdentifier(opts.columnsForInsert[i]);
  }
  for (var j = 0; j < opts.hashableColumns.length; j++) {
    safeSql.validateIdentifier(opts.hashableColumns[j]);
  }

  var table             = opts.table;
  var columnsForInsert  = opts.columnsForInsert.slice();
  var hashableColumns   = opts.hashableColumns.slice();
  var validateInput     = opts.validateInput || null;
  // Where the chain resumes when the table holds no row for this key, as
  // `{ hash, counter }` — the last hash of what came before, and the highest
  // counter already used — or nothing, for a key where nothing came before.
  // Optional; without it an empty table starts a new chain at ZERO_HASH from
  // counter 1, which is right for every table that has never had rows removed
  // from under it. A resolver that throws stops the append, which is how it
  // says the chain cannot be grounded and no row should be written.
  //
  // Both halves or neither. Restoring the hash alone leaves the counter to
  // restart at 1, and a verifier skips every row at or below the purge
  // boundary — so the rows would be written, look linked, and be silently
  // excluded from every verification that ever ran over them. That is worse
  // than the break restoring the hash was meant to fix, because nothing
  // reports it.
  // Only undefined and null mean "this table has no origin to resolve". `||`
  // would have folded false / 0 / "" into that too, so a mistyped option would
  // silently turn the resolution off — and a purged table would then restart
  // at ZERO_HASH and counter 1, inside the range a verifier skips, which is
  // exactly the failure the paragraph above describes.
  var resolveOrigin = (opts.resolveOrigin === undefined || opts.resolveOrigin === null)
    ? null : opts.resolveOrigin;
  if (resolveOrigin !== null && typeof resolveOrigin !== "function") {
    throw new ChainWriterError(
      "resolveOrigin must be a function, got " + typeof opts.resolveOrigin +
        " — a value that cannot be called would silently disable origin resolution",
      "chain-writer/invalid-config"
    );
  }

  // chainKey: the partition column for many independent chains in one table
  // (one chain per account / device / tenant). When set, the tip read,
  // counter priming, and the append Mutex all scope to a single key value, so
  // appends to DIFFERENT keys run in parallel while same-key appends
  // serialize. Identifier-validated at config time (THROW tier) because it is
  // interpolated as a column name; it must also appear in columnsForInsert so
  // every row carries its partition key.
  var chainKey = opts.chainKey || null;
  if (chainKey !== null) {
    safeSql.validateIdentifier(chainKey);
    if (columnsForInsert.indexOf(chainKey) === -1) {
      throw new ChainWriterError(
        "chainKey '" + chainKey + "' must be listed in columnsForInsert so " +
        "every appended row carries its partition key",
        "chain-writer/invalid-config"
      );
    }
  }

  // Per-CHAIN-KEY Mutex serializes the read-prev-tip + compute-hash + insert
  // sequence. Without serialization, two concurrent awaiting append() calls
  // would hash against the same prev-tip and fork the chain. A single-chain
  // writer (no chainKey) uses one shared lock under the sentinel key; a
  // multi-chain writer keys the lock by the partition value so appends to
  // DIFFERENT keys run concurrently while same-key appends serialize.
  var _SINGLE_CHAIN_KEY = "__single_chain__";   // sentinel; not a valid driver value
  var _mutexByKey = new Map();
  function _mutexFor(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    return boundedMap.getOrInsert(_mutexByKey, k, function () { return new safeAsync.Mutex(); });
  }

  // Lazy counter primer — first append for a given key reads
  // MAX(monotonicCounter) [WHERE chainKey = ?] and increments from there.
  // Per-key so each chain's counter is independent; a per-key Once shares one
  // in-flight init across concurrent first-callers for the same key.
  var _nextCounterByKey = new Map();
  var _counterInitByKey = new Map();
  // The resolved origin for a key, cached because resolving it is a database
  // read and an append must not do one per row. It is also why the cache is
  // not merely an optimization: the owner's resolver reads a table, that read
  // can emit an audit event, and emitting one is an append — so resolving on
  // every append to an empty chain feeds itself. Resolved once per key, and
  // again only when invalidateOrigin() says the answer changed.
  var _originByKey = new Map();
  // Keys whose cached origin was invalidated while something else held the
  // lock. Cleared by the re-derivation in append(), which runs BEFORE the
  // mutex — see invalidateOrigin for why it cannot run inside it.
  var _originStaleByKey = new Map();
  // Each cached origin carries the fencing token it was read under, in the
  // same entry — see _invalidateOriginIfTermChanged: invalidateOrigin only
  // reaches THIS process, so a cached origin has to expire on its own when
  // leadership has moved since it was read.

  // `recordedAt` has to order the same way `monotonicCounter` does. Readers
  // depend on it crossing between the two: b.auditTools.exportSlice selects a
  // slice by recordedAt and then requires that slice to be CONTIGUOUS in
  // monotonicCounter. Date.now() cannot carry that — it repeats inside a
  // millisecond and steps backwards when NTP corrects the clock — so one
  // backwards step drops a row out of the window its neighbours are in and
  // refuses the operator's export.
  //
  // One clock per partition, seeded from that partition's own persisted tip on
  // every append: the floor therefore survives a restart or a failover, and a
  // clock excursion on one chain cannot push another chain's timestamps into
  // the future.
  var _clockByKey = new Map();
  function _clockFor(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    return boundedMap.getOrInsert(_clockByKey, k, function () {
      return time.monotonicClock({ label: table + ":" + k });
    });
  }

  // Only carry a timestamp when the table actually has the column — a
  // consumer's chain table is free not to.
  var _hasRecordedAt = columnsForInsert.indexOf("recordedAt") !== -1;

  // Ask the table's owner where the chain resumes, and refuse an answer that
  // cannot be acted on. A garbage hash would throw deep inside computeRowHash
  // as an opaque failure, and a garbage counter floor would stamp NaN into a
  // NOT NULL column — both are config-time mistakes by the module supplying
  // the resolver, so they fail loudly and immediately.
  async function _readOrigin(keyValue) {
    var origin = await resolveOrigin(keyValue);
    // Nothing came before this key — the documented answer for a chain that is
    // genuinely new, which is every key on a writer that has never had rows
    // removed from under it.
    if (origin == null) return { hash: auditChain.ZERO_HASH, counter: 0 };
    if (typeof origin !== "object") {
      throw new ChainWriterError(
        "resolveOrigin must return { hash, counter } or nothing",
        "chain-writer/bad-origin"
      );
    }
    if (!safeBuffer.isHex(origin.hash, ORIGIN_HASH_HEX_LEN)) {
      throw new ChainWriterError(
        "resolveOrigin returned hash '" + String(origin.hash).slice(0, 32) +
          "', which is not a SHA3-512 hex digest — refusing to append a row " +
          "whose link into the chain cannot be established",
        "chain-writer/bad-origin"
      );
    }
    // Safe-integer, not merely whole — the same bound the purge anchor applies
    // to the boundary this usually comes from. monotonicCounter is a BIGINT,
    // and above 2^53 distinct stored values collapse onto one Number, so a
    // floor taken from up there would silently equal a different counter and
    // the writer would reuse or skip one.
    var counter = Number(origin.counter);
    if (!numericBounds.isIncrementableSafeInt(counter)) {
      throw new ChainWriterError(
        "resolveOrigin returned counter '" + String(origin.counter) +
          "', which is not a whole non-negative number the chain can resume " +
          "above while staying below 2^53",
        "chain-writer/bad-origin"
      );
    }
    return { hash: origin.hash, counter: counter };
  }

  // The origin for a key, resolved at most once until it is invalidated. Both
  // callers below go through here so a single resolution answers the counter
  // floor and the link hash — asking twice could get two different answers and
  // pair a counter from one boundary with a hash from another.
  // Resolve the origin and prove leadership did not move while we were
  // reading it. The read is a database round trip, so a term can begin and end
  // inside it — and an origin read just before another node purged describes a
  // chain that no longer exists. Stamping the term without re-checking it
  // would only correct the NEXT append; this append would still link an
  // emptied table to the pre-purge answer, which is the break the stamp exists
  // to prevent.
  //
  // A term that keeps moving means this node is not reliably the leader, and
  // an append is not the place to wait that out: refuse rather than link to a
  // boundary that may already be superseded.
  var _ORIGIN_TERM_ATTEMPTS = 3;
  async function _resolveOriginInOneTerm(keyValue) {
    for (var attempt = 0; attempt < _ORIGIN_TERM_ATTEMPTS; attempt += 1) {
      var term = cluster.fencingToken();
      var origin = await _readOrigin(keyValue);
      if (cluster.fencingToken() === term) {
        return { hash: origin.hash, counter: origin.counter, term: term };
      }
    }
    throw new ChainWriterError(
      "leadership changed during every attempt to resolve where " + table +
        " resumes; an origin read across a term change may already be superseded",
      "chain-writer/origin-term-unstable"
    );
  }

  async function _cachedOrigin(k, keyValue) {
    if (_originByKey.has(k)) return _originByKey.get(k);
    var resolved = await _resolveOriginInOneTerm(keyValue);
    // One entry carries the origin AND the term it was read in, so a
    // concurrent resolution cannot leave one paired with the other's term.
    boundedMap.getOrInsert(_originByKey, k, function () { return resolved; });
    return _originByKey.get(k);
  }

  // invalidateOrigin is process-local, and a purge runs on ONE node. A node
  // that led before the purge, lost leadership, and leads again after it still
  // holds the pre-purge answer — so an append to the emptied table would link
  // to ZERO_HASH instead of the boundary the anchor recorded, and the next
  // verify would call a legitimate purge a chain break.
  //
  // The fencing token is the observable that crosses nodes: it moves whenever
  // leadership does. An origin resolved under an earlier term is therefore not
  // trusted. Re-reading on every empty-table append instead would resolve on
  // each one — and the resolver's read reports itself through the audit chain,
  // so that feeds itself (see _originByKey). A term change is rare, which is
  // what makes expiring on it affordable.
  //
  // Single-node deployments never initialize a lease, so the token stays 0,
  // nothing expires, and invalidateOrigin remains the whole mechanism there.
  function _invalidateOriginIfTermChanged(keyValue) {
    if (!resolveOrigin) return;
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    var cached = _originByKey.get(k);
    if (!cached) return;
    if (cached.term === cluster.fencingToken()) return;
    _originByKey.delete(k);
    _originStaleByKey.set(k, true);
  }

  // Re-derive a key's counter after something told us the answer moved. Runs
  // before the mutex, for the reason invalidateOrigin explains.
  //
  // The re-derived value is taken as a FLOOR, never as a replacement: a
  // counter only ever goes up. The value being replaced may have been read
  // midway through a purge and be too low, which is why this runs at all — but
  // it may equally be a correct, higher value from a busy chain, and dropping
  // back to the boundary would reuse counters that are already in the table.
  async function _reprimeIfStale(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    if (!_originStaleByKey.get(k)) return;
    _originStaleByKey.delete(k);
    var had = _nextCounterByKey.get(k);
    _counterInitByKey.delete(k);
    _nextCounterByKey.delete(k);
    await _ensureCounterInit(keyValue);
    var derived = _nextCounterByKey.get(k);
    if (had != null && had > derived) _nextCounterByKey.set(k, had);
  }

  function _ensureCounterInit(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    var once = boundedMap.getOrInsert(_counterInitByKey, k, function () {
      return new safeAsync.Once(async function () {
        // BARE logical table name — clusterStorage rewrites the framework
        // name to the configured-prefix form (consumer tables pass through
        // unchanged) and placeholderizes; b.sql quotes the camelCase column +
        // emits the MAX aggregate. A keyed writer scopes the MAX to the
        // partition via a bound WHERE.
        var maxQ = sql.select(table, _sqlOpts()).max("monotonicCounter", "m");
        if (chainKey !== null) maxQ = maxQ.where(chainKey, keyValue);
        var maxBuilt = maxQ.toSql();
        var row = await safeAsync.withTimeout(
          safeAsync.asyncRetry(function () {
            return clusterStorage.executeOne(maxBuilt.sql, maxBuilt.params);
          }),
          FRAMEWORK_SQL_TIMEOUT_MS,
          { name: table + ".readMaxCounter" }
        );
        // Deliberately does NOT consult resolveOrigin. This runs inside a Once
        // whose promise is cached and awaited by every concurrent appender, so
        // a resolver that throws leaves a stored rejected promise that nothing
        // is attached to — an unhandled rejection that takes the process down
        // even though the appender itself caught the error. The origin is
        // resolved in _appendInsideMutex instead, where exactly one caller is
        // awaiting it; see the counter floor raised there.
        _nextCounterByKey.set(k, (row && row.m ? Number(row.m) : 0) + 1);
      });
    });
    return once.invoke();
  }

  async function _readChainTipRow(keyValue) {
    // recordedAt rides along with rowHash: the tip is this partition's durable
    // clock floor, and reading it here costs no extra round trip.
    var tipQ = sql.select(table, _sqlOpts())
      .columns(_hasRecordedAt ? ["rowHash", "recordedAt"] : ["rowHash"])
      .orderBy("monotonicCounter", "desc")
      .limit(1);
    // Scope the tip to the partition so per-key chains link correctly —
    // bound value, never interpolated.
    if (chainKey !== null) tipQ = tipQ.where(chainKey, keyValue);
    var tipBuilt = tipQ.toSql();
    return await safeAsync.withTimeout(
      safeAsync.asyncRetry(function () {
        return clusterStorage.executeOne(tipBuilt.sql, tipBuilt.params);
      }),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: table + ".readChainTip" }
    );
  }

  async function _insertRow(values) {
    // b.sql INSERT: map each column (identifier-validated at create()) to
    // its positional value and bind as a row object — the unambiguous form
    // (a flat value array whose first element is a Buffer/object would be
    // misread as an array-of-rows). BARE logical table name — clusterStorage
    // rewrites + placeholderizes per dialect.
    var rowObj = {};
    for (var ci = 0; ci < columnsForInsert.length; ci++) {
      rowObj[columnsForInsert[ci]] = values[ci];
    }
    var insBuilt = sql.insert(table, _sqlOpts())
      .columns(columnsForInsert)
      .values(rowObj)
      .toSql();
    return await safeAsync.withTimeout(
      clusterStorage.execute(insBuilt.sql, insBuilt.params),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: table + ".insertRow" }
    );
  }

  async function append(logical) {
    if (validateInput) validateInput(logical);
    cluster.requireLeader();

    // Resolve the partition key from the logical row for a multi-chain writer.
    // Fail closed: a keyed writer with a missing / empty key can't pick a
    // chain to append to, so refuse rather than silently fold the row into the
    // wrong chain.
    var keyValue = _SINGLE_CHAIN_KEY;
    if (chainKey !== null) {
      keyValue = logical ? logical[chainKey] : undefined;
      if (keyValue === undefined || keyValue === null || String(keyValue).length === 0) {
        throw new ChainWriterError(
          "append: a chainKey writer requires logical['" + chainKey + "'] to be a " +
          "non-empty partition value",
          "chain-writer/invalid-input"
        );
      }
    }
    // Priming runs BEFORE the mutex, and has to. It reads the database, and in
    // cluster mode that read reports its own outcome through the audit chain —
    // so an append that primes while holding the mutex queues an audit event
    // whose append waits for that same mutex. One transient read failure then
    // compounds: every queued append finds the counter still unset, primes
    // again, and emits again. That is the shape that wedged the external-db
    // suite for five minutes and dropped 45 buffered rows.
    //
    // Priming here instead means concurrent appends share ONE in-flight read
    // through the Once below. A read that lands mid-purge — after the rows are
    // gone, before the anchor accounting for them is written — is handled by
    // the purge itself: it discards what this primed before releasing the lock
    // (see invalidateOrigin), so the transient answer never survives the
    // operation that produced it.
    _invalidateOriginIfTermChanged(keyValue);
    await _reprimeIfStale(keyValue);
    await _ensureCounterInit(keyValue);

    return await _mutexFor(keyValue).runExclusive(async function () {
      return await _appendInsideMutex(logical, keyValue);
    });
  }

  async function _appendInsideMutex(logical, keyValue) {
    var _ck = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;

    // Re-prime if the counter is gone. append() awaits _ensureCounterInit
    // BEFORE taking this mutex, so a call already queued behind one that
    // failed has cleared that gate while the failure handler below deleted the
    // primed value — this read would then be `undefined` and stamp NaN.
    //
    // Today that is masked: the tip is screened before `counter` is first
    // used, so a pre-insert throw hides it, and monotonicCounter is INTEGER
    // NOT NULL with a unique index in every schema. Relying on the masking
    // would make correctness here an argument about which throw happens first,
    // and that is precisely the reasoning that produced the permanent write
    // wedge this handler now exists to prevent. Under the mutex the answer
    // cannot change underneath us, and _ensureCounterInit takes no lock, so
    // calling it here cannot deadlock.
    if (!_nextCounterByKey.has(_ck)) await _ensureCounterInit(keyValue);

    // An empty table is not necessarily counter 0. A sanctioned purge removes
    // rows that DID use the counters below its boundary, and a verifier skips
    // everything at or below that boundary — so resuming at 1 would write rows
    // that look correctly linked and are silently excluded from every
    // verification of this chain. Nothing reports that, which makes it worse
    // than a visible break.
    //
    // Raised here rather than during priming because resolving the origin can
    // fail, and priming happens inside a shared Once whose cached rejection
    // would surface as an unhandled rejection no appender can catch. Here the
    // caller awaiting this IS the appender.
    //
    // Checked on EVERY append rather than only when the counter came back as
    // 1. Priming happens before this lock, so a purge can land between the two
    // and the value primed is then whatever the table held mid-deletion —
    // which is any number at or below the boundary, not just 1 (a purge that
    // leaves earlier rows in place answers with one of them). And an
    // invalidation that arrives after this append primed but before it reached
    // the lock is not visible to it any other way.
    //
    // It costs a database read only when the cached origin was invalidated:
    // the first append after a purge re-resolves, every one after it is
    // answered from the cache. That bound is what keeps this read, taken while
    // holding the lock, from feeding itself — see _cachedOrigin.
    if (resolveOrigin) {
      var floor = (await _cachedOrigin(_ck, keyValue)).counter;
      if (_nextCounterByKey.get(_ck) <= floor) _nextCounterByKey.set(_ck, floor + 1);
    }

    var counter = _nextCounterByKey.get(_ck);
    _nextCounterByKey.set(_ck, counter + 1);
    try {
      return await _buildAndInsert(logical, keyValue, _ck, counter);
    } catch (e) {
      // The append did not complete — but WHETHER THE ROW LANDED is unknown. A
      // timeout cannot distinguish "the insert never committed" from "it
      // committed and the acknowledgement was lost", and both arrive here as
      // the same throw.
      //
      // Restoring the counter unconditionally is right in the first case and
      // catastrophic in the second: the next append would reuse a counter that
      // IS already in the table, hit the unique index, land back here, restore
      // it again, and wedge this chain permanently — every audit or consent
      // write failing until the process restarts. That is far worse than the
      // contiguity hole the rollback exists to avoid.
      //
      // So discard the in-memory counter instead of guessing, and let the next
      // append re-read MAX(monotonicCounter) from storage. That answers both
      // cases with the same mechanism: if the row never landed the maximum is
      // unchanged and the counter is reclaimed with no gap; if it did land the
      // maximum includes it and the next append continues after it.
      _nextCounterByKey.delete(_ck);
      _counterInitByKey.delete(_ck);
      throw e;
    }
  }

  async function _buildAndInsert(logical, keyValue, _ck, counter) {

    // Read the tip BEFORE stamping: it supplies both the hash this row links
    // to and the clock floor this row's timestamp must clear.
    var tipRow = await _readChainTipRow(keyValue);
    var clock = _clockFor(keyValue);
    if (_hasRecordedAt && tipRow && tipRow.recordedAt !== undefined && tipRow.recordedAt !== null) {
      // Postgres hands a BIGINT back as a string; the floor is a number.
      var tipMs = Number(tipRow.recordedAt);
      // A tip that carries a timestamp MUST yield a usable floor. Skipping an
      // unreadable one would append beneath the row it links to and put the
      // chain back in the state this floor exists to prevent, so an unusable
      // tip refuses the append and says which chain it came from - rather than
      // surfacing a bare clock error from two frames down.
      if (!Number.isSafeInteger(tipMs) || tipMs < 0 || tipMs >= Number.MAX_SAFE_INTEGER) {
        throw new ChainWriterError(
          "append: the chain tip for " + table + " carries an unusable recordedAt (" +
          String(tipRow.recordedAt) + "), so the next row's timestamp cannot be " +
          "ordered against it. The row is corrupt or was written outside the " +
          "framework; verify the chain before appending.",
          "chain-writer/bad-tip-timestamp"
        );
      }
      clock.observeFloor(tipMs);
    }
    var nowMs   = clock.now();
    var nonce   = generateBytes(C.BYTES.bytes(16));

    // Caller-supplied logical row: spread + add framework-managed fields.
    var fullLogical = Object.assign({}, logical, {
      _id:               (logical && logical._id) || generateToken(C.BYTES.bytes(16)),
      recordedAt:        nowMs,
      monotonicCounter:  counter,
    });

    // Seal sealed-fields, compute derived hashes
    var sealed = cryptoField.sealRow(table, fullLogical);

    // Materialize null entries for every hashable column the schema
    // expects, so canonicalize sees the same key set at write-time and
    // verify-time. JSON canonicalization distinguishes missing-key
    // from key:null — must not.
    for (var hci = 0; hci < hashableColumns.length; hci++) {
      if (!(hashableColumns[hci] in sealed)) sealed[hashableColumns[hci]] = null;
    }

    // Compute rowHash over the sealed content fields, linking to THIS key's
    // tip — the same read that supplied the clock floor above.
    // An empty table is not always a new chain. A sanctioned purge can remove
    // every row while the chain continues past it, and restarting at ZERO_HASH
    // there writes a row whose prevHash contradicts what the purge recorded —
    // a break the next verify reports as tampering, on a deletion the
    // framework itself performed. The owner of the table says where the chain
    // resumes; ZERO_HASH from counter 1 is what that answers when nothing came
    // before.
    //
    // Resolved here rather than carried from counter priming because the two
    // happen at different times: a purge inside a running process leaves the
    // primed counter correct but empties the table, so the hash has to be read
    // after the purge, not from whatever was true at boot. The counter floor
    // in _ensureCounterInit consults the same origin, so neither half can be
    // restored without the other.
    // The term was checked before the lock, and then this append waited — for
    // the counter to prime, and for every append ahead of it in the queue. A
    // new leader can purge inside that wait, which would leave the cached
    // origin describing a chain that no longer exists. Checking again here,
    // with the row about to be written, is the last point where that is still
    // catchable.
    //
    // It refuses rather than re-resolving: resolving reads a table, that read
    // reports itself through the audit chain, and an append doing that while
    // holding this mutex would queue an append waiting for the mutex it holds.
    // The caller retries, and the retry re-resolves before the lock where it
    // is safe to.
    if (resolveOrigin && !tipRow) {
      var held = _originByKey.get(_ck);
      if (held && held.term !== cluster.fencingToken()) {
        _originByKey.delete(_ck);
        _originStaleByKey.set(_ck, true);
        throw new ChainWriterError(
          "leadership changed while this append waited for the " + table +
            " chain lock; where the chain resumes may have moved with it",
          "chain-writer/origin-term-changed"
        );
      }
    }
    var prevHash = tipRow ? tipRow.rowHash
      : (resolveOrigin ? (await _cachedOrigin(_ck, keyValue)).hash : auditChain.ZERO_HASH);
    var rowHash = auditChain.computeRowHash(prevHash, sealed, nonce);

    sealed.prevHash = prevHash;
    sealed.rowHash  = rowHash;
    sealed.nonce    = nonce;

    var fencingToken = cluster.fencingToken();
    var values = columnsForInsert.map(function (c) {
      if (c === "fencingToken") return fencingToken;
      return c in sealed ? sealed[c] : null;
    });
    await _insertRow(values);

    return Object.assign({ rowHash: rowHash, prevHash: prevHash }, fullLogical);
  }

  function _resetForTest() {
    _mutexByKey = new Map();
    _counterInitByKey = new Map();
    _nextCounterByKey = new Map();
    _originByKey = new Map();
    _originStaleByKey = new Map();
    // The clocks go too: a test that tears down and reseeds a table would
    // otherwise carry the previous run's floor into the new chain and stamp
    // every row far ahead of wall clock.
    _clockByKey = new Map();
  }

  return {
    table:          table,
    chainKey:       chainKey,
    append:         append,
    // Run `fn` under the same lock append() holds across read-tip → insert.
    //
    // A checkpoint signs a statement about the tip, so it has to observe a tip
    // that actually existed. Reading it outside this lock can land in the
    // middle of an append — between the row being written and the counter
    // advancing — and pair a counter with a hash that were never the tip
    // together. The signature over that pair is valid and self-consistent and
    // describes a state the chain was never in.
    //
    // Callers hold it for the READ only and sign afterwards. The signature is
    // post-quantum and slow, and every concurrent append waits on this lock;
    // signing under it would charge that cost to unrelated writers for no
    // added guarantee, since a checkpoint claims a prefix rather than claiming
    // nothing has been appended since.
    withChainLock: function (keyValue, fn) {
      return _mutexFor(keyValue).runExclusive(fn);
    },
    // Say that what this key cached about where its chain resumes is out of
    // date. Whoever changed the answer — a purge writing a new boundary —
    // calls this while still holding the chain lock.
    //
    // It MARKS rather than deletes, and the difference is a deadlock. An
    // append that primed its counter and is queued behind the purge would, if
    // its primed value were deleted here, re-prime after it takes the mutex —
    // and that read reports its own outcome through the audit chain in cluster
    // mode, so it would queue an append waiting for the mutex it is holding.
    // Marking instead lets the re-derivation happen where the first priming
    // does, before the lock (see append).
    //
    // The mark matters because an append that primed while the purge was
    // midway through — after the rows were deleted, before the anchor
    // accounting for them was written — read a maximum of zero and would
    // otherwise restart at 1, at or below the new boundary, where a verifier
    // skips every row it writes.
    invalidateOrigin: function (keyValue) {
      var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
      _originByKey.delete(k);
      _originStaleByKey.set(k, true);
    },
    _resetForTest:  _resetForTest,
    // Expose for diagnostic introspection — the lock for a given key (or the
    // single-chain lock when no chainKey is configured).
    _getMutexForTest: function (keyValue) { return _mutexFor(keyValue); },
  };
}

module.exports = {
  create:               create,
  registerTable:        registerTable,
  ChainWriterError:     ChainWriterError,
  ALLOWED_CHAIN_TABLES: ALLOWED_CHAIN_TABLES,
  FRAMEWORK_SQL_TIMEOUT_MS: FRAMEWORK_SQL_TIMEOUT_MS,
};
