"use strict";
/**
 * Redis-protocol queue adapter — backs b.queue with Redis instead of
 * the framework's main DB. Lets operators run multiple app nodes that
 * share a single queue without each needing to be cluster leader,
 * since Redis itself is the coordination point.
 *
 * Storage layout (operator-overridable prefix, default "blamejs:queue"):
 *   <prefix>:job:<jobId>           HASH   — full job record (sealed payload + lastError)
 *   <prefix>:q:<queue>:ready       ZSET   — member=jobId, score=availableAtMs (lease index)
 *   <prefix>:q:<queue>:inflight    ZSET   — member=jobId, score=leaseExpiresAtMs (sweep index)
 *   <prefix>:q:<queue>:dlq         ZSET   — member=jobId, score=finishedAtMs (failed jobs)
 *   <prefix>:q:<queue>:queues      SET    — registry of known queue names (for purge/size scans)
 *
 * Atomicity: lease / sweep / fail / complete all run as Lua scripts so
 * the inflight-zset / ready-zset / job-hash mutations land in a single
 * Redis op without a window for concurrent consumers to double-lease
 * or for sweep to race a complete.
 *
 * Field-crypto integration: payload + lastError seal/unseal go through
 * cryptoField.sealRow("_blamejs_jobs", row) and unsealRow(...) — the
 * SAME crypto-field config the local backend uses, keyed by the
 * "_blamejs_jobs" table name. Operators configuring sealedFields on the
 * jobs table get the same protection on Redis as on SQLite.
 *
 * Cron-repeat: handled at complete()-time in JS (not Lua) — re-enqueues
 * the next firing as a fresh jobId with availableAt = next-cron-fire.
 *
 * Out of scope (defer to follow-up patches):
 *   - Redis Cluster (slot-routing across multi-node Redis)
 *   - Sentinel (managed primary failover)
 *   - Job priority (queue-local supports `priority` opt; Redis backend
 *     orders strictly by availableAt for v1 — re-introduce when a real
 *     operator demand surfaces with a clean Lua-side ordering scheme)
 *   - Flow children with dependsOn (queue-local's _maybeReleaseFlowChildren
 *     coordination — orthogonal to backend choice; ships when flow primitive
 *     itself becomes backend-agnostic)
 */
var C = require("./constants");
var cryptoField = require("./crypto-field");
var { generateToken } = require("./crypto");
var lazyRequire = require("./lazy-require");
var redisClient = require("./redis-client");
var safeJson = require("./safe-json");
var scheduler = require("./scheduler");
var { QueueError } = require("./framework-error");

var _err = QueueError.factory;

// vault is lazy-required because some flows (sealed lastError) only
// touch it on retry-with-error paths, and the import order
// (queue-redis → vault → db → audit) tolerates the late bind.
var vault = lazyRequire(function () { return require("./vault"); });

var DEFAULT_PREFIX = "blamejs:queue";

// ---- Lua scripts ----
//
// LEASE_LUA — atomically pull up to maxRows jobs from the ready zset
// whose score (availableAt) is <= nowMs, move them to the inflight
// zset with score = leaseExpiresAt, increment attempts, flip status,
// and return the jobIds. The JS side then HGETALLs each id.
//
// KEYS[1] = ready zset
// KEYS[2] = inflight zset
// ARGV[1] = nowMs
// ARGV[2] = leaseExpiresAt
// ARGV[3] = maxRows
// ARGV[4] = job-key prefix (e.g. "blamejs:queue:job:")
var LEASE_LUA = [
  'local readyKey = KEYS[1]',
  'local inflightKey = KEYS[2]',
  'local nowMs = tonumber(ARGV[1])',
  'local leaseExpiresAt = tonumber(ARGV[2])',
  'local maxRows = tonumber(ARGV[3])',
  'local jobKeyPrefix = ARGV[4]',
  'local jobIds = redis.call("ZRANGEBYSCORE", readyKey, 0, nowMs, "LIMIT", 0, maxRows)',
  'if #jobIds == 0 then return {} end',
  'for i = 1, #jobIds do',
  '  local jobId = jobIds[i]',
  '  redis.call("ZREM", readyKey, jobId)',
  '  redis.call("ZADD", inflightKey, leaseExpiresAt, jobId)',
  '  redis.call("HINCRBY", jobKeyPrefix..jobId, "attempts", 1)',
  '  redis.call("HSET", jobKeyPrefix..jobId,',
  '             "status", "inflight",',
  '             "leasedAt", nowMs,',
  '             "leaseExpiresAt", leaseExpiresAt)',
  'end',
  'return jobIds',
].join("\n");

// SWEEP_LUA — find jobs in inflight whose lease expired, push back to
// ready with score=nowMs (so they're immediately leasable again).
//
// KEYS[1] = inflight zset
// KEYS[2] = ready zset
// ARGV[1] = nowMs
// ARGV[2] = job-key prefix
var SWEEP_LUA = [
  'local inflightKey = KEYS[1]',
  'local readyKey = KEYS[2]',
  'local nowMs = tonumber(ARGV[1])',
  'local jobKeyPrefix = ARGV[2]',
  'local expired = redis.call("ZRANGEBYSCORE", inflightKey, 0, nowMs)',
  'local count = 0',
  'for i = 1, #expired do',
  '  local jobId = expired[i]',
  '  redis.call("ZREM", inflightKey, jobId)',
  '  redis.call("ZADD", readyKey, nowMs, jobId)',
  '  redis.call("HSET", jobKeyPrefix..jobId, "status", "pending", "leaseExpiresAt", "")',
  '  count = count + 1',
  'end',
  'return count',
].join("\n");

// COMPLETE_LUA — atomically remove from inflight zset, flip status to
// done, set finishedAt. Returns 1 if the job was inflight, 0 otherwise.
//
// KEYS[1] = inflight zset
// KEYS[2] = job hash key
// ARGV[1] = jobId (member to ZREM)
// ARGV[2] = nowMs
var COMPLETE_LUA = [
  'local inflightKey = KEYS[1]',
  'local jobKey = KEYS[2]',
  'local jobId = ARGV[1]',
  'local nowMs = tonumber(ARGV[2])',
  'local removed = redis.call("ZREM", inflightKey, jobId)',
  'if removed == 1 then',
  '  redis.call("HSET", jobKey, "status", "done", "finishedAt", nowMs, "leaseExpiresAt", "")',
  'end',
  'return removed',
].join("\n");

// FAIL_LUA — decide retry vs DLQ based on the row's current attempts
// vs maxAttempts (read from HASH for race-freedom). Retry: ZADD ready
// at score=nextAvailableAt, status=pending. DLQ: ZADD dlq at
// score=nowMs, status=failed.
//
// KEYS[1] = inflight zset
// KEYS[2] = ready zset
// KEYS[3] = dlq zset
// KEYS[4] = job hash key
// ARGV[1] = jobId
// ARGV[2] = nowMs
// ARGV[3] = sealedErr (string; "" if no error)
// ARGV[4] = nextAvailableAt
var FAIL_LUA = [
  'local inflightKey = KEYS[1]',
  'local readyKey = KEYS[2]',
  'local dlqKey = KEYS[3]',
  'local jobKey = KEYS[4]',
  'local jobId = ARGV[1]',
  'local nowMs = tonumber(ARGV[2])',
  'local sealedErr = ARGV[3]',
  'local nextAvailableAt = tonumber(ARGV[4])',
  'local attempts = tonumber(redis.call("HGET", jobKey, "attempts")) or 0',
  'local maxAttempts = tonumber(redis.call("HGET", jobKey, "maxAttempts")) or 5',
  'redis.call("ZREM", inflightKey, jobId)',
  'if sealedErr ~= "" then redis.call("HSET", jobKey, "lastError", sealedErr) end',
  'redis.call("HSET", jobKey, "leaseExpiresAt", "")',
  'if attempts < maxAttempts then',
  '  redis.call("HSET", jobKey, "status", "pending", "availableAt", nextAvailableAt)',
  '  redis.call("ZADD", readyKey, nextAvailableAt, jobId)',
  '  return 0',  // retried
  'else',
  '  redis.call("HSET", jobKey, "status", "failed", "finishedAt", nowMs, "availableAt", "")',
  '  redis.call("ZADD", dlqKey, nowMs, jobId)',
  '  return 1',  // landed in dlq
  'end',
].join("\n");

// EXTEND_LUA — push leaseExpiresAt forward iff the job is still inflight.
//
// KEYS[1] = inflight zset
// KEYS[2] = job hash key
// ARGV[1] = jobId
// ARGV[2] = newExpiry
var EXTEND_LUA = [
  'local inflightKey = KEYS[1]',
  'local jobKey = KEYS[2]',
  'local jobId = ARGV[1]',
  'local newExpiry = tonumber(ARGV[2])',
  'local score = redis.call("ZSCORE", inflightKey, jobId)',
  'if score == false then return 0 end',
  'redis.call("ZADD", inflightKey, newExpiry, jobId)',
  'redis.call("HSET", jobKey, "leaseExpiresAt", newExpiry)',
  'return 1',
].join("\n");

// DLQ_RETRY_LUA — pull a job out of dlq, reset attempts, ZADD ready.
//
// KEYS[1] = dlq zset
// KEYS[2] = ready zset
// KEYS[3] = job hash key
// ARGV[1] = jobId
// ARGV[2] = nowMs
var DLQ_RETRY_LUA = [
  'local dlqKey = KEYS[1]',
  'local readyKey = KEYS[2]',
  'local jobKey = KEYS[3]',
  'local jobId = ARGV[1]',
  'local nowMs = tonumber(ARGV[2])',
  'local removed = redis.call("ZREM", dlqKey, jobId)',
  'if removed == 0 then return 0 end',
  'redis.call("HSET", jobKey,',
  '           "status", "pending",',
  '           "attempts", 0,',
  '           "availableAt", nowMs,',
  '           "lastError", "",',
  '           "finishedAt", "",',
  '           "leasedAt", "",',
  '           "leaseExpiresAt", "")',
  'redis.call("ZADD", readyKey, nowMs, jobId)',
  'return 1',
].join("\n");

// ---- Adapter ----

function create(opts) {
  opts = opts || {};
  if (typeof opts.url !== "string" || opts.url.length === 0) {
    throw _err("INVALID_CONFIG",
      "queue-redis: opts.url is required (e.g. redis://localhost:6379/0)", true);
  }
  var prefix = typeof opts.keyPrefix === "string" && opts.keyPrefix.length > 0
                    ? opts.keyPrefix : DEFAULT_PREFIX;

  var client = redisClient.create({
    url:       opts.url,
    password:  opts.password,
    username:  opts.username,
    tls:       opts.tls,
    connectTimeoutMs: opts.connectTimeoutMs,
    commandTimeoutMs: opts.commandTimeoutMs,
  });

  // Lazy connect — defer first connect until the first operation so
  // queue.init({ backends }) doesn't have to be async.
  var connectPromise = null;
  function _ensureConnected() {
    if (client.isOpen()) return Promise.resolve();
    if (!connectPromise) connectPromise = client.connect();
    return connectPromise;
  }

  // ---- Key helpers ----
  function _jobKey(jobId)         { return prefix + ":job:" + jobId; }
  function _readyKey(queueName)   { return prefix + ":q:" + queueName + ":ready"; }
  function _inflightKey(queueName){ return prefix + ":q:" + queueName + ":inflight"; }
  function _dlqKey(queueName)     { return prefix + ":q:" + queueName + ":dlq"; }
  function _queuesKey()           { return prefix + ":queues"; }
  function _jobKeyPrefix()        { return prefix + ":job:"; }

  // ---- Row encoding ----
  //
  // Redis HSET fields are flat string-or-binary. Encode a JS object
  // into HSET-friendly args while preserving null/undefined as missing
  // (HDEL on update; never sent on insert) and boolean/number/buffer
  // as their natural string form.
  function _hsetArgs(jobId, fieldsObj) {
    var args = ["HSET", _jobKey(jobId)];
    Object.keys(fieldsObj).forEach(function (k) {
      var v = fieldsObj[k];
      if (v === null || v === undefined) return;     // skip
      args.push(k);
      if (Buffer.isBuffer(v))      args.push(v);
      else if (v === true || v === false) args.push(v ? "1" : "0");
      else                          args.push(String(v));
    });
    return args;
  }

  // Decode an HGETALL reply (alternating field/value Buffers) into a
  // plain object with Buffer/string values as appropriate. Returns
  // null when the hash didn't exist (HGETALL on missing key returns []).
  function _decodeHash(hashArr) {
    if (!hashArr || hashArr.length === 0) return null;
    var out = {};
    for (var i = 0; i + 1 < hashArr.length; i += 2) {
      var k = Buffer.isBuffer(hashArr[i]) ? hashArr[i].toString("utf8") : String(hashArr[i]);
      out[k] = Buffer.isBuffer(hashArr[i + 1]) ? hashArr[i + 1].toString("utf8") : hashArr[i + 1];
    }
    return out;
  }

  // Shape a leased row into the same { jobId, queueName, payload, ... }
  // contract queue-local returns from _shapeLeasedRow.
  function _shapeLeasedRow(jobId, raw) {
    if (!raw) return null;
    // Pretend it's a "_blamejs_jobs" row so cryptoField unseals correctly.
    var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
    return {
      jobId:          jobId,
      queueName:      unsealed.queueName,
      payload:        unsealed.payload ? safeJson.parse(unsealed.payload) : null,
      attempts:       Number(unsealed.attempts),
      maxAttempts:    Number(unsealed.maxAttempts),
      traceId:        unsealed.traceId || null,
      classification: unsealed.classification || null,
      enqueuedAt:     Number(unsealed.enqueuedAt),
      leaseExpiresAt: Number(unsealed.leaseExpiresAt),
      repeatCron:     unsealed.repeatCron     || null,
      repeatTimezone: unsealed.repeatTimezone || null,
      flowId:         unsealed.flowId         || null,
      flowChildName:  unsealed.flowChildName  || null,
    };
  }

  // ---- Public adapter ops ----

  async function enqueue(queueName, payload, opts2) {
    await _ensureConnected();
    opts2 = opts2 || {};
    var nowMs = Date.now();
    // Same SCHEDULING PRECEDENCE rule as queue-local: opts.availableAt
    // wins when finite; relative form is shorthand only.
    var availableAt;
    if (typeof opts2.availableAt === "number" && isFinite(opts2.availableAt)) {
      availableAt = opts2.availableAt;
    } else {
      availableAt = nowMs + (opts2.delaySeconds ? C.TIME.seconds(opts2.delaySeconds) : 0);
    }
    var jobId = generateToken(16);
    var row = {
      _id:             jobId,
      queueName:       queueName,
      payload:         payload === undefined ? null : JSON.stringify(payload),
      status:          "pending",
      enqueuedAt:      nowMs,
      availableAt:     availableAt,
      attempts:        0,
      maxAttempts:     opts2.maxAttempts != null ? opts2.maxAttempts : 5,
      lastError:       null,
      finishedAt:      null,
      traceId:         opts2.traceId || null,
      classification:  opts2.classification || null,
      priority:        (typeof opts2.priority === "number" && isFinite(opts2.priority))
                          ? Math.floor(opts2.priority) : 0,
      repeatCron:      opts2.repeat && typeof opts2.repeat.cron === "string"
                          ? opts2.repeat.cron : null,
      repeatTimezone:  opts2.repeat && typeof opts2.repeat.timezone === "string"
                          ? opts2.repeat.timezone : null,
      flowId:          typeof opts2.flowId === "string" ? opts2.flowId : null,
      flowChildName:   typeof opts2.flowChildName === "string" ? opts2.flowChildName : null,
      dependsOn:       Array.isArray(opts2.dependsOn) && opts2.dependsOn.length > 0
                          ? JSON.stringify(opts2.dependsOn) : null,
    };
    var sealed = cryptoField.sealRow("_blamejs_jobs", row);

    // Pipeline: HSET job + ZADD ready + SADD queues. Pipelined writes
    // hit Redis without round-trips between them.
    var hsetArgs = _hsetArgs(jobId, sealed);
    var p1 = client.command.apply(null, hsetArgs);
    var p2 = client.command("ZADD", _readyKey(queueName), String(availableAt), jobId);
    var p3 = client.command("SADD", _queuesKey(), queueName);
    await Promise.all([p1, p2, p3]);

    return {
      jobId:          jobId,
      queueName:      queueName,
      enqueuedAt:     nowMs,
      availableAt:    availableAt,
      classification: row.classification,
    };
  }

  async function lease(queueName, leaseMs, count) {
    await _ensureConnected();
    var nowMs = Date.now();
    var leaseExpiresAt = nowMs + leaseMs;
    var maxRows = count != null ? count : 1;

    var jobIdsRaw = await client.runScript(
      LEASE_LUA, 2,
      _readyKey(queueName), _inflightKey(queueName),
      String(nowMs), String(leaseExpiresAt), String(maxRows), _jobKeyPrefix()
    );
    if (!jobIdsRaw || jobIdsRaw.length === 0) return [];

    var jobIds = jobIdsRaw.map(function (x) {
      return Buffer.isBuffer(x) ? x.toString("utf8") : String(x);
    });

    // Fetch each job's full record. Pipelined HGETALLs.
    var hashes = await Promise.all(jobIds.map(function (id) {
      return client.command("HGETALL", _jobKey(id));
    }));
    var leased = [];
    for (var i = 0; i < jobIds.length; i++) {
      var raw = _decodeHash(hashes[i]);
      var shaped = _shapeLeasedRow(jobIds[i], raw);
      if (shaped) leased.push(shaped);
    }
    return leased;
  }

  async function extendLease(jobId, additionalMs) {
    await _ensureConnected();
    if (typeof additionalMs !== "number" || additionalMs <= 0) {
      throw _err("INVALID_LEASE_EXTENSION",
        "extendLease: additionalMs must be a positive number", true);
    }
    var newExpiry = Date.now() + additionalMs;
    // We don't know which queue the job belongs to without a HGET, so
    // fetch queueName first (avoids storing inflight by queue, which
    // would otherwise need a global secondary index).
    var qBuf = await client.command("HGET", _jobKey(jobId), "queueName");
    if (qBuf === null || qBuf === undefined) return false;
    var queueName = Buffer.isBuffer(qBuf) ? qBuf.toString("utf8") : String(qBuf);
    var rv = await client.runScript(
      EXTEND_LUA, 2,
      _inflightKey(queueName), _jobKey(jobId),
      jobId, String(newExpiry)
    );
    return rv === 1;
  }

  async function complete(jobId) {
    await _ensureConnected();
    var nowMs = Date.now();
    // Read row first to act on cron-repeat metadata. Same shape as
    // queue-local: SELECT row → flip status → if repeatCron, enqueue
    // next firing.
    var rawArr = await client.command("HGETALL", _jobKey(jobId));
    var raw = _decodeHash(rawArr);
    if (!raw) return false;
    var queueName = raw.queueName || "unknown";

    await client.runScript(
      COMPLETE_LUA, 2,
      _inflightKey(queueName), _jobKey(jobId),
      jobId, String(nowMs)
    );

    if (raw.repeatCron) {
      try {
        var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
        var cron = scheduler.parseCron(unsealed.repeatCron);
        var nextMs = scheduler.nextCronFire(
          cron, new Date(nowMs), unsealed.repeatTimezone || null);
        await enqueue(unsealed.queueName,
          unsealed.payload ? safeJson.parse(unsealed.payload) : null,
          {
            availableAt:     nextMs,
            repeat:          { cron: unsealed.repeatCron, timezone: unsealed.repeatTimezone },
            priority:        Number(unsealed.priority) || 0,
            classification:  unsealed.classification || null,
            traceId:         unsealed.traceId || null,
          });
      } catch (_e) { /* best-effort — cron resumes next tick if op fixes the issue */ }
    }
    return true;
  }

  async function fail(jobId, errorMessage, retryDelayMs) {
    await _ensureConnected();
    var nowMs = Date.now();
    if (typeof retryDelayMs !== "number" || !isFinite(retryDelayMs) || retryDelayMs < 0) {
      retryDelayMs = 0;
    }
    var nextAvailableAt = nowMs + retryDelayMs;

    var queueBuf = await client.command("HGET", _jobKey(jobId), "queueName");
    if (queueBuf === null || queueBuf === undefined) return false;
    var queueName = Buffer.isBuffer(queueBuf) ? queueBuf.toString("utf8") : String(queueBuf);

    var sealedErr = errorMessage ? vault().seal(String(errorMessage)) : "";

    await client.runScript(
      FAIL_LUA, 4,
      _inflightKey(queueName), _readyKey(queueName), _dlqKey(queueName), _jobKey(jobId),
      jobId, String(nowMs), sealedErr, String(nextAvailableAt)
    );
    return true;
  }

  async function sweepExpired() {
    await _ensureConnected();
    // Walk every known queue; the queues SET keeps the list current
    // (enqueue SADDs the name).
    var qs = await client.command("SMEMBERS", _queuesKey());
    if (!qs || qs.length === 0) return 0;
    var nowMs = Date.now();
    var totals = await Promise.all(qs.map(function (qBuf) {
      var queueName = Buffer.isBuffer(qBuf) ? qBuf.toString("utf8") : String(qBuf);
      return client.runScript(
        SWEEP_LUA, 2,
        _inflightKey(queueName), _readyKey(queueName),
        String(nowMs), _jobKeyPrefix());
    }));
    return totals.reduce(function (acc, n) { return acc + Number(n || 0); }, 0);
  }

  async function size(queueName) {
    await _ensureConnected();
    var [r, i] = await Promise.all([
      client.command("ZCARD", _readyKey(queueName)),
      client.command("ZCARD", _inflightKey(queueName)),
    ]);
    return Number(r || 0) + Number(i || 0);
  }

  async function purge(queueName) {
    await _ensureConnected();
    // Walk the ready + inflight + dlq zsets, delete the per-job
    // hashes, then drop the zsets and the queues-set membership.
    var [readyMembers, inflightMembers, dlqMembers] = await Promise.all([
      client.command("ZRANGE", _readyKey(queueName),    "0", "-1"),
      client.command("ZRANGE", _inflightKey(queueName), "0", "-1"),
      client.command("ZRANGE", _dlqKey(queueName),      "0", "-1"),
    ]);
    var allIds = [].concat(readyMembers || [], inflightMembers || [], dlqMembers || [])
      .map(function (b) { return Buffer.isBuffer(b) ? b.toString("utf8") : String(b); });
    var dels = allIds.map(function (id) { return client.command("DEL", _jobKey(id)); });
    var zdrops = [
      client.command("DEL", _readyKey(queueName)),
      client.command("DEL", _inflightKey(queueName)),
      client.command("DEL", _dlqKey(queueName)),
      client.command("SREM", _queuesKey(), queueName),
    ];
    await Promise.all(dels.concat(zdrops));
    return allIds.length;
  }

  async function dlqList(queueName, opts2) {
    await _ensureConnected();
    opts2 = opts2 || {};
    var limit = (typeof opts2.limit === "number" && opts2.limit > 0) ? opts2.limit : 100;
    // Newest failures first — score is finishedAtMs, so ZREVRANGE.
    var ids = await client.command(
      "ZREVRANGE", _dlqKey(queueName), "0", String(limit - 1));
    if (!ids || ids.length === 0) return [];
    var idStrs = ids.map(function (b) { return Buffer.isBuffer(b) ? b.toString("utf8") : String(b); });
    var hashes = await Promise.all(idStrs.map(function (id) {
      return client.command("HGETALL", _jobKey(id));
    }));
    var out = [];
    for (var i = 0; i < idStrs.length; i++) {
      var raw = _decodeHash(hashes[i]);
      if (!raw) continue;
      var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
      out.push({
        jobId:          idStrs[i],
        queueName:      unsealed.queueName,
        payload:        unsealed.payload ? safeJson.parse(unsealed.payload) : null,
        status:         unsealed.status,
        enqueuedAt:     Number(unsealed.enqueuedAt),
        finishedAt:     unsealed.finishedAt ? Number(unsealed.finishedAt) : null,
        attempts:       Number(unsealed.attempts),
        maxAttempts:    Number(unsealed.maxAttempts),
        lastError:      unsealed.lastError || null,
        traceId:        unsealed.traceId || null,
        classification: unsealed.classification || null,
      });
    }
    return out;
  }

  async function dlqRetry(jobId) {
    await _ensureConnected();
    var nowMs = Date.now();
    var queueBuf = await client.command("HGET", _jobKey(jobId), "queueName");
    if (queueBuf === null || queueBuf === undefined) return false;
    var queueName = Buffer.isBuffer(queueBuf) ? queueBuf.toString("utf8") : String(queueBuf);
    var rv = await client.runScript(
      DLQ_RETRY_LUA, 3,
      _dlqKey(queueName), _readyKey(queueName), _jobKey(jobId),
      jobId, String(nowMs)
    );
    return rv === 1;
  }

  async function dlqSize(queueName) {
    await _ensureConnected();
    var n = await client.command("ZCARD", _dlqKey(queueName));
    return Number(n || 0);
  }

  async function shutdown() {
    try { await client.close(); } catch (_e) { /* best effort */ }
  }

  return {
    protocol:     "redis",
    enqueue:      enqueue,
    lease:        lease,
    extendLease:  extendLease,
    complete:     complete,
    fail:         fail,
    sweepExpired: sweepExpired,
    size:         size,
    purge:        purge,
    dlqList:      dlqList,
    dlqRetry:     dlqRetry,
    dlqSize:      dlqSize,
    shutdown:     shutdown,
    // Diagnostic — exposed for tests + ops dashboards
    _client:      client,
    _prefix:      function () { return prefix; },
  };
}

module.exports = { create: create };
