// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var workerThreads = require("node:worker_threads");
var bCrypto = require("./crypto");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var observability = require("./observability");
var { Argon2Error } = require("./framework-error");

var ARGON2ID = "argon2id";

var ARGON2_VERSION = 0x13;

var DEFAULT_HASH_LENGTH = C.BYTES.bytes(32);
var DEFAULT_SALT_LENGTH = C.BYTES.bytes(16);
var MAX_TAG_BYTES = C.BYTES.kib(1);
var MAX_SALT_BYTES = C.BYTES.kib(1);

function _b64NoPad(buf) {
  var s = buf.toString("base64");
  var end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x3D ) end -= 1;
  return end === s.length ? s : s.slice(0, end);
}

function _fromB64NoPad(s) {
  return Buffer.from(s, "base64");
}

function _phcEncode(salt, hash, params) {
  return "$argon2id$v=" + ARGON2_VERSION +
         "$m=" + params.memoryCost +
         ",t=" + params.timeCost +
         ",p=" + params.parallelism +
         "$" + _b64NoPad(salt) +
         "$" + _b64NoPad(hash);
}

function _positiveInt(n) {
  return typeof n === "number" && isFinite(n) && n > 0 && Math.floor(n) === n;
}

function isGateRefusal(err) {
  return !!(err && err.isArgon2Error === true && err.permanent === false);
}

function isArgon2Error(err) {
  return !!(err && err.isArgon2Error === true);
}

var COST_CEILING_DEFAULT = Object.freeze({
  memoryCost:  C.BYTES.kib(64) * 8,
  timeCost:    3 * 8,
  parallelism: 16,
});
var _costCeiling = COST_CEILING_DEFAULT;

function costCeiling(opts) {
  if (opts === undefined) return Object.assign({}, _costCeiling);
  if (opts === null) {
    _costCeiling = COST_CEILING_DEFAULT;
    return Object.assign({}, _costCeiling);
  }
  validateOpts(opts, ["memoryCost", "timeCost", "parallelism"],
    "argon2.costCeiling");
  var next = Object.assign({}, _costCeiling, opts);
  ["memoryCost", "timeCost", "parallelism"].forEach(function (k) {
    if (!_positiveInt(next[k])) {
      throw new TypeError("argon2.costCeiling: " + k +
        " must be a positive finite integer");
    }
  });
  _costCeiling = Object.freeze(next);
  return Object.assign({}, _costCeiling);
}

function _withinCeiling(p) {
  return p.memoryCost  <= _costCeiling.memoryCost &&
         p.timeCost    <= _costCeiling.timeCost &&
         p.parallelism <= _costCeiling.parallelism;
}

function exceedsCostCeiling(stored) {
  var dec = _phcDecode(typeof stored === "string" ? stored : String(stored == null ? "" : stored));
  return !!(dec && !_withinCeiling(dec.params));
}

function _phcDecode(stored) {
  if (typeof stored !== "string" || stored.length === 0) return null;
  var parts = stored.split("$");
  if (parts.length !== 6) return null;
  if (parts[0] !== "" || parts[1] !== ARGON2ID) return null;
  var ver = /^v=(\d+)$/.exec(parts[2]);
  if (!ver) return null;
  var version = parseInt(ver[1], 10);
  if (!isFinite(version) || version <= 0) return null;
  var paramTokens = parts[3].split(",");
  var p = { memoryCost: NaN, timeCost: NaN, parallelism: NaN };
  for (var i = 0; i < paramTokens.length; i += 1) {
    var t = paramTokens[i];
    var eq = t.indexOf("=");
    if (eq === -1) return null;
    var k = t.slice(0, eq);
    var v = parseInt(t.slice(eq + 1), 10);
    if (!isFinite(v)) return null;
    if (k === "m") p.memoryCost = v;
    else if (k === "t") p.timeCost = v;
    else if (k === "p") p.parallelism = v;
  }
  if (!_positiveInt(p.memoryCost) || !_positiveInt(p.timeCost) ||
      !_positiveInt(p.parallelism)) return null;
  var salt;
  var hash;
  try { salt = _fromB64NoPad(parts[4]); }
  catch (_e) { return null; }
  try { hash = _fromB64NoPad(parts[5]); }
  catch (_e) { return null; }
  if (salt.length === 0 || salt.length > MAX_SALT_BYTES) return null;
  if (hash.length === 0 || hash.length > MAX_TAG_BYTES) return null;
  return { version: version, params: p, salt: salt, hash: hash };
}

var GATE_DEFAULT_LIMIT = 8;
var _limit = GATE_DEFAULT_LIMIT;
var _activeLocal = 0;
var _activeShared = 0;
var _waiters = [];
var _maxQueued = Infinity;
var _waitTimeoutMs = 0;

var SLOT_AVAIL = 0;
var SLOT_LIMIT = 1;
var SLOT_OWNER_SLOTS = 2;
var OWNERS_BASE = 3;
var OWNER_SLOTS = 256;
var SHARED_WORDS = OWNERS_BASE + OWNER_SLOTS;
var SHARED_BYTES = SHARED_WORDS * 4;
var SHARED_LIMIT_MAX = OWNER_SLOTS;
var THREAD_ID_MAX = 2147483646;
var _shared = null;
var _sharedView = null;
var _sharedWaiters = [];
var _keepAlive = null;

function _holdThreadWhileWaiting() {
  if (_sharedWaiters.length === 0) {
    if (_keepAlive !== null) { clearInterval(_keepAlive); _keepAlive = null; }
    return;
  }
  // allow:timer-no-unref-process-pinning — waitAsync does not pin the loop.
  if (_keepAlive === null) _keepAlive = setInterval(function () {}, 50);
}

function gateHandle() {
  return _shared;
}

function _resolveSharedOpt(value, n, currentLimit) {
  if (value === true) {
    var limit = n !== undefined && n !== null ? n : currentLimit;
    if (limit > SHARED_LIMIT_MAX) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate: a shared gate records the thread holding each of its " +
        "permits, and the handle holds " + SHARED_LIMIT_MAX + " of those records, " +
        "so a shared limit must be at most " + SHARED_LIMIT_MAX + "; got " + limit);
    }
    var buf = new SharedArrayBuffer(SHARED_BYTES);
    var view = new Int32Array(buf);
    Atomics.store(view, SLOT_AVAIL, limit);
    Atomics.store(view, SLOT_LIMIT, limit);
    Atomics.store(view, SLOT_OWNER_SLOTS, OWNER_SLOTS);
    return { buf: buf, view: view, limit: limit };
  }
  if (value === false || value === null) return { buf: null, view: null, limit: null };
  if (typeof SharedArrayBuffer === "function" && value instanceof SharedArrayBuffer) {
    if (value.byteLength < SHARED_BYTES) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate: shared must be a handle from argon2.gateHandle()");
    }
    var adopting = new Int32Array(value);
    var sharedLimit = Atomics.load(adopting, SLOT_LIMIT);
    if (!_positiveInt(sharedLimit)) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate: shared handle carries no limit — it was not produced by " +
        "argon2.gate(n, { shared: true })");
    }
    if (sharedLimit > SHARED_LIMIT_MAX) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate: the shared handle names a limit of " + sharedLimit +
        ", above the " + SHARED_LIMIT_MAX + " permit records a handle holds, so " +
        "it was not produced by argon2.gate(n, { shared: true })");
    }
    if (n !== undefined && n !== null && n !== sharedLimit) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate: the shared handle's limit is " + sharedLimit +
        " and cannot be changed from a thread that adopts it; got n=" + n);
    }
    return { buf: value, view: adopting, limit: sharedLimit };
  }
  throw new Argon2Error("argon2/bad-gate",
    "argon2.gate: shared must be true, false, or a handle from argon2.gateHandle()");
}

function gate(n, opts) {
  var nextLimit = _limit;
  var nextMaxQueued = _maxQueued;
  var nextWaitTimeoutMs = _waitTimeoutMs;
  var nextShared;
  if (n !== undefined && n !== null) {
    if (!_positiveInt(n)) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate(n): n must be a positive integer");
    }
    nextLimit = n;
  }
  if (opts !== undefined && opts !== null) {
    validateOpts(opts, ["maxQueued", "waitTimeoutMs", "shared"], "argon2.gate");
    if (opts.shared !== undefined) {
      nextShared = _resolveSharedOpt(opts.shared, n, _limit);
      if (nextShared.limit !== null) nextLimit = nextShared.limit;
    }
  }
  if (_sharedView && (nextShared === undefined || nextShared.view === _sharedView)) {
    var attachedLimit = Atomics.load(_sharedView, SLOT_LIMIT);
    if (n !== undefined && n !== null && n !== attachedLimit) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate: this thread is on a shared gate whose limit is " +
        attachedLimit + " and that limit is fixed for its life; got n=" + n +
        ". Create a new shared gate, or pass shared: false first.");
    }
    nextLimit = attachedLimit;
  }
  if (opts !== undefined && opts !== null) {
    if (opts.maxQueued !== undefined) {
      if (opts.maxQueued !== Infinity && !_positiveInt(opts.maxQueued) && opts.maxQueued !== 0) {
        throw new Argon2Error("argon2/bad-gate",
          "argon2.gate: maxQueued must be a non-negative integer or Infinity");
      }
      nextMaxQueued = opts.maxQueued;
    }
    if (opts.waitTimeoutMs !== undefined) {
      if (opts.waitTimeoutMs !== 0 && !_positiveInt(opts.waitTimeoutMs)) {
        throw new Argon2Error("argon2/bad-gate",
          "argon2.gate: waitTimeoutMs must be 0 or a positive integer");
      }
      nextWaitTimeoutMs = opts.waitTimeoutMs;
    }
  }
  _limit = nextLimit;
  _maxQueued = nextMaxQueued;
  _waitTimeoutMs = nextWaitTimeoutMs;
  var priorView = _sharedView;
  var priorBuf = _shared;
  if (nextShared !== undefined) {
    _shared = nextShared.buf;
    _sharedView = nextShared.view;
  }
  if (priorBuf !== _shared) _rehomeWaiters(priorView);
  _startWaiters();
  return stats();
}

function stats() {
  var out = {
    running:       _inFlight(),
    waiting:       _waiters.length + _sharedWaiters.length,
    limit:         _limit,
    maxQueued:     _maxQueued,
    waitTimeoutMs: _waitTimeoutMs,
    shared:        !!_sharedView,
  };
  if (_sharedView) out.available = _syncAvail(_sharedView);
  return out;
}

function _inFlight() {
  return _activeLocal + _activeShared;
}

function _queued() {
  return _waiters.length + _sharedWaiters.length;
}

function _releaseLocal() {
  _activeLocal -= 1;
  _afterRelease();
}

function _releaseTo(view) {
  return function () {
    _activeShared -= 1;
    _dropPermitOwner(view);
    _syncAvail(view);
    Atomics.notify(view, SLOT_AVAIL);
    _afterRelease();
  };
}

function _threadKey() {
  return workerThreads.threadId + 1;
}

function _permitSlots(view) {
  var limit = Atomics.load(view, SLOT_LIMIT);
  var slots = Atomics.load(view, SLOT_OWNER_SLOTS);
  if (!(slots > 0) || slots > OWNER_SLOTS) slots = OWNER_SLOTS;
  return limit < slots ? limit : slots;
}

function _syncAvail(view) {
  var slots = _permitSlots(view);
  var free = 0;
  for (var i = 0; i < slots; i += 1) {
    if (Atomics.load(view, OWNERS_BASE + i) === 0) free += 1;
  }
  Atomics.store(view, SLOT_AVAIL, free);
  return free;
}

function _dropPermitOwner(view) {
  var key = _threadKey();
  var slots = _permitSlots(view);
  for (var i = 0; i < slots; i += 1) {
    if (Atomics.compareExchange(view, OWNERS_BASE + i, key, 0) === key) return true;
  }
  return false;
}

function reclaimGatePermits(threadId) {
  if (_sharedView === null) {
    throw new Argon2Error("argon2/bad-gate",
      "argon2.reclaimGatePermits: this thread is not attached to a shared gate; " +
      "attach one with gate(n, { shared: true }) or gate(null, { shared: handle })");
  }
  if (typeof threadId !== "number" || !isFinite(threadId) ||
      Math.floor(threadId) !== threadId || threadId < 0 ||
      threadId > THREAD_ID_MAX) {
    throw new Argon2Error("argon2/bad-gate",
      "argon2.reclaimGatePermits: an owner key is a 32-bit signed integer, so " +
      "thread id must be an integer from 0 to " + THREAD_ID_MAX + ", got " +
      String(threadId));
  }
  if (threadId === workerThreads.threadId) {
    throw new Argon2Error("argon2/bad-gate",
      "argon2.reclaimGatePermits: a thread cannot reclaim its own permits; the " +
      "release function the gate hands the caller is what gives a permit back");
  }
  var key = threadId + 1;
  var slots = _permitSlots(_sharedView);
  var freed = 0;
  for (var i = 0; i < slots; i += 1) {
    if (Atomics.compareExchange(_sharedView, OWNERS_BASE + i, key, 0) === key) freed += 1;
  }
  _syncAvail(_sharedView);
  Atomics.notify(_sharedView, SLOT_AVAIL);
  _afterRelease();
  return freed;
}

function _afterRelease() {
  _startWaiters();
  var pending = _sharedWaiters.slice();
  for (var i = 0; i < pending.length; i++) {
    var w = pending[i];
    if (w.heldByThread === true && typeof w.attempt === "function") w.attempt();
  }
}

function _startWaiters() {
  while (_waiters.length > 0 && _inFlight() < _limit) {
    var w = _waiters.shift();
    if (w.timer) clearTimeout(w.timer);
    _activeLocal += 1;
    w.resolve(_releaseLocal);
  }
}

function _takeSharedPermit(view) {
  var key = _threadKey();
  var slots = _permitSlots(view);
  for (var i = 0; i < slots; i += 1) {
    if (Atomics.compareExchange(view, OWNERS_BASE + i, 0, key) === 0) {
      _syncAvail(view);
      return true;
    }
  }
  _syncAvail(view);
  return false;
}

function _acquireShared(view, carried) {
  if (_inFlight() < _limit && _takeSharedPermit(view)) {
    _activeShared += 1;
    return Promise.resolve(_releaseTo(view));
  }
  if (_queued() >= _maxQueued) {
    return Promise.reject(new Argon2Error("argon2/busy",
      "argon2: no permit free in the shared gate of " +
      Atomics.load(view, SLOT_LIMIT) + " and " + _queued() +
      " waiting on this thread, at the configured maxQueued of " + _maxQueued));
  }
  var waiting = carried || { since: Date.now(), budget: _waitTimeoutMs };
  var started = waiting.since;
  var budget = waiting.budget;
  return new Promise(function (resolve, reject) {
    var entry = { resolve: resolve, reject: reject, timer: null, waiting: waiting,
                  heldByThread: false, waitOutstanding: false };
    _sharedWaiters.push(entry);
    _holdThreadWhileWaiting();
    function settle(fn, arg) {
      var at = _sharedWaiters.indexOf(entry);
      if (at === -1) return false;
      _sharedWaiters.splice(at, 1);
      if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
      _holdThreadWhileWaiting();
      fn(arg);
      return true;
    }
    function attempt() {
      if (_sharedWaiters.indexOf(entry) === -1) return;
      if (_inFlight() < _limit && _takeSharedPermit(view)) {
        _activeShared += 1;
        var release = _releaseTo(view);
        if (!settle(resolve, release)) release();
        return;
      }
      var left = budget > 0 ? budget - (Date.now() - started) : Infinity;
      if (left <= 0) {
        settle(reject, new Argon2Error("argon2/queue-timeout",
          "argon2: waited " + budget + "ms for a permit in the shared gate"));
        return;
      }
      if (_inFlight() >= _limit) {
        entry.heldByThread = true;
        if (left !== Infinity && entry.timer === null) {
          entry.timer = setTimeout(function () { entry.timer = null; attempt(); }, left);
          if (entry.timer.unref) entry.timer.unref();
        }
        return;
      }
      if (entry.waitOutstanding === true) { entry.heldByThread = false; return; }
      entry.heldByThread = false;
      var waited = Atomics.waitAsync(view, SLOT_AVAIL, 0,
        left === Infinity ? undefined : left);
      if (!waited.async) { attempt(); return; }
      entry.waitOutstanding = true;
      if (_inFlight() < _limit && _takeSharedPermit(view)) {
        _activeShared += 1;
        var late = _releaseTo(view);
        if (!settle(resolve, late)) late();
        return;
      }
      waited.value.then(function (how) {
        entry.waitOutstanding = false;
        if (how === "timed-out" && budget > 0) {
          settle(reject, new Argon2Error("argon2/queue-timeout",
            "argon2: waited " + budget + "ms for a permit in the shared gate"));
          return;
        }
        attempt();
      }, function () { entry.waitOutstanding = false; attempt(); });
    }
    entry.attempt = attempt;
    attempt();
  });
}

function _acquire() {
  if (_sharedView) return _acquireShared(_sharedView);
  if (_inFlight() < _limit) {
    _activeLocal += 1;
    return Promise.resolve(_releaseLocal);
  }
  if (_queued() >= _maxQueued) {
    return Promise.reject(new Argon2Error("argon2/busy",
      "argon2: " + _inFlight() + " run(s) in flight and " + _queued() +
      " waiting, at the configured maxQueued of " + _maxQueued));
  }
  return _parkLocal(null);
}

function _parkLocal(carried) {
  var waiting = carried || { since: Date.now(), budget: _waitTimeoutMs };
  return new Promise(function (resolve, reject) {
    var entry = { resolve: resolve, reject: reject, timer: null, waiting: waiting };
    var left = waiting.budget > 0 ? waiting.budget - (Date.now() - waiting.since) : 0;
    if (waiting.budget > 0) {
      if (left <= 0) {
        reject(new Argon2Error("argon2/queue-timeout",
          "argon2: waited " + waiting.budget + "ms for a slot"));
        return;
      }
      entry.timer = setTimeout(function () {
        var at = _waiters.indexOf(entry);
        if (at !== -1) _waiters.splice(at, 1);
        reject(new Argon2Error("argon2/queue-timeout",
          "argon2: waited " + waiting.budget + "ms for a slot"));
      }, left);
      if (entry.timer.unref) entry.timer.unref();
    }
    _waiters.push(entry);
  });
}

function _rehomeWaiters(priorView) {
  var moving = _waiters.splice(0, _waiters.length)
    .concat(_sharedWaiters.splice(0, _sharedWaiters.length));
  _holdThreadWhileWaiting();
  var abandoned = 0;
  for (var i = 0; i < moving.length; i++) {
    var w = moving[i];
    if (w.timer) { clearTimeout(w.timer); w.timer = null; }
    if (w.waitOutstanding === true) abandoned += 1;
    if (_sharedView) _acquireShared(_sharedView, w.waiting).then(w.resolve, w.reject);
    else _parkLocal(w.waiting).then(w.resolve, w.reject);
  }
  if (abandoned > 0 && priorView) Atomics.notify(priorView, SLOT_AVAIL);
}

function _runArgon2(message, salt, params, hashLength) {
  return _acquire().then(function (release) {
    return _runArgon2Ungated(message, salt, params, hashLength)
      .then(function (v) { release(); return v; },
            function (e) { release(); throw e; });
  });
}

function _runArgon2Ungated(message, salt, params, hashLength) {
  return new Promise(function (resolve, reject) {
    nodeCrypto.argon2(ARGON2ID, {
      message:     message,
      nonce:       salt,
      memory:      params.memoryCost,
      passes:      params.timeCost,
      parallelism: params.parallelism,
      tagLength:   hashLength,
    }, function (err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

async function hash(plain, opts) {
  opts = opts || {};
  var params = {
    memoryCost:  opts.memoryCost  || C.BYTES.kib(64),
    timeCost:    opts.timeCost    || 3,
    parallelism: opts.parallelism || 1,
  };
  var hashLength = opts.hashLength || DEFAULT_HASH_LENGTH;
  if (!_withinCeiling(params)) {
    throw new Argon2Error("argon2/cost-over-ceiling",
      "argon2.hash: m=" + params.memoryCost + ",t=" + params.timeCost +
      ",p=" + params.parallelism + " is over the ceiling (m=" +
      _costCeiling.memoryCost + ",t=" + _costCeiling.timeCost +
      ",p=" + _costCeiling.parallelism + "); raise it with costCeiling first");
  }
  var salt = opts.salt || nodeCrypto.randomBytes(DEFAULT_SALT_LENGTH);
  var message = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
  var raw = await _runArgon2(message, salt, params, hashLength);
  if (opts.raw === true) return raw;
  return _phcEncode(salt, raw, params);
}

async function verify(stored, plain) {
  var dec = _phcDecode(stored);
  if (!dec) return false;
  if (!_withinCeiling(dec.params)) {
    try {
      observability.safeEvent("auth.password.cost_over_ceiling", 1, {
        memoryCost:  dec.params.memoryCost,
        timeCost:    dec.params.timeCost,
        parallelism: dec.params.parallelism,
      });
    } catch (_e) { /* hot-path sink, drop-silent by design */ }
    return false;
  }
  var message = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
  var actual;
  try { actual = await _runArgon2(message, dec.salt, dec.params, dec.hash.length); }
  catch (e) {
    if (isGateRefusal(e)) throw e;
    return false;
  }
  return bCrypto.timingSafeEqual(actual, dec.hash);
}

function needsRehash(stored, opts) {
  opts = opts || {};
  var dec = _phcDecode(stored);
  if (!dec) return true;
  if (dec.version !== ARGON2_VERSION) return true;
  if (!_withinCeiling(dec.params)) return true;
  var memoryCost  = opts.memoryCost  || C.BYTES.kib(64);
  var timeCost    = opts.timeCost    || 3;
  var parallelism = opts.parallelism || 1;
  if (dec.params.memoryCost  < memoryCost)  return true;
  if (dec.params.timeCost    < timeCost)    return true;
  if (dec.params.parallelism < parallelism) return true;
  return false;
}

module.exports = {
  argon2id:       ARGON2ID,
  isGateRefusal:  isGateRefusal,
  isArgon2Error:  isArgon2Error,
  exceedsCostCeiling: exceedsCostCeiling,
  hash:        hash,
  verify:      verify,
  needsRehash: needsRehash,
  costCeiling: costCeiling,
  gate:        gate,
  gateHandle:  gateHandle,
  reclaimGatePermits: reclaimGatePermits,
  stats:       stats,
  _phcEncode:  _phcEncode,
  _phcDecode:  _phcDecode,
};
