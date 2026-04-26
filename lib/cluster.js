"use strict";
/**
 * Cluster coordination — leader election + fencing tokens.
 *
 * Opt-in via `b.cluster.init(...)`. When init is never called, the
 * local process behaves as a permanent single leader: `isLeader()`
 * always returns true, `fencingToken()` returns 0, no heartbeat thread
 * runs, no DB is touched. Single-node deployments pay zero overhead.
 *
 * When init IS called, the framework starts a heartbeat that renews
 * the leader lease via the configured provider. On lease loss (network
 * partition, takeover, lease expiry) the node transitions to follower
 * and write-side framework primitives throw `NotLeaderError`.
 *
 * Threat model:
 *   - Two leaders writing simultaneously: prevented by fencing tokens.
 *     Every leader-only DB write includes the current token; a
 *     CHECK constraint on the audit-tip row rejects a stale token.
 *     The application-layer `requireLeader()` gate is just an early
 *     rejection optimisation; the DB constraint is the canonical guard.
 *   - Follower receiving a write: rejected at the framework boundary.
 *     Operators front the cluster with a load balancer that routes
 *     write paths to the current leader.
 *   - External-db unreachable: heartbeat fails; after `leaseTtl` no
 *     leader exists and writes fail closed. When the DB recovers,
 *     election resumes.
 *
 * Public API:
 *   await cluster.init(opts)             one-time bootstrap
 *   cluster.isLeader()                   sync; true on leader (or single-node)
 *   cluster.currentNodeId()              sync; configured nodeId
 *   cluster.fencingToken()               sync; current monotonic token
 *   cluster.requireLeader()              sync; throws NotLeaderError
 *   cluster.currentLeader()              async; { nodeId, leaseExpiresAt,
 *                                                 fencingToken } | null
 *   cluster.onTransition(fn)             register transition handler
 *   await cluster.shutdown()             releases lease, stops heartbeat
 */
var C = require("./constants");
var { FrameworkError, ClusterError } = require("./framework-error");
var { createLogger } = require("./logger");

var DEFAULT_LEASE_TTL    = C.TIME.seconds(30);
var DEFAULT_HEARTBEAT    = C.TIME.seconds(10);
var MIN_LEASE_TTL        = C.TIME.seconds(5);
var MIN_HEARTBEAT        = C.TIME.seconds(1);

var initialized      = false;
var terminated       = false;           // set true by shutdown() so the
                                        // permanent-leader fallback isn't
                                        // re-engaged after a graceful exit
var nodeId           = null;
var role             = null;            // 'leader' | 'follower'
var provider         = null;
var lease            = null;            // current lease (if leader)
var heartbeatTimer   = null;
var heartbeatMs      = null;
var leaseTtlMs       = null;
var transitionHandlers = [];
// Backend coordinates for write-dispatch code in audit/consent/etc.
// These are set when cluster.init is called with `externalDbBackend`
// (the default DB-row provider path); operators using a custom
// provider can set them via init opts directly.
var configuredExternalDbBackend = null;
var configuredDialect            = null;

var log = createLogger("cluster");

class NotLeaderError extends FrameworkError {
  constructor(message) {
    super(message || "not leader: write rejected by cluster gate", "NOT_LEADER");
    this.name = "NotLeaderError";
    this.statusCode = 503;            // operator's load balancer should retry on the leader
    this.isClusterError = true;
    this.isNotLeaderError = true;
  }
}

function _err(code, message, permanent) {
  return new ClusterError(code, message, permanent);
}

function _emitTransition(kind, detail) {
  var event = Object.assign({ kind: kind, nodeId: nodeId, at: Date.now() }, detail || {});
  for (var i = 0; i < transitionHandlers.length; i++) {
    try { transitionHandlers[i](event); }
    catch (e) { log.error("transition handler threw: " + e.message); }
  }
}

// ---- init ----

async function init(opts) {
  if (initialized) {
    throw _err("ALREADY_INITIALIZED", "cluster.init() called twice", true);
  }
  opts = opts || {};
  if (!opts.nodeId) {
    throw _err("INVALID_CONFIG", "cluster.init({ nodeId }) is required", true);
  }
  nodeId = String(opts.nodeId);

  leaseTtlMs = opts.leaseTtl != null ? Number(opts.leaseTtl) : DEFAULT_LEASE_TTL;
  if (leaseTtlMs < MIN_LEASE_TTL) {
    throw _err("INVALID_TTL",
      "leaseTtl must be >= " + MIN_LEASE_TTL + "ms (got " + leaseTtlMs + ")",
      true);
  }
  heartbeatMs = opts.heartbeatInterval != null
    ? Number(opts.heartbeatInterval)
    : DEFAULT_HEARTBEAT;
  if (heartbeatMs < MIN_HEARTBEAT) {
    throw _err("INVALID_HEARTBEAT",
      "heartbeatInterval must be >= " + MIN_HEARTBEAT + "ms (got " + heartbeatMs + ")",
      true);
  }
  if (heartbeatMs >= leaseTtlMs) {
    throw _err("INVALID_HEARTBEAT",
      "heartbeatInterval must be < leaseTtl (got heartbeat=" + heartbeatMs +
      ", leaseTtl=" + leaseTtlMs + "); recommend ~1/3 of leaseTtl",
      true);
  }

  role = (opts.role || "leader").toLowerCase();
  if (role !== "leader" && role !== "follower") {
    throw _err("INVALID_ROLE", "role must be 'leader' or 'follower'", true);
  }

  if (typeof opts.onTransition === "function") {
    transitionHandlers.push(opts.onTransition);
  }

  // Provider: either operator-supplied, or build the default DB-row
  // provider against an externalDb backend.
  if (opts.provider) {
    provider = opts.provider;
    // Operator-custom provider: they may still be writing framework
    // state to an externalDb backend, in which case they pass these
    // separately so write-dispatch code knows where to go.
    configuredExternalDbBackend = opts.externalDbBackend || null;
    configuredDialect = (opts.dialect || "postgres").toLowerCase();
  } else {
    if (!opts.externalDbBackend) {
      throw _err("INVALID_CONFIG",
        "cluster.init requires either { provider } or { externalDbBackend }", true);
    }
    var dbProvider = require("./cluster-provider-db");
    provider = dbProvider.create({
      externalDbBackend: opts.externalDbBackend,
      dialect:           opts.dialect,
    });
    configuredExternalDbBackend = opts.externalDbBackend;
    configuredDialect = (opts.dialect || "postgres").toLowerCase();
  }

  if (typeof provider.ensureSchema === "function") {
    await provider.ensureSchema();
  }

  initialized = true;
  log("initialized as nodeId='" + nodeId + "', role='" + role + "'");

  // Initial acquisition attempt (only if role === 'leader')
  if (role === "leader") {
    await _tryAcquire();
  }

  // Start heartbeat
  heartbeatTimer = setInterval(_heartbeat, heartbeatMs);
  heartbeatTimer.unref();
}

async function _tryAcquire() {
  if (role !== "leader") return;        // pinned-follower role: never claim
  try {
    var got = await provider.acquireLease(nodeId, leaseTtlMs);
    if (got) {
      var wasLeader = !!lease;
      lease = got;
      if (!wasLeader) {
        log("acquired lease — fencingToken=" + lease.fencingToken);
        _emitTransition("lease-acquired", { fencingToken: lease.fencingToken });
      }
    }
  } catch (e) {
    log.error("acquire failed: " + e.message);
  }
}

async function _heartbeat() {
  if (!initialized) return;
  if (!lease) {
    // Not currently leader — try to acquire (lease may have expired
    // on the previous holder).
    await _tryAcquire();
    return;
  }
  // We hold a lease — renew it.
  try {
    lease = await provider.renewLease(lease);
  } catch (e) {
    if (e.code === "LEASE_LOST") {
      log.error("lease lost: " + e.message);
      var lostToken = lease ? lease.fencingToken : null;
      lease = null;
      _emitTransition("lease-lost", { fencingToken: lostToken });
      // Attempt to re-acquire on the next heartbeat naturally.
    } else {
      // Transient error — retry on next heartbeat. If it persists past
      // leaseTtl another node will steal, and we'll detect via LEASE_LOST.
      log.error("renew failed transiently: " + e.message);
    }
  }
}

// ---- public sync surface ----

function isLeader() {
  if (terminated) return false;         // post-shutdown: never leader
  if (!initialized) return true;        // never-initialized: permanent leader
  return !!lease && Date.now() < lease.expiresAt;
}

// Has cluster.init been called with a real configuration? Used by
// write-dispatch code (audit, consent, …) to decide whether framework
// state should go to local SQLite or external-db.
function isClusterMode() {
  return initialized && !!configuredExternalDbBackend;
}

function externalDbBackend() {
  return configuredExternalDbBackend;
}

function dialect() {
  return configuredDialect;
}

function currentNodeId() {
  return initialized ? nodeId : "single-node-local";
}

function fencingToken() {
  if (!initialized) return 0;
  return lease ? lease.fencingToken : 0;
}

function requireLeader() {
  if (!isLeader()) {
    throw new NotLeaderError(
      "node '" + currentNodeId() + "' is not currently leader" +
      (initialized ? "" : " (cluster not initialized)")
    );
  }
}

async function currentLeader() {
  if (!initialized) {
    return { nodeId: "single-node-local", leaseExpiresAt: Infinity, fencingToken: 0 };
  }
  return await provider.currentLeader();
}

function onTransition(handler) {
  if (typeof handler !== "function") {
    throw _err("INVALID_HANDLER", "onTransition expects a function", true);
  }
  transitionHandlers.push(handler);
}

async function shutdown() {
  if (!initialized) return;
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
  if (lease) {
    try {
      await provider.releaseLease(lease);
      _emitTransition("lease-released", { fencingToken: lease.fencingToken });
      log("lease released on shutdown");
    } catch (e) {
      log.error("release on shutdown failed: " + e.message);
    }
    lease = null;
  }
  initialized = false;
  terminated = true;
  provider = null;
  role = null;
  leaseTtlMs = null;
  heartbeatMs = null;
  configuredExternalDbBackend = null;
  configuredDialect = null;
  transitionHandlers = [];
  // nodeId is preserved post-shutdown so audit metadata still reflects
  // who this process was; cleared only by _resetForTest.
}

// ---- test helpers — not part of public contract ----

function _resetForTest() {
  if (heartbeatTimer) clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  initialized = false;
  terminated = false;
  nodeId = null;
  role = null;
  provider = null;
  lease = null;
  leaseTtlMs = null;
  heartbeatMs = null;
  configuredExternalDbBackend = null;
  configuredDialect = null;
  transitionHandlers = [];
}

async function _heartbeatNowForTest() {
  // Drive one heartbeat synchronously without waiting for the timer —
  // lets tests deterministically observe lease state transitions.
  await _heartbeat();
}

module.exports = {
  init:                init,
  isLeader:            isLeader,
  isClusterMode:       isClusterMode,
  externalDbBackend:   externalDbBackend,
  dialect:             dialect,
  currentNodeId:       currentNodeId,
  fencingToken:        fencingToken,
  requireLeader:       requireLeader,
  currentLeader:       currentLeader,
  onTransition:        onTransition,
  shutdown:            shutdown,
  NotLeaderError:      NotLeaderError,
  _resetForTest:       _resetForTest,
  _heartbeatNowForTest: _heartbeatNowForTest,
};
