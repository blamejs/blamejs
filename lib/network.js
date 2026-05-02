"use strict";

var ntpCheck = require("./ntp-check");
var nts      = require("./network-nts");
var dns      = require("./network-dns");
var proxy    = require("./network-proxy");
var trust    = require("./network-tls");
var heartbeat = require("./network-heartbeat");

var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var NetworkError = defineClass("NetworkError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });

var SOCKET_DEFAULTS = {
  noDelay:           true,
  keepAlive:         true,
  keepAliveInitialDelayMs: 0,
  linger:            null,
};

function _setSocketNoDelay(value) {
  if (typeof value !== "boolean") {
    throw new NetworkError("socket.setDefaultNoDelay: expected boolean, got " + typeof value, "socket/bad-no-delay");
  }
  SOCKET_DEFAULTS.noDelay = value;
}

function _setSocketKeepAlive(opts) {
  opts = opts || {};
  validateOpts(opts, ["enable", "initialDelayMs"], "socket.setDefaultKeepAlive");
  if (opts.enable !== undefined) {
    if (typeof opts.enable !== "boolean") {
      throw new NetworkError("socket.setDefaultKeepAlive: enable must be boolean", "socket/bad-keepalive");
    }
    SOCKET_DEFAULTS.keepAlive = opts.enable;
  }
  if (opts.initialDelayMs !== undefined) {
    if (typeof opts.initialDelayMs !== "number" || !isFinite(opts.initialDelayMs) || opts.initialDelayMs < 0) {
      throw new NetworkError("socket.setDefaultKeepAlive: initialDelayMs must be non-negative finite number",
        "socket/bad-keepalive-delay");
    }
    SOCKET_DEFAULTS.keepAliveInitialDelayMs = opts.initialDelayMs;
  }
}

function _setSocketLinger(opts) {
  if (opts === false || opts === null) {
    SOCKET_DEFAULTS.linger = null;
    return;
  }
  validateOpts(opts || {}, ["enable", "timeoutMs"], "socket.setDefaultLinger");
  if (typeof opts.enable !== "boolean") {
    throw new NetworkError("socket.setDefaultLinger: enable must be boolean", "socket/bad-linger");
  }
  if (opts.enable && (typeof opts.timeoutMs !== "number" || opts.timeoutMs < 0)) {
    throw new NetworkError("socket.setDefaultLinger: timeoutMs must be non-negative number when enable=true",
      "socket/bad-linger-timeout");
  }
  SOCKET_DEFAULTS.linger = { enable: opts.enable, timeoutMs: opts.timeoutMs || 0 };
}

function _socketDefaults() {
  return {
    noDelay:                 SOCKET_DEFAULTS.noDelay,
    keepAlive:               SOCKET_DEFAULTS.keepAlive,
    keepAliveInitialDelayMs: SOCKET_DEFAULTS.keepAliveInitialDelayMs,
    linger:                  SOCKET_DEFAULTS.linger,
  };
}

function applyToSocket(socket) {
  if (!socket) return socket;
  try {
    if (typeof socket.setNoDelay === "function") socket.setNoDelay(SOCKET_DEFAULTS.noDelay);
    if (typeof socket.setKeepAlive === "function") {
      socket.setKeepAlive(SOCKET_DEFAULTS.keepAlive, SOCKET_DEFAULTS.keepAliveInitialDelayMs || 0);
    }
  } catch (_e) {}
  return socket;
}

var ntpFacade = {
  querySingle:    ntpCheck.querySingle,
  checkDrift:     ntpCheck.checkDrift,
  bootCheck:      ntpCheck.bootCheck,
  setThresholds:  ntpCheck.setThresholds,
  getThresholds:  ntpCheck.getThresholds,
  setServers:     function (list) {
    if (!Array.isArray(list) || list.length === 0) {
      throw new NetworkError("ntp.setServers: expected non-empty array", "ntp/bad-servers");
    }
    ntpFacade._defaultServers = list.slice();
    _emitObs("network.ntp.servers.set", { count: list.length });
  },
  getServers:     function () {
    return (ntpFacade._defaultServers || ntpCheck.DEFAULT_SERVERS).slice();
  },
  _defaultServers: null,
  nts:            nts,
};

function bootFromEnv(opts) {
  opts = opts || {};
  validateOpts(opts, ["env", "audit"], "network.bootFromEnv");
  var env = opts.env || process.env;
  var applied = { ntp: {}, dns: {}, proxy: false, tls: {}, heartbeat: 0, socket: {} };

  if (env.BLAMEJS_NTP_SERVERS) {
    var list = String(env.BLAMEJS_NTP_SERVERS).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    if (list.length > 0) { ntpFacade.setServers(list); applied.ntp.servers = list.length; }
  }
  var ntpTimeout = env.BLAMEJS_NTP_TIMEOUT_MS;
  if (ntpTimeout) {
    var t = parseInt(ntpTimeout, 10);
    if (isFinite(t) && t > 0) { ntpFacade._defaultTimeoutMs = t; applied.ntp.timeoutMs = t; }
  }
  var ntpWarn = env.BLAMEJS_NTP_DRIFT_WARN_MS;
  var ntpFatal = env.BLAMEJS_NTP_DRIFT_FATAL_MS;
  if (ntpWarn || ntpFatal) {
    var thr = {};
    if (ntpWarn)  { thr.warnMs  = parseInt(ntpWarn, 10);  applied.ntp.warnMs  = thr.warnMs; }
    if (ntpFatal) { thr.fatalMs = parseInt(ntpFatal, 10); applied.ntp.fatalMs = thr.fatalMs; }
    ntpCheck.setThresholds(thr);
  }

  var dnsServers = env.BLAMEJS_DNS_SERVERS;
  if (dnsServers) {
    var dl = String(dnsServers).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    if (dl.length > 0) { dns.setServers(dl); applied.dns.servers = dl.length; }
  }
  if (env.BLAMEJS_DNS_RESULT_ORDER)  { dns.setResultOrder(env.BLAMEJS_DNS_RESULT_ORDER); applied.dns.resultOrder = env.BLAMEJS_DNS_RESULT_ORDER; }
  if (env.BLAMEJS_DNS_FAMILY)        { dns.setFamily(parseInt(env.BLAMEJS_DNS_FAMILY, 10)); applied.dns.family = parseInt(env.BLAMEJS_DNS_FAMILY, 10); }
  if (env.BLAMEJS_DNS_LOOKUP_TIMEOUT_MS) { dns.setLookupTimeoutMs(parseInt(env.BLAMEJS_DNS_LOOKUP_TIMEOUT_MS, 10)); applied.dns.lookupTimeoutMs = parseInt(env.BLAMEJS_DNS_LOOKUP_TIMEOUT_MS, 10); }
  if (env.BLAMEJS_DNS_CACHE_TTL_MS)      { dns.setCacheTtlMs(parseInt(env.BLAMEJS_DNS_CACHE_TTL_MS, 10)); applied.dns.cacheTtlMs = parseInt(env.BLAMEJS_DNS_CACHE_TTL_MS, 10); }
  if (env.BLAMEJS_DOH_URL)               { dns.useDnsOverHttps({ url: env.BLAMEJS_DOH_URL }); applied.dns.doh = env.BLAMEJS_DOH_URL; }
  else if (env.BLAMEJS_DOH_PROVIDER)     { dns.useDnsOverHttps({ provider: env.BLAMEJS_DOH_PROVIDER }); applied.dns.dohProvider = env.BLAMEJS_DOH_PROVIDER; }
  if (env.BLAMEJS_DOT_HOST)              { dns.useDnsOverTls({ host: env.BLAMEJS_DOT_HOST, port: env.BLAMEJS_DOT_PORT ? parseInt(env.BLAMEJS_DOT_PORT, 10) : 853 }); applied.dns.dot = env.BLAMEJS_DOT_HOST; }

  if (env.HTTP_PROXY || env.http_proxy || env.HTTPS_PROXY || env.https_proxy ||
      env.NO_PROXY  || env.no_proxy  || env.ALL_PROXY    || env.all_proxy) {
    applied.proxy = proxy.fromEnv(env);
  }

  if (env.BLAMEJS_EXTRA_CA_CERTS) {
    trust.addCa(env.BLAMEJS_EXTRA_CA_CERTS, { label: "BLAMEJS_EXTRA_CA_CERTS" });
    applied.tls.fileLoaded = env.BLAMEJS_EXTRA_CA_CERTS;
  }
  if (env.BLAMEJS_EXTRA_CA_CERTS_DIR) {
    trust.addCaBundle(env.BLAMEJS_EXTRA_CA_CERTS_DIR, { label: "BLAMEJS_EXTRA_CA_CERTS_DIR" });
    applied.tls.dirLoaded = env.BLAMEJS_EXTRA_CA_CERTS_DIR;
  }
  if (env.BLAMEJS_USE_SYSTEM_TRUST === "1" || env.BLAMEJS_USE_SYSTEM_TRUST === "true") {
    trust.useSystemTrust(true);
    applied.tls.systemTrust = true;
  }

  if (env.BLAMEJS_SOCKET_NO_DELAY)             _setSocketNoDelay(env.BLAMEJS_SOCKET_NO_DELAY === "1" || env.BLAMEJS_SOCKET_NO_DELAY === "true");
  if (env.BLAMEJS_SOCKET_KEEPALIVE)            _setSocketKeepAlive({ enable: env.BLAMEJS_SOCKET_KEEPALIVE === "1" || env.BLAMEJS_SOCKET_KEEPALIVE === "true" });
  if (env.BLAMEJS_SOCKET_KEEPALIVE_DELAY_MS)   _setSocketKeepAlive({ initialDelayMs: parseInt(env.BLAMEJS_SOCKET_KEEPALIVE_DELAY_MS, 10) });
  applied.socket = _socketDefaults();

  var auditOn = opts.audit !== false;
  if (auditOn) {
    var sink;
    try { sink = audit(); } catch (_e) { sink = null; }
    if (sink && typeof sink.safeEmit === "function") {
      try {
        sink.safeEmit({
          action:   "network.boot.from_env",
          outcome:  "success",
          metadata: applied,
        });
      } catch (_e) {}
    }
  }
  _emitObs("network.boot.from_env", { source: "env" });
  return applied;
}

function snapshot() {
  return {
    ntp: {
      servers:     ntpFacade.getServers(),
      thresholds:  ntpCheck.getThresholds(),
    },
    dns: dns._stateForTest(),
    proxy: proxy.snapshot(),
    tls:  {
      systemTrust: trust.isSystemTrustEnabled(),
      caCount:     trust.getTrustStore().length,
    },
    heartbeat: heartbeat.statuses(),
    socket: _socketDefaults(),
  };
}

function _emitObs(name, fields) {
  try { observability().emit(name, fields || {}); } catch (_e) {}
}

function _resetForTest() {
  ntpFacade._defaultServers = null;
  ntpFacade._defaultTimeoutMs = null;
  if (typeof ntpCheck._resetThresholdsForTest === "function") ntpCheck._resetThresholdsForTest();
  dns._resetForTest();
  proxy._resetForTest();
  trust._resetForTest();
  heartbeat._resetForTest();
  SOCKET_DEFAULTS.noDelay = true;
  SOCKET_DEFAULTS.keepAlive = true;
  SOCKET_DEFAULTS.keepAliveInitialDelayMs = 0;
  SOCKET_DEFAULTS.linger = null;
}

module.exports = {
  ntp:        ntpFacade,
  dns:        dns,
  proxy:      proxy,
  tls:        trust,
  heartbeat:  heartbeat,
  socket: {
    setDefaultNoDelay:   _setSocketNoDelay,
    setDefaultKeepAlive: _setSocketKeepAlive,
    setDefaultLinger:    _setSocketLinger,
    defaults:            _socketDefaults,
    applyToSocket:       applyToSocket,
  },
  bootFromEnv:    bootFromEnv,
  snapshot:       snapshot,
  NetworkError:   NetworkError,
  _resetForTest:  _resetForTest,
};
