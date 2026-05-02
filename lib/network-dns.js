"use strict";

var dns = require("node:dns");
var net = require("node:net");
var https = require("node:https");
var tls = require("node:tls");
var dnsPromises = dns.promises;

var C = require("./constants");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var DnsError = defineClass("DnsError", { alwaysPermanent: false });

var observability = lazyRequire(function () { return require("./observability"); });

var STATE = {
  servers:        null,
  resultOrder:    null,
  family:         0,
  lookupTimeoutMs: 0,
  cacheTtlMs:     0,
  cacheNegativeTtlMs: 0,
  doh:            null,
  dot:            null,
};

var POSITIVE_CACHE = new Map();
var NEGATIVE_CACHE = new Map();

function _now() { return Date.now(); }

function _cacheGet(host, family) {
  var key = host + "/" + family;
  var pos = POSITIVE_CACHE.get(key);
  if (pos && pos.expiresAt > _now()) return { hit: true, value: pos.value };
  if (pos) POSITIVE_CACHE.delete(key);
  var neg = NEGATIVE_CACHE.get(key);
  if (neg && neg.expiresAt > _now()) return { hit: true, error: neg.error };
  if (neg) NEGATIVE_CACHE.delete(key);
  return { hit: false };
}

function _cachePutPositive(host, family, value) {
  if (STATE.cacheTtlMs <= 0) return;
  POSITIVE_CACHE.set(host + "/" + family, {
    value:     value,
    expiresAt: _now() + STATE.cacheTtlMs,
  });
}

function _cachePutNegative(host, family, error) {
  if (STATE.cacheTtlMs <= 0) return;
  var ttl = STATE.cacheNegativeTtlMs > 0 ? STATE.cacheNegativeTtlMs : Math.min(STATE.cacheTtlMs, C.TIME.seconds(30));
  NEGATIVE_CACHE.set(host + "/" + family, {
    error:     error,
    expiresAt: _now() + ttl,
  });
}

function _clearCache() {
  POSITIVE_CACHE.clear();
  NEGATIVE_CACHE.clear();
}

function setServers(serverList) {
  if (!Array.isArray(serverList) || serverList.length === 0) {
    throw new DnsError("dns/bad-servers", "dns.setServers: expected non-empty array of resolver IPs");
  }
  for (var i = 0; i < serverList.length; i++) {
    var s = serverList[i];
    if (typeof s !== "string" || s.length === 0) {
      throw new DnsError("dns/bad-server", "dns.setServers[" + i + "]: expected non-empty string, got " + typeof s);
    }
  }
  STATE.servers = serverList.slice();
  try { dns.setServers(serverList); } catch (e) {
    throw new DnsError("dns/setservers-failed", "dns.setServers failed: " + e.message);
  }
  _clearCache();
  _emitObs("network.dns.servers.set", { count: serverList.length });
}

function getServers() {
  if (STATE.servers) return STATE.servers.slice();
  try { return dns.getServers(); } catch (_e) { return []; }
}

function setResultOrder(order) {
  if (order !== "ipv4first" && order !== "verbatim" && order !== "ipv6first") {
    throw new DnsError("dns/bad-result-order",
      "dns.setResultOrder: expected 'ipv4first' | 'verbatim' | 'ipv6first', got " + JSON.stringify(order));
  }
  STATE.resultOrder = order;
  if (order === "ipv6first") {
    try { dns.setDefaultResultOrder("verbatim"); } catch (_e) {}
  } else {
    try { dns.setDefaultResultOrder(order); } catch (_e) {}
  }
  _clearCache();
  _emitObs("network.dns.result_order.set", { order: order });
}

function setFamily(fam) {
  if (fam !== 0 && fam !== 4 && fam !== 6) {
    throw new DnsError("dns/bad-family", "dns.setFamily: expected 0 | 4 | 6, got " + JSON.stringify(fam));
  }
  STATE.family = fam;
  _clearCache();
}

function setLookupTimeoutMs(ms) {
  if (typeof ms !== "number" || !isFinite(ms) || ms < 0) {
    throw new DnsError("dns/bad-timeout",
      "dns.setLookupTimeoutMs: expected non-negative finite number, got " + JSON.stringify(ms));
  }
  STATE.lookupTimeoutMs = ms;
}

function setCacheTtlMs(ms, negativeMs) {
  if (typeof ms !== "number" || !isFinite(ms) || ms < 0) {
    throw new DnsError("dns/bad-cache-ttl",
      "dns.setCacheTtlMs: expected non-negative finite number, got " + JSON.stringify(ms));
  }
  STATE.cacheTtlMs = ms;
  if (negativeMs !== undefined) {
    if (typeof negativeMs !== "number" || !isFinite(negativeMs) || negativeMs < 0) {
      throw new DnsError("dns/bad-cache-ttl",
        "dns.setCacheTtlMs negativeMs: expected non-negative finite number, got " + JSON.stringify(negativeMs));
    }
    STATE.cacheNegativeTtlMs = negativeMs;
  }
  if (ms === 0) _clearCache();
}

function useDnsOverHttps(opts) {
  opts = opts || {};
  validateOpts(opts, ["provider", "url", "method"], "dns.useDnsOverHttps");
  var url = opts.url;
  if (!url && opts.provider) {
    var p = String(opts.provider).toLowerCase();
    if (p === "cloudflare") url = "https://cloudflare-dns.com/dns-query";
    else if (p === "google")  url = "https://dns.google/dns-query";
    else if (p === "quad9")   url = "https://dns.quad9.net/dns-query";
    else throw new DnsError("dns/bad-doh-provider", "dns.useDnsOverHttps: unknown provider '" + opts.provider + "'");
  }
  if (typeof url !== "string" || url.indexOf("https://") !== 0) {
    throw new DnsError("dns/bad-doh-url",
      "dns.useDnsOverHttps: url must be an https:// string, got " + JSON.stringify(url));
  }
  var method = opts.method;
  if (method !== undefined && method !== "GET" && method !== "POST") {
    throw new DnsError("dns/bad-doh-method",
      "dns.useDnsOverHttps: method must be 'GET' | 'POST' | undefined (auto), got " +
      JSON.stringify(method));
  }
  STATE.doh = { url: url, method: method };
  _clearCache();
  _emitObs("network.dns.doh.set", { url: url, method: method || "auto" });
}

function useDnsOverTls(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "servername"], "dns.useDnsOverTls");
  if (typeof opts.host !== "string" || opts.host.length === 0) {
    throw new DnsError("dns/bad-dot-host", "dns.useDnsOverTls: host required");
  }
  STATE.dot = {
    host:       opts.host,
    port:       opts.port || 853,
    servername: opts.servername || opts.host,
  };
  _clearCache();
  _emitObs("network.dns.dot.set", { host: STATE.dot.host, port: STATE.dot.port });
}

function _withTimeout(promise, ms, host) {
  if (ms <= 0) return promise;
  return new Promise(function (resolve, reject) {
    var timer = setTimeout(function () {
      reject(new DnsError("dns/lookup-timeout", "dns lookup of '" + host + "' exceeded " + ms + "ms"));
    }, ms);
    timer.unref && timer.unref();
    promise.then(
      function (v) { clearTimeout(timer); resolve(v); },
      function (e) { clearTimeout(timer); reject(e); }
    );
  });
}

function _encodeDnsQuery(host, qtype) {
  var parts = host.split(".").filter(Boolean);
  var nameLen = 1;
  for (var i = 0; i < parts.length; i++) nameLen += 1 + Buffer.byteLength(parts[i], "ascii");
  var buf = Buffer.alloc(12 + nameLen + 4);
  var id = (Math.random() * 0xffff) | 0;
  buf.writeUInt16BE(id, 0);
  buf.writeUInt16BE(0x0100, 2);
  buf.writeUInt16BE(1, 4);
  var off = 12;
  for (var p = 0; p < parts.length; p++) {
    var s = parts[p];
    buf.writeUInt8(Buffer.byteLength(s, "ascii"), off++);
    off += buf.write(s, off, "ascii");
  }
  buf.writeUInt8(0, off++);
  buf.writeUInt16BE(qtype, off); off += 2;
  buf.writeUInt16BE(1, off);
  return { buf: buf, id: id };
}

function _decodeDnsAnswer(buf, qtype) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) throw new DnsError("dns/bad-reply", "dns reply truncated");
  var rcode = buf.readUInt8(3) & 0x0f;
  if (rcode !== 0) throw new DnsError("dns/no-result", "dns reply rcode " + rcode);
  var qdcount = buf.readUInt16BE(4);
  var ancount = buf.readUInt16BE(6);
  var off = 12;
  for (var q = 0; q < qdcount; q++) {
    while (off < buf.length && buf[off] !== 0) {
      if ((buf[off] & 0xc0) === 0xc0) { off += 2; break; }
      off += buf[off] + 1;
    }
    if (buf[off] === 0) off++;
    off += 4;
  }
  var addrs = [];
  for (var a = 0; a < ancount; a++) {
    while (off < buf.length && buf[off] !== 0) {
      if ((buf[off] & 0xc0) === 0xc0) { off += 2; break; }
      off += buf[off] + 1;
    }
    if (buf[off] === 0) off++;
    var rtype  = buf.readUInt16BE(off); off += 2;
    off += 2;
    off += 4;
    var rdlen  = buf.readUInt16BE(off); off += 2;
    if (rtype === qtype && qtype === 1 && rdlen === 4) {
      addrs.push(buf[off] + "." + buf[off + 1] + "." + buf[off + 2] + "." + buf[off + 3]);
    } else if (rtype === qtype && qtype === 28 && rdlen === 16) {
      var groups = [];
      for (var g = 0; g < 8; g++) {
        groups.push(buf.readUInt16BE(off + g * 2).toString(16));
      }
      addrs.push(groups.join(":"));
    }
    off += rdlen;
  }
  return addrs;
}

// DoH GET URL length cap. RFC 8484 §4.1 says clients MAY use POST when
// the GET URL would exceed implementation limits. We pick 2048 bytes
// (a conservative ceiling well below RFC 7230's recommended 8 KB) so
// long DNS names (e.g. ESNI / SVCB record queries with operator-side
// hostname concatenation) fall back cleanly. Operator can force POST
// always with `useDnsOverHttps({ url, method: "POST" })`.
var DOH_GET_URL_MAX_BYTES = 2048;

async function _dohLookup(host, family) {
  var qtype = family === 6 ? 28 : 1;
  var enc = _encodeDnsQuery(host, qtype);
  var b64 = enc.buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  var getUrl = STATE.doh.url + (STATE.doh.url.indexOf("?") === -1 ? "?" : "&") + "dns=" + b64;
  var forcedMethod = STATE.doh.method;
  var usePost = forcedMethod === "POST" || (!forcedMethod && getUrl.length > DOH_GET_URL_MAX_BYTES);
  var u = new URL(STATE.doh.url);
  return new Promise(function (resolve, reject) {
    var reqOpts = {
      hostname:   u.hostname,
      port:       u.port || 443,
      path:       u.pathname + u.search,
      method:     usePost ? "POST" : "GET",
      headers:    {
        "accept": "application/dns-message",
      },
      minVersion: "TLSv1.3",
      ecdhCurve:  C.TLS_GROUP_CURVE_STR,
    };
    if (usePost) {
      reqOpts.headers["content-type"]   = "application/dns-message";
      reqOpts.headers["content-length"] = enc.buf.length;
    } else {
      reqOpts.path = (new URL(getUrl)).pathname + (new URL(getUrl)).search;
    }
    var req = https.request(reqOpts, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        try {
          var body = Buffer.concat(chunks);
          if (res.statusCode !== 200) {
            reject(new DnsError("dns/doh-http", "DoH HTTP " + res.statusCode + " for " + host));
            return;
          }
          resolve(_decodeDnsAnswer(body, qtype));
        } catch (e) { reject(e); }
      });
    });
    req.on("error", function (e) { reject(new DnsError("dns/doh-failed", "DoH request failed: " + e.message)); });
    if (usePost) req.write(enc.buf);
    req.end();
  });
}

// DoT connection pool. Per-(host:port) cached TLS socket so successive
// lookups amortize the handshake. Sockets idle past the timeout are
// closed and removed; first lookup after expiry rebuilds. Each socket
// services one in-flight query at a time (DNS-over-TCP allows pipelining
// but the framework chooses serialization for simpler back-pressure).
var DOT_IDLE_TIMEOUT_MS = C.TIME.minutes(2);
var _dotPool = new Map();           // "host:port" → { sock, lastUsedAt, idle, queue }

function _dotPoolKey() {
  return STATE.dot.host + ":" + STATE.dot.port;
}

function _dotConnect() {
  var sock = tls.connect({
    host:       STATE.dot.host,
    port:       STATE.dot.port,
    servername: STATE.dot.servername,
    minVersion: "TLSv1.3",
    ecdhCurve:  C.TLS_GROUP_CURVE_STR,
  });
  sock.unref && sock.unref();
  return sock;
}

function _dotEvict(key) {
  var entry = _dotPool.get(key);
  if (!entry) return;
  try { entry.sock.destroy(); } catch (_e) {}
  _dotPool.delete(key);
}

async function _dotLookup(host, family) {
  var qtype = family === 6 ? 28 : 1;
  var enc = _encodeDnsQuery(host, qtype);
  var key = _dotPoolKey();
  var entry = _dotPool.get(key);
  if (entry && (Date.now() - entry.lastUsedAt > DOT_IDLE_TIMEOUT_MS)) {
    _dotEvict(key);
    entry = null;
  }
  if (!entry) {
    var sock = _dotConnect();
    entry = {
      sock:       sock,
      lastUsedAt: Date.now(),
      idle:       true,
      ready:      new Promise(function (res, rej) {
        sock.once("secureConnect", function () { res(); });
        sock.once("error", function (e) { rej(e); });
      }),
    };
    _dotPool.set(key, entry);
    sock.on("error", function () { _dotEvict(key); });
    sock.on("close", function () { if (_dotPool.get(key) === entry) _dotPool.delete(key); });
  }
  // Serialize: each socket handles one query at a time. If another
  // query is in flight, queue behind it.
  var waitTicket = entry._tail || Promise.resolve();
  entry._tail = waitTicket.then(function () {
    return new Promise(function (resolve, reject) {
      entry.idle = false;
      Promise.resolve(entry.ready).then(function () {
        var lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16BE(enc.buf.length, 0);
        var got = [];
        var expectLen = -1;
        var done = false;
        function settle(err, val) {
          if (done) return;
          done = true;
          entry.sock.removeListener("data", onData);
          entry.sock.removeListener("error", onErr);
          entry.idle = true;
          entry.lastUsedAt = Date.now();
          if (err) reject(err); else resolve(val);
        }
        function onData(chunk) {
          got.push(chunk);
          var all = Buffer.concat(got);
          if (expectLen === -1 && all.length >= 2) expectLen = all.readUInt16BE(0);
          if (expectLen >= 0 && all.length >= expectLen + 2) {
            try {
              settle(null, _decodeDnsAnswer(all.slice(2, 2 + expectLen), qtype));
            } catch (e) { settle(e); }
          }
        }
        function onErr(e) {
          _dotEvict(key);
          settle(new DnsError("dns/dot-failed", "DoT failed: " + e.message));
        }
        entry.sock.on("data", onData);
        entry.sock.on("error", onErr);
        entry.sock.write(lenBuf);
        entry.sock.write(enc.buf);
      });
    });
  });
  return entry._tail;
}

function _resetDotPool() {
  var keys = Array.from(_dotPool.keys());
  for (var i = 0; i < keys.length; i++) _dotEvict(keys[i]);
}

function _orderAddrs(addrs) {
  if (STATE.resultOrder === "ipv6first") {
    addrs.sort(function (a, b) { return (b.family || 0) - (a.family || 0); });
  } else if (STATE.resultOrder === "ipv4first") {
    addrs.sort(function (a, b) { return (a.family || 0) - (b.family || 0); });
  }
  return addrs;
}

async function _dualStack(queryFn, host, family) {
  if (family === 4 || family === 6) {
    return _withTimeout(queryFn(host, family), STATE.lookupTimeoutMs, host);
  }
  var first  = STATE.resultOrder === "ipv6first" ? 6 : 4;
  var second = first === 4 ? 6 : 4;
  var firstResult  = await _withTimeout(queryFn(host, first), STATE.lookupTimeoutMs, host).catch(function () { return []; });
  var secondResult = await _withTimeout(queryFn(host, second), STATE.lookupTimeoutMs, host).catch(function () { return []; });
  return (firstResult || []).concat(secondResult || []);
}

async function lookup(host, opts) {
  opts = opts || {};
  validateOpts(opts, ["family", "all"], "dns.lookup");
  var family = opts.family !== undefined ? opts.family : STATE.family;
  if (net.isIP(host)) {
    var fam = net.isIP(host);
    var literal = { address: host, family: fam };
    return opts.all ? [literal] : literal;
  }
  var cacheKey = family || 0;
  var cached = _cacheGet(host, cacheKey);
  if (cached.hit) {
    if (cached.error) throw cached.error;
    return opts.all ? cached.value : cached.value[0];
  }
  _emitObs("network.dns.lookup.requested", { family: cacheKey });
  var startMs = _now();
  try {
    var addrs;
    if (STATE.doh) {
      addrs = await _dualStack(_dohLookup, host, family);
    } else if (STATE.dot) {
      addrs = await _dualStack(_dotLookup, host, family);
    } else {
      var nodeOpts = { all: true };
      if (family === 4 || family === 6) nodeOpts.family = family;
      addrs = await _withTimeout(dnsPromises.lookup(host, nodeOpts), STATE.lookupTimeoutMs, host);
      if (!Array.isArray(addrs)) addrs = [addrs];
    }
    var normalized = (addrs || []).map(function (a) {
      if (typeof a === "string") return { address: a, family: net.isIP(a) || 4 };
      return { address: a.address || a, family: a.family || net.isIP(a.address || a) || 4 };
    });
    _orderAddrs(normalized);
    if (normalized.length === 0) {
      throw new DnsError("dns/no-result", "dns lookup of '" + host + "' returned no addresses");
    }
    _cachePutPositive(host, cacheKey, normalized);
    _emitObs("network.dns.lookup.success", { latencyMs: _now() - startMs, count: normalized.length });
    return opts.all ? normalized : normalized[0];
  } catch (e) {
    _cachePutNegative(host, cacheKey, e);
    _emitObs("network.dns.lookup.failure", { latencyMs: _now() - startMs, code: e.code || "unknown" });
    throw e;
  }
}

async function _resolveProtocol(host, family) {
  if (typeof host !== "string" || host.length === 0) {
    throw new DnsError("dns/bad-host", "dns.resolve" + family + ": host required");
  }
  if (net.isIP(host)) {
    if (net.isIP(host) !== family) {
      throw new DnsError("dns/wrong-family", "dns.resolve" + family + ": IP literal '" + host + "' is not family " + family);
    }
    return [host];
  }
  _emitObs("network.dns.resolve.requested", { family: family });
  var startMs = _now();
  try {
    var addrs;
    if (STATE.doh) {
      addrs = await _withTimeout(_dohLookup(host, family), STATE.lookupTimeoutMs, host);
    } else if (STATE.dot) {
      addrs = await _withTimeout(_dotLookup(host, family), STATE.lookupTimeoutMs, host);
    } else {
      var resolver = family === 6 ? dnsPromises.resolve6 : dnsPromises.resolve4;
      addrs = await _withTimeout(resolver(host), STATE.lookupTimeoutMs, host);
    }
    if (!Array.isArray(addrs)) addrs = [addrs];
    var normalized = addrs.map(function (a) { return typeof a === "string" ? a : (a.address || a); });
    if (normalized.length === 0) {
      throw new DnsError("dns/no-result", "dns.resolve" + family + " of '" + host + "' returned no addresses");
    }
    _emitObs("network.dns.resolve.success", { family: family, latencyMs: _now() - startMs, count: normalized.length });
    return normalized;
  } catch (e) {
    _emitObs("network.dns.resolve.failure", { family: family, latencyMs: _now() - startMs, code: e.code || "unknown" });
    if (e instanceof DnsError) throw e;
    throw new DnsError("dns/resolve-failed",
      "dns.resolve" + family + " of '" + host + "' failed: " + (e.message || String(e)));
  }
}

async function resolve4(host) { return _resolveProtocol(host, 4); }
async function resolve6(host) { return _resolveProtocol(host, 6); }
async function resolveAaaa(host) { return _resolveProtocol(host, 6); }

function nodeLookup(host, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  options = options || {};
  var fam = options.family !== undefined ? options.family : 0;
  lookup(host, { family: fam, all: !!options.all }).then(
    function (res) {
      if (options.all) callback(null, res);
      else callback(null, res.address, res.family);
    },
    function (err) { callback(err); }
  );
}

function _emitObs(name, fields) {
  try { observability().emit(name, fields || {}); } catch (_e) {}
}

function _stateForTest() { return STATE; }
function _resetForTest() {
  STATE.servers = null; STATE.resultOrder = null; STATE.family = 0;
  STATE.lookupTimeoutMs = 0; STATE.cacheTtlMs = 0; STATE.cacheNegativeTtlMs = 0;
  STATE.doh = null; STATE.dot = null;
  _clearCache();
  _resetDotPool();
}

module.exports = {
  setServers:        setServers,
  getServers:        getServers,
  setResultOrder:    setResultOrder,
  setFamily:         setFamily,
  setLookupTimeoutMs: setLookupTimeoutMs,
  setCacheTtlMs:     setCacheTtlMs,
  useDnsOverHttps:   useDnsOverHttps,
  useDnsOverTls:     useDnsOverTls,
  lookup:            lookup,
  resolve4:          resolve4,
  resolve6:          resolve6,
  resolveAaaa:       resolveAaaa,
  nodeLookup:        nodeLookup,
  clearCache:        _clearCache,
  DnsError:          DnsError,
  _stateForTest:     _stateForTest,
  _resetForTest:     _resetForTest,
};
