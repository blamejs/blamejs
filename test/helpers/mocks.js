"use strict";
/**
 * HTTP request/response mocks for middleware-style tests.
 *
 *   _mockReq(opts?)  — minimal { method, url, headers, socket } shape
 *   _mockRes()       — captures setHeader/writeHead/end into ._captured()
 *
 *   _bodyReq(...)    — EventEmitter-backed req with a body buffer that
 *                      replays via "data"/"end" on the next setImmediate.
 *                      Used by body-parser, csp-nonce, compression,
 *                      health, app-shutdown tests.
 *   _bodyRes()       — EventEmitter-backed res that captures status,
 *                      headers, and body chunks. Emits "finish" on end().
 *
 *   _streamingRes()  — like _bodyRes but supports getHeader/setHeader/
 *                      removeHeader (used by compression's in-flight
 *                      header inspection).
 */

function _mockReq(opts) {
  opts = opts || {};
  return {
    method:    opts.method || "GET",
    url:       opts.url || "/",
    pathname:  opts.pathname || (opts.url || "/").split("?")[0],
    headers:   Object.assign({}, opts.headers || {}),
    socket:    opts.socket || { remoteAddress: "127.0.0.1" },
  };
}

function _mockRes() {
  var headers = {};
  var statusCode = null;
  var bodyParts = [];
  var ended = false;
  return {
    statusCode:    null,
    writableEnded: false,
    setHeader:     function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:     function (k) { return headers[k.toLowerCase()]; },
    writeHead:     function (s, h) {
      statusCode = s;
      if (h) for (var k in h) headers[k.toLowerCase()] = h[k];
    },
    end:           function (b) { if (b !== undefined) bodyParts.push(b); ended = true; this.writableEnded = true; },
    _captured:     function () { return { status: statusCode, headers: headers, body: bodyParts.join(""), ended: ended }; },
  };
}

// EventEmitter-backed body req. Replays the supplied body bytes via
// "data" + "end" events on the next setImmediate, after listeners
// have attached.
function _bodyReq(method, headers, body) {
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method  = method;
  req.url     = "/";
  req.headers = Object.assign({}, headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { /* mock — no-op */ };
  setImmediate(function () {
    if (Buffer.isBuffer(body)) req.emit("data", body);
    else if (typeof body === "string") req.emit("data", Buffer.from(body));
    req.emit("end");
  });
  return req;
}

// EventEmitter-backed res. Tests register res.on("finish", ...) to
// know when end() has been called. Status + body captured.
function _bodyRes() {
  var EE = require("node:events").EventEmitter;
  var res = new EE();
  res.statusCode = null;
  res.headersSent = false;
  res._captured = "";
  res._endedStatus = null;
  res._headers = {};
  res.writeHead = function (s, h) {
    res.statusCode = s;
    res._endedStatus = s;
    res.headersSent = true;
    res._headers = h || {};
  };
  res.end = function (body) { if (body) res._captured += body; res.emit("finish"); };
  return res;
}

// Stream-shaped res with full setHeader/getHeader/removeHeader so
// middleware that inspects pre-write headers (compression) can
// interrogate the captured state.
function _streamingRes() {
  var EE = require("node:events").EventEmitter;
  var res = new EE();
  res._chunks = [];
  res._headers = {};
  res._statusCode = 200;
  res.headersSent = false;
  res.writeHead = function (status, statusMsgOrHeaders, headersIfMsg) {
    res._statusCode = status;
    res.headersSent = true;
    var h = null;
    if (headersIfMsg && typeof headersIfMsg === "object") h = headersIfMsg;
    else if (statusMsgOrHeaders && typeof statusMsgOrHeaders === "object" && !Array.isArray(statusMsgOrHeaders)) h = statusMsgOrHeaders;
    if (h) {
      var keys = Object.keys(h);
      for (var i = 0; i < keys.length; i++) res._headers[keys[i].toLowerCase()] = h[keys[i]];
    }
  };
  res.setHeader    = function (k, v) { res._headers[k.toLowerCase()] = v; };
  res.getHeader    = function (k)    { return res._headers[k.toLowerCase()]; };
  res.removeHeader = function (k)    { delete res._headers[k.toLowerCase()]; };
  res.write = function (chunk) {
    if (Buffer.isBuffer(chunk)) res._chunks.push(chunk);
    else if (typeof chunk === "string") res._chunks.push(Buffer.from(chunk));
    return true;
  };
  res.end = function (chunk) {
    if (chunk != null) res.write(chunk);
    res.emit("finish");
    return res;
  };
  res._captured = function () { return Buffer.concat(res._chunks); };
  return res;
}

module.exports = {
  _mockReq:       _mockReq,
  _mockRes:       _mockRes,
  _bodyReq:       _bodyReq,
  _bodyRes:       _bodyRes,
  _streamingRes:  _streamingRes,
};
