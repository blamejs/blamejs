// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.parsers.json(req, opts) / b.parsers.multipart(req, opts) — standalone
 * async wrappers around the body-parser pipeline. Handlers that lazy-parse
 * (route-shape dispatch, streaming endpoints that bypass the middleware)
 * call these inline; the middleware composes the same parsing path.
 *
 * Run standalone: `node test/layer-0-primitives/parsers-standalone.test.js`
 */

var EventEmitter = require("events");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
// _contentType is the internal Content-Type parameter parser the
// middleware + standalone helpers share; exposed for tests.
var _contentType = require("../../lib/middleware/body-parser")._contentType;

function _streamReq(opts) {
  opts = opts || {};
  var req = new EventEmitter();
  req.method  = opts.method || "POST";
  req.url     = opts.url || "/";
  req.headers = Object.assign({}, opts.headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { /* mock — no-op */ };
  setImmediate(function () {
    var body = opts.body;
    if (Buffer.isBuffer(body))      req.emit("data", body);
    else if (typeof body === "string") req.emit("data", Buffer.from(body));
    else if (Array.isArray(body))      body.forEach(function (chunk) { req.emit("data", Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)); });
    req.emit("end");
  });
  return req;
}

// ---- parsers.json ----

async function testJsonParsesValidObject() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "13" },
    body: '{"hello":1}',
  });
  var parsed = await b.parsers.json(req, { maxBytes: b.constants.BYTES.kib(1) });
  check("parsers.json parses valid JSON", parsed && parsed.hello === 1);
}

async function testJsonRefusesOverMaxBytes() {
  var big = '{"x":"' + "a".repeat(2000) + '"}';
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": String(big.length) },
    body: big,
  });
  var threw = false;
  try { await b.parsers.json(req, { maxBytes: 100 }); }
  catch (e) { threw = e.code === "body-parser/too-large"; }
  check("parsers.json refuses over maxBytes", threw);
}

async function testJsonRefusesPrototypePollution() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "32" },
    body: '{"__proto__":{"polluted":true}}',
  });
  var parsed = await b.parsers.json(req, { maxBytes: b.constants.BYTES.kib(1) });
  // safeJson strips __proto__ — parsed object has no polluted attr.
  check("parsers.json strips __proto__", !({}).polluted);
  check("parsers.json returns sanitized object", parsed && Object.keys(parsed).length === 0);
}

async function testJsonStrictRefusesNonObjectStart() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "5" },
    body: '"hi"',
  });
  var threw = false;
  try { await b.parsers.json(req, { maxBytes: b.constants.BYTES.kib(1), strict: true }); }
  catch (e) { threw = e.code === "body-parser/json-strict"; }
  check("parsers.json strict refuses non-object/array head", threw);
}

async function testJsonRefusesBadOpts() {
  var threw1 = false;
  try { await b.parsers.json(_streamReq(), { maxBytes: 0 }); }
  catch (e) { threw1 = e.code === "body-parser/bad-max-bytes"; }
  check("parsers.json throws on maxBytes=0", threw1);
  var threw2 = false;
  try { await b.parsers.json(_streamReq(), { maxBytes: Infinity }); }
  catch (e) { threw2 = e.code === "body-parser/bad-max-bytes"; }
  check("parsers.json throws on non-finite maxBytes", threw2);

  async function jsonCode(opts) {
    var req = _streamReq({ headers: { "content-type": "application/json", "content-length": "2" }, body: "{}" });
    try { await b.parsers.json(req, opts); return "resolved"; }
    catch (e) { return e.code || String(e); }
  }
  var jsonCases = [
    ["maxBytes fraction",       { maxBytes: 1.5 },         "body-parser/bad-max-bytes"],
    ["maxBytes null",           { maxBytes: null },        "body-parser/bad-max-bytes"],
    ["strict as a string",      { strict: "false" },       "body-parser/bad-strict"],
    ["charset Node cannot use", { charset: "klingon" },    "body-parser/bad-charset"],
    ["parseHook not callable",  { parseHook: "trim" },     "body-parser/bad-parse-hook"],
    ["unknown option limit",    { limit: 10 },             "body-parser/bad-opts"],
    ["opts not an object",      5,                         "body-parser/bad-opts"],
  ];
  for (var i = 0; i < jsonCases.length; i += 1) {
    var got = await jsonCode(jsonCases[i][1]);
    check("parsers.json: " + jsonCases[i][0] + " -> " + jsonCases[i][2] + " (got " + got + ")", got === jsonCases[i][2]);
  }
  check("parsers.json: valid strict, charset and parseHook are accepted",
    await jsonCode({ strict: false, charset: "utf8", parseHook: function (v) { return v; } }) === "resolved");
}

// ---- parsers.multipart ----

function _multipartBody(boundary, parts) {
  var chunks = [];
  parts.forEach(function (p) {
    chunks.push("--" + boundary + "\r\n");
    var headers = 'Content-Disposition: form-data; name="' + p.name + '"';
    if (p.filename) headers += '; filename="' + p.filename + '"';
    chunks.push(headers + "\r\n");
    if (p.contentType) chunks.push("Content-Type: " + p.contentType + "\r\n");
    chunks.push("\r\n");
    chunks.push(p.value);
    chunks.push("\r\n");
  });
  chunks.push("--" + boundary + "--\r\n");
  return chunks.join("");
}

async function testMultipartParsesFieldsAndFiles() {
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "title",  value: "hello world" },
    { name: "upload", filename: "data.txt", contentType: "text/plain", value: "file-bytes-here" },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var result = await b.parsers.multipart(req, {
    maxBytes: b.constants.BYTES.mib(1),
    maxFiles: 5,
  });
  check("parsers.multipart returns fields", result.fields && result.fields.title === "hello world");
  check("parsers.multipart returns files",  Array.isArray(result.files) && result.files.length === 1);
  check("parsers.multipart file metadata",  result.files[0].filename === "data.txt" && result.files[0].size === 15);
  check("parsers.multipart hash present",   typeof result.files[0].hash === "string" && result.files[0].hash.length > 0);
  // Cleanup tmp file (handler-owned).
  try { require("fs").unlinkSync(result.files[0].path); } catch (_e) { /* tmp file already removed */ }
}

async function testMultipartRefusesNonMultipartType() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "2" },
    body: "{}",
  });
  var threw = false;
  try { await b.parsers.multipart(req, { maxBytes: 1024, maxFiles: 1 }); }
  catch (e) { threw = e.code === "body-parser/standalone-not-multipart"; }
  check("parsers.multipart refuses non-multipart Content-Type", threw);
}

async function testMultipartEnforcesMaxFiles() {
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "f1", filename: "a.txt", contentType: "text/plain", value: "x" },
    { name: "f2", filename: "b.txt", contentType: "text/plain", value: "y" },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var threw = false;
  try { await b.parsers.multipart(req, { maxBytes: b.constants.BYTES.mib(1), maxFiles: 1 }); }
  catch (e) { threw = e.code === "body-parser/multipart-too-many-files"; }
  check("parsers.multipart enforces maxFiles", threw);
}

async function testMultipartRefusesBadOpts() {
  var threw1 = false;
  try { await b.parsers.multipart(_streamReq({ headers: { "content-type": "multipart/form-data; boundary=x" } }), { maxBytes: 0, maxFiles: 1 }); }
  catch (e) { threw1 = e.code === "body-parser/bad-max-bytes"; }
  check("parsers.multipart throws on maxBytes=0", threw1);
  var threw2 = false;
  try { await b.parsers.multipart(_streamReq({ headers: { "content-type": "multipart/form-data; boundary=x" } }), { maxBytes: 1024, maxFiles: 0 }); }
  catch (e) { threw2 = e.code === "body-parser/bad-max-files"; }
  check("parsers.multipart throws on maxFiles=0", threw2);
  var threw3 = false;
  try { await b.parsers.multipart(_streamReq({ headers: { "content-type": "multipart/form-data; boundary=x" } }), { maxBytes: 1024, maxFiles: 2.5 }); }
  catch (e) { threw3 = e.code === "body-parser/bad-max-files"; }
  check("parsers.multipart throws on non-integer maxFiles", threw3);
}

// ---- Composition seam — middleware uses the same internals ----

async function testMiddlewareAndStandaloneShareImpl() {
  // The middleware's req.body for a JSON route must equal the standalone
  // result for the same input — verifies they share one parsing pipeline.
  var bodyText = '{"a":1,"b":[1,2,3]}';

  var req1 = _streamReq({
    headers: { "content-type": "application/json", "content-length": String(bodyText.length) },
    body: bodyText,
  });
  var standalone = await b.parsers.json(req1, { maxBytes: b.constants.BYTES.kib(1) });

  var req2 = _streamReq({
    headers: { "content-type": "application/json", "content-length": String(bodyText.length) },
    body: bodyText,
  });
  var res2 = b.testing.bodyRes();
  var mw = b.middleware.bodyParser({ json: { limit: b.constants.BYTES.kib(1) } });
  await new Promise(function (resolve) { mw(req2, res2, resolve); });
  var middlewareParsed = req2.body;

  check("standalone + middleware return identical shape",
        JSON.stringify(standalone) === JSON.stringify(middlewareParsed));
}

// ---- Prototype-pollution defense (CWE-915 / CWE-1321) ----
//
// Header/parameter/field names are request-controlled. The parsers build
// their maps from [key, value] pairs through Object.fromEntries instead
// of a computed-write (`target[key] = value`) sink, dropping the
// __proto__ / constructor / prototype names so a hostile name can never
// reach Object.prototype.

function testContentTypeIgnoresPoisonedParam() {
  // A Content-Type parameter literally named `__proto__` must not pollute
  // the prototype chain, and the legitimate boundary/charset must still
  // parse to the same shape.
  var ct = _contentType({
    headers: {
      "content-type":
        'multipart/form-data; boundary=----abc; __proto__=evil; charset=utf-8',
    },
  });
  check("content-type: type parsed", ct.type === "multipart/form-data");
  check("content-type: boundary parsed", ct.params.boundary === "----abc");
  check("content-type: charset parsed", ct.params.charset === "utf-8");
  check("content-type: __proto__ param dropped (no own prop)",
        !Object.prototype.hasOwnProperty.call(ct.params, "__proto__"));
  check("content-type: Object.prototype not polluted",
        ({}).evil === undefined && Object.prototype.evil === undefined);
}

async function testMultipartRefusesPoisonedFieldName() {
  // A multipart field whose Content-Disposition name is `__proto__` is
  // refused at the parse boundary (400) and never reaches the field map.
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "__proto__", value: '{"polluted":true}' },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var threw = false;
  try { await b.parsers.multipart(req, { maxBytes: b.constants.BYTES.mib(1), maxFiles: 5 }); }
  catch (e) { threw = e.code === "body-parser/multipart-poisoned-field"; }
  check("multipart: __proto__ field name refused with 400", threw);
  check("multipart: Object.prototype not polluted by field name",
        ({}).polluted === undefined && Object.prototype.polluted === undefined);
}

async function testMultipartRepeatedFieldShapeUnchanged() {
  // Success path: repeated field name → array; single → scalar. The
  // entries-merge accumulation must produce the same shape the prior
  // computed-write accumulation did.
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "tag", value: "a" },
    { name: "tag", value: "b" },
    { name: "tag", value: "c" },
    { name: "title", value: "solo" },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var result = await b.parsers.multipart(req, { maxBytes: b.constants.BYTES.mib(1), maxFiles: 5 });
  check("multipart: repeated field collapses to array in order",
        Array.isArray(result.fields.tag) &&
        result.fields.tag.length === 3 &&
        result.fields.tag[0] === "a" &&
        result.fields.tag[1] === "b" &&
        result.fields.tag[2] === "c");
  check("multipart: single field stays scalar", result.fields.title === "solo");
}

// The standalone parser must honor the documented `storage: "memory"` knob
// (serverless / read-only FS): the file part is buffered in RAM (files[].buffer)
// with no tmp path, instead of silently falling back to disk mode.
async function testMultipartStorageMemoryBuffersInRam() {
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "upload", filename: "mem.txt", contentType: "text/plain", value: "in-memory-bytes" },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var result = await b.parsers.multipart(req, { storage: "memory", maxBytes: b.constants.BYTES.mib(1) });
  check("parsers.multipart storage:memory buffers the file in RAM",
        result.files.length === 1 && Buffer.isBuffer(result.files[0].buffer) &&
        result.files[0].buffer.toString() === "in-memory-bytes");
  check("parsers.multipart storage:memory writes no tmp path",
        result.files[0].path === undefined || result.files[0].path === null);
}

// A bad `storage` value is an operator-config error → throw a TypeError at the
// call (mirrors b.middleware.bodyParser), not a silent disk-mode fallback.
async function testMultipartStorageRejectsBadValue() {
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [{ name: "f", value: "x" }]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var threw = null;
  try { await b.parsers.multipart(req, { storage: "ram" }); } catch (e) { threw = e; }
  check("parsers.multipart rejects an invalid storage value with a TypeError",
        threw instanceof TypeError);
}

// The documented `filenameCharsets` knob must pass through: a
// filename*=ISO-8859-1'' part is refused by default (utf-8 only, legacy
// filename= wins) and decoded only when the operator opts iso-8859-1 in.
async function testMultipartFilenameCharsetsOptIn() {
  var boundary = "----blamejstest" + Date.now();
  var body =
    "--" + boundary + "\r\n" +
    "Content-Disposition: form-data; name=\"doc\"; " +
      "filename=\"fallback.txt\"; filename*=ISO-8859-1''r%E9sum%E9.txt\r\n" +
    "Content-Type: text/plain\r\n\r\n" +
    "hello\r\n" +
    "--" + boundary + "--\r\n";
  function _mk() {
    return _streamReq({
      headers: {
        "content-type":   "multipart/form-data; boundary=" + boundary,
        "content-length": String(Buffer.byteLength(body)),
      },
      body: body,
    });
  }
  var def = await b.parsers.multipart(_mk(), { storage: "memory" });
  check("parsers.multipart default refuses iso-8859-1 filename* (legacy filename= wins)",
        def.files[0].filename === "fallback.txt");
  var optIn = await b.parsers.multipart(_mk(), { storage: "memory", filenameCharsets: ["utf-8", "iso-8859-1"] });
  check("parsers.multipart filenameCharsets opt-in decodes iso-8859-1 to résumé.txt",
        optIn.files[0].filename === "résumé.txt");
}

// Every rejection b.parsers.multipart documents, driven through the
// standalone parser with the input that produces it.
async function testMultipartRejectionCodes() {
  var fs = helpers.fs;
  var B = "----blamejsrej" + Date.now();
  var CT = "multipart/form-data; boundary=" + B;
  function part(headers, value) {
    return "--" + B + "\r\n" + headers + "\r\n\r\n" + value + "\r\n";
  }
  var END = "--" + B + "--\r\n";
  function field(name, value) {
    return part("Content-Disposition: form-data; name=\"" + name + "\"", value);
  }
  function file(name, filename, mime, value) {
    return part("Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\"\r\n" +
      "Content-Type: " + mime, value);
  }
  async function codeOf(contentType, body, opts, mutateReq) {
    var req = _streamReq({ headers: { "content-type": contentType }, body: body });
    if (mutateReq) mutateReq(req);
    try { await b.parsers.multipart(req, opts); return "resolved"; }
    catch (e) { return e.code || String(e); }
  }
  var mem = { storage: "memory" };
  var tmpRoot = fs.mkdtempSync(helpers.path.join(helpers.os.tmpdir(), "blamejs-mp-rej-"));
  var blocker = helpers.path.join(tmpRoot, "not-a-dir");
  fs.writeFileSync(blocker, "x");
  var diskDir = helpers.path.join(tmpRoot, "uploads");

  var cases = [
    ["no-boundary", "multipart/form-data", END, mem],
    ["bad-boundary", "multipart/form-data; boundary=" + "x".repeat(71), END, mem],
    ["malformed", CT, "--" + B + "XX\r\n", mem],
    ["headers-too-large", CT, "--" + B + "\r\nX-Long: " + "a".repeat(17 * 1024), mem],
    ["total-too-large", CT, field("n".repeat(80), "v") + END, { storage: "memory", maxBytes: 50 }],
    ["obs-fold", CT, part("Content-Disposition: form-data; name=\"a\"\r\n folded", "v") + END, mem],
    ["bad-header-value", CT, part("Content-Disposition: form-data; name=\"a\"\r\nX-H: a\u0000b", "v") + END, mem],
    ["bad-disposition", CT, part("Content-Disposition: attachment; name=\"a\"", "v") + END, mem],
    ["poisoned-field", CT, field("constructor", "v") + END, mem],
    ["bad-filename", CT, file("f", "..", "text/plain", "v") + END, mem],
    ["mime-not-allowed", CT, file("f", "a.txt", "text/plain", "v") + END,
      { storage: "memory", mimeAllowlist: ["image/png"] }],
    ["mime-not-allowed", CT, file("f", "a.png", "image/png", "v") + END,
      { storage: "memory", mimeAllowlist: ["image/png"], fields: { f: { mimeTypes: ["image/jpeg"] } } }],
    ["too-many-files", CT, file("f1", "a.txt", "text/plain", "x") + file("f2", "b.txt", "text/plain", "y") + END,
      { storage: "memory", maxFiles: 1 }],
    ["too-many-fields", CT, field("a", "1") + field("b", "2") + END, { storage: "memory", fieldCount: 1 }],
    ["file-filter-throw", CT, file("f", "a.txt", "text/plain", "v") + END,
      { storage: "memory", fileFilter: function () { throw new Error("filter failed"); } }],
    ["internal", CT, file("f", "a.txt", "text/plain", "v") + END,
      { storage: "memory", fileFilter: function () {
        return { get reject() { throw new Error("verdict unreadable"); } };
      } }],
    ["file-too-large", CT, file("f", "a.txt", "text/plain", "x".repeat(50)) + END, { storage: "memory", fileSize: 10 }],
    ["file-too-large", CT, file("f", "a.txt", "text/plain", "x".repeat(50)) + END,
      { storage: "memory", fields: { f: { maxBytes: 10 } } }],
    ["field-too-large", CT, field("a", "x".repeat(50)) + END, { storage: "memory", fieldSize: 5 }],
    ["total-too-large", CT, field("a", "x".repeat(300)) + END, { storage: "memory", maxBytes: 200 }],
    ["truncated", CT, "--" + B + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue", mem],
    ["tmpdir", CT, field("a", "v") + END, { storage: "disk", tmpDir: helpers.path.join(blocker, "sub") }],
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var got = await codeOf(cases[i][1], cases[i][2], cases[i][3]);
    check("parsers.multipart rejects with body-parser/multipart-" + cases[i][0] + " (case " + i + ")",
      got === "body-parser/multipart-" + cases[i][0]);
  }

  var streamCode = await codeOf(CT, [], mem, function (req) {
    var origEmit = req.emit;
    req.emit = function (ev) {
      if (ev === "end") return origEmit.call(req, "error", new Error("socket reset"));
      return origEmit.apply(req, arguments);
    };
  });
  check("parsers.multipart rejects a stream error with body-parser/multipart-stream",
    streamCode === "body-parser/multipart-stream");

  var origOpen = fs.openSync;
  fs.openSync = function () { throw new Error("EACCES: simulated"); };
  var openCode;
  try { openCode = await codeOf(CT, file("f", "a.txt", "text/plain", "v") + END, { storage: "disk", tmpDir: diskDir }); }
  finally { fs.openSync = origOpen; }
  check("parsers.multipart rejects an unopenable tmp file with body-parser/multipart-tmp-open",
    openCode === "body-parser/multipart-tmp-open");

  var origWrite = fs.writeSync;
  fs.writeSync = function () { throw new Error("ENOSPC: simulated"); };
  var writeCode;
  try { writeCode = await codeOf(CT, file("f", "a.txt", "text/plain", "v") + END, { storage: "disk", tmpDir: diskDir }); }
  finally { fs.writeSync = origWrite; }
  check("parsers.multipart rejects a failed tmp write with body-parser/multipart-tmp-write",
    writeCode === "body-parser/multipart-tmp-write");
  check("parsers.multipart removes the tmp file after a failed write",
    fs.readdirSync(diskDir).length === 0);

  var bigCode = await codeOf(CT,
    file("ok", "ok.txt", "text/plain", "kept") + file("f", "a.txt", "text/plain", "x".repeat(50)) + END,
    { storage: "disk", tmpDir: diskDir, fileSize: 10 });
  check("parsers.multipart disk mode: oversize second file rejects with multipart-file-too-large",
    bigCode === "body-parser/multipart-file-too-large");
  check("parsers.multipart removes the tmp files it wrote when it rejects",
    fs.readdirSync(diskDir).length === 0);

  fs.rmSync(tmpRoot, { recursive: true, force: true });
}

// Every option b.parsers.multipart documents is checked at the call, so a
// value that would switch a cap or a filter off is refused instead.
async function testMultipartOptionValidation() {
  var B = "----blamejsopt" + Date.now();
  var CT = "multipart/form-data; boundary=" + B;
  var body = "--" + B + "\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n" +
    "Content-Type: text/plain\r\n\r\n" + "y".repeat(5 * 1024) + "\r\n--" + B + "--\r\n";
  async function codeOf(opts) {
    try { await b.parsers.multipart(_streamReq({ headers: { "content-type": CT }, body: body }), opts); return "resolved"; }
    catch (e) { return e.code || (e instanceof TypeError ? "TypeError" : String(e)); }
  }
  var cases = [
    ["fileSize string",            { fileSize: "1kb" },                    "body-parser/bad-file-size"],
    ["fileSize NaN",               { fileSize: NaN },                      "body-parser/bad-file-size"],
    ["fileSize fraction",          { fileSize: 10.5 },                     "body-parser/bad-file-size"],
    ["fieldSize negative",         { fieldSize: -1 },                      "body-parser/bad-field-size"],
    ["fieldCount string",          { fieldCount: "many" },                 "body-parser/bad-field-count"],
    ["fieldCount null",            { fieldCount: null },                   "body-parser/bad-field-count"],
    ["maxBytes fraction",          { maxBytes: 1.5 },                      "body-parser/bad-max-bytes"],
    ["maxBytes null",              { maxBytes: null },                     "body-parser/bad-max-bytes"],
    ["fileFilter object",          { fileFilter: { reject: true } },       "body-parser/bad-file-filter"],
    ["mimeAllowlist string",       { mimeAllowlist: "image/png" },         "body-parser/bad-mime-allowlist"],
    ["mimeAllowlist with number",  { mimeAllowlist: ["image/png", 5] },    "body-parser/bad-mime-allowlist"],
    ["filenameCharsets string",    { filenameCharsets: "utf-8" },          "body-parser/bad-filename-charsets"],
    ["filenameCharsets unknown",   { filenameCharsets: ["windows-1252"] }, "body-parser/bad-filename-charsets"],
    ["fields array",               { fields: [] },                         "body-parser/bad-fields"],
    ["fields rule not an object",  { fields: { f: 5 } },                   "body-parser/bad-fields"],
    ["fields rule maxBytes",       { fields: { f: { maxBytes: "1kb" } } }, "body-parser/bad-fields"],
    ["fields rule mimeTypes",      { fields: { f: { mimeTypes: "a/b" } } }, "body-parser/bad-fields"],
    ["fields rule unknown key",    { fields: { f: { maxSize: 10 } } },     "body-parser/bad-fields"],
    ["audit without safeEmit",     { audit: { emit: function () {} } },    "body-parser/bad-audit"],
    ["tmpDir empty",               { tmpDir: "" },                         "body-parser/bad-tmp-dir"],
    ["unknown option totalSize",   { totalSize: 10 },                      "body-parser/bad-opts"],
    ["misspelled maxFile",         { maxFile: 1 },                         "body-parser/bad-opts"],
    ["opts not an object",         "memory",                               "body-parser/bad-opts"],
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var opts = typeof cases[i][1] === "object" && !Array.isArray(cases[i][1])
      ? Object.assign({ storage: "memory" }, cases[i][1]) : cases[i][1];
    var got = await codeOf(opts);
    check("parsers.multipart: " + cases[i][0] + " -> " + cases[i][2] + " (got " + got + ")", got === cases[i][2]);
  }
  var ok = await b.parsers.multipart(_streamReq({ headers: { "content-type": CT }, body: body }), {
    storage: "memory", fileSize: b.constants.BYTES.kib(8), fieldCount: 3, fieldSize: 100,
    mimeAllowlist: ["text/plain"], filenameCharsets: ["UTF-8", "ISO-8859-1"],
    fields: { f: { maxBytes: b.constants.BYTES.kib(8), mimeTypes: ["text/plain"] } },
    fileFilter: function () { return true; }, audit: null, tmpDir: null,
  });
  check("parsers.multipart: every documented option with a valid value is accepted",
    ok.files.length === 1 && ok.files[0].size === 5 * 1024);
}

// maxBytes counts every byte of the body: the preamble before the first
// boundary, the boundary lines, the part headers and the part content.
async function testMultipartWholeBodyAndHeaderLimits() {
  var B = "----blamejslim" + Date.now();
  var CT = "multipart/form-data; boundary=" + B;
  var tail = "--" + B + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--" + B + "--\r\n";
  async function codeOf(chunks, opts) {
    try { await b.parsers.multipart(_streamReq({ headers: { "content-type": CT }, body: chunks }), opts); return "resolved"; }
    catch (e) { return e.code || String(e); }
  }
  check("parsers.multipart: a 1 MiB preamble passes maxBytes 1024 -> multipart-total-too-large",
    await codeOf(["x".repeat(b.constants.BYTES.mib(1)) + "\r\n" + tail], { storage: "memory", maxBytes: 1024 }) ===
      "body-parser/multipart-total-too-large");
  var drip = [];
  for (var i = 0; i < 64; i += 1) drip.push("p".repeat(b.constants.BYTES.kib(4)));
  drip.push("\r\n" + tail);
  check("parsers.multipart: a preamble streamed in 4 KiB chunks past maxBytes -> multipart-total-too-large",
    await codeOf(drip, { storage: "memory", maxBytes: b.constants.BYTES.kib(64) }) ===
      "body-parser/multipart-total-too-large");
  var parts = "";
  for (var j = 0; j < 40; j += 1) parts += "--" + B + "\r\nContent-Disposition: form-data; name=\"e" + j + "\"\r\n\r\n\r\n";
  check("parsers.multipart: boundary and header bytes of empty fields count toward maxBytes",
    await codeOf([parts + "--" + B + "--\r\n"], { storage: "memory", maxBytes: 1024 }) ===
      "body-parser/multipart-total-too-large");
  check("parsers.multipart: a body under maxBytes with a short preamble still parses",
    await codeOf(["preamble\r\n" + tail], { storage: "memory", maxBytes: 1024 }) === "resolved");
  var bigHeaders = "--" + B + "\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Pad: " +
    "a".repeat(b.constants.BYTES.kib(40)) + "\r\n\r\nv\r\n--" + B + "--\r\n";
  check("parsers.multipart: a 40 KiB header block arriving in one chunk -> multipart-headers-too-large",
    await codeOf([bigHeaders], { storage: "memory" }) === "body-parser/multipart-headers-too-large");
}

async function run() {
  await testJsonParsesValidObject();
  await testJsonRefusesOverMaxBytes();
  await testJsonRefusesPrototypePollution();
  await testJsonStrictRefusesNonObjectStart();
  await testJsonRefusesBadOpts();
  await testMultipartParsesFieldsAndFiles();
  await testMultipartRefusesNonMultipartType();
  await testMultipartEnforcesMaxFiles();
  await testMultipartRefusesBadOpts();
  await testMiddlewareAndStandaloneShareImpl();
  testContentTypeIgnoresPoisonedParam();
  await testMultipartRefusesPoisonedFieldName();
  await testMultipartRepeatedFieldShapeUnchanged();
  await testMultipartStorageMemoryBuffersInRam();
  await testMultipartStorageRejectsBadValue();
  await testMultipartFilenameCharsetsOptIn();
  await testMultipartRejectionCodes();
  await testMultipartOptionValidation();
  await testMultipartWholeBodyAndHeaderLimits();
  console.log("OK — parsers-standalone tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
