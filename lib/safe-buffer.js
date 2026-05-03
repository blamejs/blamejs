"use strict";
/**
 * Buffer-safety primitives — centralizes the input-normalize, capped
 * chunk collection, and secure-zero patterns that were scattered across
 * lib/parsers/*, lib/atomic-file.js, lib/object-store-*.js, and
 * lib/log-stream-*.js.
 *
 * Public API:
 *   safeBuffer.normalizeText(input, { maxBytes, stripBom, errorClass })
 *     Accept string | Buffer | Uint8Array → returns string. Strips a
 *     leading UTF-8 BOM (U+FEFF) by default. Throws errorClass(message,
 *     code) if input is the wrong type or exceeds maxBytes.
 *
 *   safeBuffer.toBuffer(data, { maxBytes, errorClass })
 *     Accept Buffer | Uint8Array | string → returns Buffer. Throws
 *     errorClass on type mismatch or oversize.
 *
 *   safeBuffer.boundedChunkCollector({ maxBytes, errorClass })
 *     Returns { push(chunk), result(), bytesCollected() }. Each push()
 *     enforces the cap on every chunk — the OOM defense for unbounded
 *     HTTP response bodies replacing the previous `chunks.push(c)` +
 *     `Buffer.concat(chunks)` pattern that accumulated arbitrary bytes
 *     before checking size.
 *
 *   safeBuffer.secureZero(buf)
 *     Best-effort zero of buf contents (`buf.fill(0)`). JavaScript can't
 *     truly zero memory — V8 may have copies — but `fill(0)` removes the
 *     in-Buffer reference so a heap-dump won't show the secret in this
 *     particular Buffer. No-op on non-Buffers.
 *
 * Why a default error class:
 *   Each caller (xml-safe, json-safe, atomic-file, ...) wants to throw
 *   its own format-specific error class with a particular `code`. The
 *   helpers accept `{ errorClass }` so the byte-handling lives here but
 *   the error type stays format-aware (existing tests check
 *   e.code === "xml/too-large" etc.). A default SafeBufferError is used
 *   if the caller doesn't pass one.
 */

var { FrameworkError } = require("./framework-error");

class SafeBufferError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "SafeBufferError";
    this.code = code || "buffer/invalid";
    this.isSafeBufferError = true;
  }
}

function _throw(errorClass, message, code) {
  var Cls = errorClass || SafeBufferError;
  throw new Cls(message, code);
}

// ---- normalizeText ----

function normalizeText(input, opts) {
  opts = opts || {};
  var maxBytes  = (typeof opts.maxBytes === "number" && opts.maxBytes > 0) ? opts.maxBytes : null;
  var stripBom  = opts.stripBom !== false;  // default true
  var errClass  = opts.errorClass;
  var typeCode  = opts.typeCode  || "buffer/wrong-input-type";
  var sizeCode  = opts.sizeCode  || "buffer/too-large";
  var typeMsg   = opts.typeMessage || "input must be string, Buffer, or Uint8Array";
  var sizeMsg   = opts.sizeMessage || "input exceeds maxBytes";

  var text;
  if (typeof input === "string")            text = input;
  else if (Buffer.isBuffer(input))          text = input.toString("utf8");
  else if (input instanceof Uint8Array)     text = Buffer.from(input).toString("utf8");
  else _throw(errClass, typeMsg, typeCode);

  if (stripBom && text.charCodeAt(0) === 0xFEFF) text = text.slice(1);

  if (maxBytes !== null && Buffer.byteLength(text, "utf8") > maxBytes) {
    _throw(errClass, sizeMsg, sizeCode);
  }
  return text;
}

// ---- toBuffer ----

function toBuffer(data, opts) {
  opts = opts || {};
  var maxBytes = (typeof opts.maxBytes === "number" && opts.maxBytes > 0) ? opts.maxBytes : null;
  var errClass = opts.errorClass;
  var typeCode = opts.typeCode  || "buffer/wrong-input-type";
  var sizeCode = opts.sizeCode  || "buffer/too-large";
  var typeMsg  = opts.typeMessage || "data must be Buffer, Uint8Array, or string";
  var sizeMsg  = opts.sizeMessage || "data exceeds maxBytes";

  var buf;
  if (Buffer.isBuffer(data))             buf = data;
  else if (typeof data === "string")     buf = Buffer.from(data, "utf8");
  else if (data instanceof Uint8Array)   buf = Buffer.from(data);
  else _throw(errClass, typeMsg, typeCode);

  if (maxBytes !== null && buf.length > maxBytes) {
    _throw(errClass, sizeMsg, sizeCode);
  }
  return buf;
}

// ---- boundedChunkCollector ----
//
// Replaces the unbounded `chunks.push(c); ... Buffer.concat(chunks)`
// pattern in HTTP response handlers. The cap is enforced at push() time
// so a 10-GB response from a hostile/misbehaving upstream rejects on the
// chunk that overflows — without first accumulating the whole 10 GB in
// the chunks array.

function boundedChunkCollector(opts) {
  opts = opts || {};
  // maxBytes must be a positive finite integer. Accepting `Infinity`
  // would defeat the entire point of the bounded collector (a hostile
  // 10-GB upstream would accumulate fully); accepting `3.5` would set
  // a non-sensical fractional cap that confuses downstream `total +
  // chunk.length > maxBytes` arithmetic. NaN, negative, zero, non-
  // numbers all reject with the same `buffer/bad-arg` so operators
  // see one consistent error at boot from a typo or misconfiguration.
  var maxBytes = (typeof opts.maxBytes === "number" &&
                  Number.isFinite(opts.maxBytes) &&
                  Number.isInteger(opts.maxBytes) &&
                  opts.maxBytes > 0) ? opts.maxBytes : null;
  if (maxBytes === null) {
    throw new SafeBufferError(
      "boundedChunkCollector requires maxBytes (positive finite integer); got " +
      JSON.stringify(opts.maxBytes),
      "buffer/bad-arg");
  }
  var errClass = opts.errorClass;
  var sizeCode = opts.sizeCode  || "buffer/too-large";
  var sizeMsg  = opts.sizeMessage || "stream body exceeds maxBytes";

  var chunks = [];
  var total = 0;

  return {
    push: function (chunk) {
      // Accept Buffer or Uint8Array (Node's res.on('data') yields Buffer
      // by default but consumers may have set encoding to get strings).
      if (typeof chunk === "string") chunk = Buffer.from(chunk, "utf8");
      else if (!Buffer.isBuffer(chunk) && chunk instanceof Uint8Array) chunk = Buffer.from(chunk);
      if (!Buffer.isBuffer(chunk)) {
        _throw(errClass, "chunk must be Buffer, Uint8Array, or string", "buffer/wrong-input-type");
      }
      if (total + chunk.length > maxBytes) {
        _throw(errClass, sizeMsg, sizeCode);
      }
      chunks.push(chunk);
      total += chunk.length;
    },
    result: function () {
      return Buffer.concat(chunks, total);
    },
    bytesCollected: function () { return total; },
  };
}

// ---- secureZero ----

function secureZero(buf) {
  if (Buffer.isBuffer(buf) || buf instanceof Uint8Array) {
    try { buf.fill(0); } catch (_e) { /* best effort — locked memory etc. */ }
  }
}

module.exports = {
  normalizeText:         normalizeText,
  toBuffer:              toBuffer,
  boundedChunkCollector: boundedChunkCollector,
  secureZero:            secureZero,
  SafeBufferError:       SafeBufferError,
};
