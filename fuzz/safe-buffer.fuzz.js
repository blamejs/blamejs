// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var safeBuffer = require("../lib/safe-buffer");
var expected   = require("./_expected");

// safeBuffer is where operator-supplied bytes become a string or a Buffer.
// normalizeText decodes UTF-8 and strips a BOM, toBuffer coerces whatever a
// caller passed, and the base64 / base64url / hex readers parse text a peer
// controls. Each is reached with bytes the framework did not choose, so a lone
// surrogate, an overlong sequence, a truncated multi-byte character or a body
// just over a cap must answer or refuse with a typed error rather than crash.
module.exports.fuzz = function (data) {
  try { safeBuffer.normalizeText(data, {}); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
  try { safeBuffer.normalizeText(data, { maxBytes: 64 }); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
  try { safeBuffer.normalizeText(data, { stripBom: false }); }
  catch (e) { if (!expected.isExpected(e)) throw e; }

  try { safeBuffer.toBuffer(data, {}); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
  try { safeBuffer.toBuffer(data, { maxBytes: 32, allowString: false }); }
  catch (e) { if (!expected.isExpected(e)) throw e; }

  try { safeBuffer.byteLengthOf(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
  try { safeBuffer.byteLengthOfIfMeasurable(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }

  // The text readers take a string a peer controls, so decode the bytes first
  // and hand the result over however malformed it is.
  var text;
  try { text = data.toString("utf8"); } catch (_e) { return; }
  ["isBase64", "isCanonicalBase64", "isBase64Url", "isHex"].forEach(function (fn) {
    if (typeof safeBuffer[fn] !== "function") return;
    try { safeBuffer[fn](text); }
    catch (e) { if (!expected.isExpected(e)) throw e; }
  });

  // A chunk collector is the streaming path, and a body just over the cap is the
  // case the cap exists for.
  try {
    var collector = safeBuffer.boundedChunkCollector({ maxBytes: 128 });
    collector.push(data);
    collector.result();
  } catch (e) { if (!expected.isExpected(e)) throw e; }
};
