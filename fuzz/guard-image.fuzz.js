// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var guardImage = require("../lib/guard-image");
var expected   = require("./_expected");

// guardImage is a metadata guard, so `validate` takes what the host primitive
// read rather than raw bytes. Two surfaces consume adversarial bytes anyway:
// `inspectMagic(bytes)` walks a signature table over the leading bytes of an
// upload, and `validate` reads `metadata.bytes` to route SVG and to compare the
// magic against the declared MIME. A header truncated mid-signature, a buffer
// shorter than any signature, and a run carrying two signatures at once all
// arrive from an upload, and each must answer or refuse with a typed
// GuardImageError rather than crash.
var MIMES = ["image/png", "image/jpeg", "image/svg+xml", "image/gif", "application/pdf"];

module.exports.fuzz = function (data) {
  try { guardImage.inspectMagic(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }

  // The mismatch class: the bytes say one thing and the declaration says
  // another. Driving every declared MIME against the same bytes covers both the
  // agreeing and the lying case whatever the bytes turn out to be.
  MIMES.forEach(function (mime) {
    try { guardImage.validate({ bytes: data, declaredMime: mime }, {}); }
    catch (e) { if (!expected.isExpected(e)) throw e; }
  });

  ["strict", "balanced", "permissive"].forEach(function (profile) {
    try { guardImage.validate({ bytes: data, declaredMime: "image/png" }, { profile: profile }); }
    catch (e) { if (!expected.isExpected(e)) throw e; }
  });

  // Dimensions and frame count come from the host as numbers it read from the
  // file, so a value derived from the bytes exercises the pixel and frame caps.
  var n = data.length ? data[0] * 256 + (data.length > 1 ? data[1] : 0) : 0;
  try {
    guardImage.validate({
      bytes: data, declaredMime: "image/png", width: n, height: n, frames: data.length,
    }, {});
  } catch (e) { if (!expected.isExpected(e)) throw e; }

  try { guardImage.sanitize({ bytes: data, declaredMime: "image/png" }, {}); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
};
