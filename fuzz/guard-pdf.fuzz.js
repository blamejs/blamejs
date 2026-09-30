// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var guardPdf = require("../lib/guard-pdf");
var expected = require("./_expected");

// guardPdf is a metadata guard, so `validate` takes what the host primitive
// read rather than raw bytes. Two surfaces consume adversarial bytes anyway:
// `inspectMagic(bytes)` decides whether the leading bytes claim to be a PDF, and
// `validate` reads `metadata.bytes` to check that claim against the declared
// MIME. A header truncated mid-signature and a buffer shorter than the signature
// both arrive from an upload, and each must answer or refuse with a typed
// GuardPdfError rather than crash.
module.exports.fuzz = function (data) {
  try { guardPdf.inspectMagic(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }

  ["application/pdf", "image/png", "application/octet-stream"].forEach(function (mime) {
    try { guardPdf.validate({ bytes: data, declaredMime: mime }, {}); }
    catch (e) { if (!expected.isExpected(e)) throw e; }
  });

  ["strict", "balanced", "permissive"].forEach(function (profile) {
    try {
      guardPdf.validate({ bytes: data, declaredMime: "application/pdf" }, { profile: profile });
    } catch (e) { if (!expected.isExpected(e)) throw e; }
  });

  // Page and object counts come from the host as numbers it read from the file,
  // so values derived from the bytes exercise the structural caps.
  var n = data.length ? data[0] : 0;
  try {
    guardPdf.validate({
      bytes: data, declaredMime: "application/pdf", pageCount: n, objectCount: data.length,
    }, {});
  } catch (e) { if (!expected.isExpected(e)) throw e; }

  try { guardPdf.sanitize({ bytes: data, declaredMime: "application/pdf" }, {}); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
};
