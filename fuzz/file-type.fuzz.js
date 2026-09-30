// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fileType = require("../lib/file-type");
var expected = require("./_expected");

// fileType walks a signature table over the leading bytes of a buffer whose
// contents the framework does not choose: b.fileUpload passes an upload body,
// b.mail passes an attachment, and b.safeMime passes a decoded part. detect and
// assertOneOf must answer or refuse with a typed FileTypeError, never crash on a
// truncated header, a buffer shorter than a signature, or a byte run that
// matches two formats at once.
module.exports.fuzz = function (data) {
  try { fileType.detect(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }

  // assertOneOf is the gate a host primitive calls, so drive it with an
  // allowlist the bytes may or may not satisfy, and with allowEmpty both ways
  // since an empty buffer is what a truncated upload delivers.
  try { fileType.assertOneOf(data, ["image/png", "application/pdf", "image/jpeg"]); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
  try { fileType.assertOneOf(data, ["image/png"], { allowEmpty: true }); }
  catch (e) { if (!expected.isExpected(e)) throw e; }

  // The two lookups a caller reaches for after a detect, driven from whatever
  // detect answered so a malformed answer cannot slip past them either.
  var detected = null;
  try { detected = fileType.detect(data); } catch (_e) { detected = null; }
  if (detected && typeof detected.mime === "string") {
    try { fileType.extensionFor(detected.mime); }
    catch (e) { if (!expected.isExpected(e)) throw e; }
  }
  if (detected && typeof detected.extension === "string") {
    try { fileType.mimeFor(detected.extension); }
    catch (e) { if (!expected.isExpected(e)) throw e; }
  }
};
