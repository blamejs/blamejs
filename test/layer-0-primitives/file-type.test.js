// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _png()  { return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), Buffer.alloc(20)]); }
function _jpeg() { return Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(20)]); }
function _pdf()  { return Buffer.concat([Buffer.from("%PDF-1.7\n", "ascii"),  Buffer.alloc(20)]); }
function _gz()   { return Buffer.concat([Buffer.from([0x1F, 0x8B]), Buffer.alloc(20)]); }
function _pe()   { return Buffer.concat([Buffer.from([0x4D, 0x5A]), Buffer.alloc(20)]); }
function _elf()  { return Buffer.concat([Buffer.from([0x7F, 0x45, 0x4C, 0x46]), Buffer.alloc(20)]); }
function _polyglot() {
  // PNG header followed by what an attacker might claim is HTML.
  // Magic-byte check should still classify as PNG (the actual format).
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    Buffer.from("<script>alert(1)</script>", "utf8")]);
}

// #575 — the MIME/extension table was reachable only through the
// underscore-prefixed test hook, so a consumer that had just detected a type
// and needed a name for it forked a partial copy of the table.
function testMimeExtensionAccessors() {
  check("fileType.extensionFor is fn", typeof b.fileType.extensionFor === "function");
  check("fileType.mimeFor is fn",      typeof b.fileType.mimeFor === "function");

  check("extensionFor: image/png -> png", b.fileType.extensionFor("image/png") === "png");
  check("mimeFor: png -> image/png",      b.fileType.mimeFor("png") === "image/png");

  // A leading dot is the form a caller usually has in hand (path.extname).
  check("mimeFor: accepts a leading dot", b.fileType.mimeFor(".png") === "image/png");
  check("extensionFor: returns no leading dot",
    b.fileType.extensionFor("application/pdf") === "pdf");

  // Case is not significant in either direction: MIME types are
  // case-insensitive (RFC 2045 sec. 5.1) and extensions arrive in any case.
  check("extensionFor: MIME lookup is case-insensitive",
    b.fileType.extensionFor("IMAGE/PNG") === "png");
  check("mimeFor: extension lookup is case-insensitive",
    b.fileType.mimeFor("PNG") === "image/png");

  // A parameterised content type still resolves on its bare type — this is
  // the form a Content-Type header actually arrives in.
  check("extensionFor: ignores content-type parameters",
    b.fileType.extensionFor("image/png; name=logo.png") === "png");

  // Unknown is null, never a guess — a caller minting an object-store key
  // needs to know the framework does not recognise the type.
  check("extensionFor: unknown MIME is null", b.fileType.extensionFor("application/x-nonesuch") === null);
  check("mimeFor: unknown extension is null", b.fileType.mimeFor("nonesuch") === null);
  check("extensionFor: non-string is null",   b.fileType.extensionFor(null) === null);
  check("mimeFor: non-string is null",        b.fileType.mimeFor(42) === null);
  check("mimeFor: empty string is null",      b.fileType.mimeFor("") === null);
  check("extensionFor: empty string is null", b.fileType.extensionFor("") === null);

  // The accessors must agree with the table detect() answers from, in both
  // directions, for every row — a forked copy is exactly what drifts.
  var sigs = b.fileType._SIGNATURES;
  var roundTripped = sigs.every(function (row) {
    return b.fileType.extensionFor(row.mime) === row.extension &&
           b.fileType.mimeFor(row.extension) === row.mime;
  });
  check("accessors round-trip every signature row", roundTripped);

  // And the answer matches what detect() reports for real bytes.
  var detected = b.fileType.detect(_png());
  check("extensionFor names what detect detected",
    b.fileType.extensionFor(detected.mime) === detected.extension);
}

// A format spelled two ways must answer for both spellings.
//
// The extension table took ONE canonical extension per signature row, so every
// alias answered null: `.jpg` resolved and `.jpeg` did not, though they are the
// same format and `.jpeg` is what Windows and most cameras write. The gap is
// symmetric and was not only the reported one — `.tiff` resolved while `.tif`
// did not.
//
// It matters because of what the answer is FOR: a consumer comparing a declared
// extension against the MIME its detector reports gets `null` for a real image
// and has to decide what null means. A table that answers for one spelling and
// not the other is wrong in the direction that produces a wrong decision.
function testExtensionAliasesResolveToTheSameMime() {
  var PAIRS = [
    ["jpg", "jpeg", "image/jpeg"],
    ["tiff", "tif", "image/tiff"],
  ];
  PAIRS.forEach(function (p) {
    check("fileType.mimeFor: ." + p[0] + " -> " + p[2],
          b.fileType.mimeFor("." + p[0]) === p[2]);
    check("fileType.mimeFor: ." + p[1] + " -> " + p[2] + " (the alias spelling)",
          b.fileType.mimeFor("." + p[1]) === p[2]);
  });

  // An alias must not become the CANONICAL answer in the other direction: the
  // reverse lookup still names one extension per type, and it stays the one it
  // named before.
  check("fileType.extensionFor: image/jpeg still answers jpg",
        b.fileType.extensionFor("image/jpeg") === "jpg");
  check("fileType.extensionFor: image/tiff still answers tiff",
        b.fileType.extensionFor("image/tiff") === "tiff");

  // The control: an extension the framework genuinely does not know still
  // answers null, so this is not a table that started answering for anything.
  check("fileType.mimeFor: an unknown extension is still null",
        b.fileType.mimeFor(".sfx-not-a-format") === null);

  // And a format with no signature must not gain a MIME mapping. `.ico` is the
  // case: nothing in the registry detects the icon magic, so answering for the
  // extension would have mimeFor claim a format the detector cannot recognise.
  check("fileType.mimeFor: an extension with no signature stays null",
        b.fileType.mimeFor(".ico") === null);
}

async function run() {
  testMimeExtensionAccessors();
  testExtensionAliasesResolveToTheSameMime();
  check("fileType namespace present",                typeof b.fileType === "object");
  check("fileType.detect is fn",                     typeof b.fileType.detect === "function");
  check("fileType.assertOneOf is fn",                typeof b.fileType.assertOneOf === "function");

  // ---- Detection round-trips ----
  var pngDet = b.fileType.detect(_png());
  check("detect: PNG",                pngDet && pngDet.mime === "image/png" && pngDet.category === "image");
  var jpegDet = b.fileType.detect(_jpeg());
  check("detect: JPEG",               jpegDet && jpegDet.mime === "image/jpeg");
  var pdfDet = b.fileType.detect(_pdf());
  check("detect: PDF",                pdfDet && pdfDet.mime === "application/pdf" && pdfDet.category === "document");
  var gzDet = b.fileType.detect(_gz());
  check("detect: gzip",               gzDet && gzDet.category === "archive");
  var peDet = b.fileType.detect(_pe());
  check("detect: PE/Windows exe",     peDet && peDet.category === "executable");
  var elfDet = b.fileType.detect(_elf());
  check("detect: ELF",                elfDet && elfDet.category === "executable");

  // ---- Polyglot defense ----
  var poly = b.fileType.detect(_polyglot());
  check("detect: polyglot still PNG", poly && poly.mime === "image/png");

  // ---- assertOneOf happy path ----
  var ok = b.fileType.assertOneOf(_png(), ["image/png", "image/jpeg"]);
  check("assertOneOf: PNG passes",    ok && ok.mime === "image/png");
  var imgCat = b.fileType.assertOneOf(_jpeg(), ["image"]);
  check("assertOneOf: category match", imgCat && imgCat.mime === "image/jpeg");

  // ---- assertOneOf rejection ----
  var threwExe = null;
  try { b.fileType.assertOneOf(_pe(), ["image/png", "application/pdf"]); }
  catch (e) { threwExe = e; }
  check("assertOneOf: PE rejected",   threwExe && /file-type\/disallowed-type/.test(threwExe.code || ""));

  var threwUnknown = null;
  try { b.fileType.assertOneOf(Buffer.from("not-a-real-format-bytes"), ["image/png"]); }
  catch (e) { threwUnknown = e; }
  check("assertOneOf: unknown format", threwUnknown && /file-type\/unknown-type/.test(threwUnknown.code || ""));

  var threwEmpty = null;
  try { b.fileType.assertOneOf(Buffer.alloc(0), ["image/png"]); }
  catch (e) { threwEmpty = e; }
  check("assertOneOf: zero-byte rejected by default", threwEmpty && threwEmpty.code === "file-type/empty");

  var allowEmpty = b.fileType.assertOneOf(Buffer.alloc(0), ["image/png"], { allowEmpty: true });
  check("assertOneOf: zero-byte allowed when opted in", allowEmpty === null);

  // ---- detect() returns null for non-buffers and unrecognised content ----
  check("detect: null for non-buffer",  b.fileType.detect("not a buffer") === null);
  check("detect: null for empty",       b.fileType.detect(Buffer.alloc(0)) === null);
  check("detect: null for unknown",     b.fileType.detect(Buffer.from("not-a-real-format-bytes")) === null);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[file-type] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
