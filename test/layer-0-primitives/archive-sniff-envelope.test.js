"use strict";
/**
 * Layer 0 — b.archive.sniffEnvelope — magic-byte identification
 * of recipient vs passphrase envelopes vs raw payload.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testSniffRecipient() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var sealed = b.archive.wrap(Buffer.from("PHI"), { recipient: pair });
  check("sniffEnvelope: BAWRP buffer returns \"recipient\"",
    b.archive.sniffEnvelope(sealed) === "recipient");
}

async function testSniffPassphrase() {
  var sealed = await b.archive.wrapWithPassphrase(Buffer.from("PHI"), {
    passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase",
  });
  check("sniffEnvelope: BAWPP buffer returns \"passphrase\"",
    b.archive.sniffEnvelope(sealed) === "passphrase");
}

async function testSniffRawBytes() {
  check("sniffEnvelope: plain bytes return \"none\"",
    b.archive.sniffEnvelope(Buffer.from("hello world")) === "none");
  check("sniffEnvelope: gzip bytes return \"none\" (gzip is not a wrap envelope)",
    b.archive.sniffEnvelope(Buffer.from([0x1f, 0x8b, 0x08, 0x00])) === "none");
  check("sniffEnvelope: tar header bytes return \"none\"",
    b.archive.sniffEnvelope(Buffer.alloc(512)) === "none");
}

async function testSniffEmpty() {
  check("sniffEnvelope: empty buffer returns \"none\"",
    b.archive.sniffEnvelope(Buffer.alloc(0)) === "none");
  check("sniffEnvelope: 1-byte buffer returns \"none\"",
    b.archive.sniffEnvelope(Buffer.from([0x42])) === "none");
}

async function testSniffNonBuffer() {
  check("sniffEnvelope: string input returns \"none\" (non-Buffer)",
    b.archive.sniffEnvelope("BAWRP") === "none");
  check("sniffEnvelope: null returns \"none\"",
    b.archive.sniffEnvelope(null) === "none");
  check("sniffEnvelope: undefined returns \"none\"",
    b.archive.sniffEnvelope(undefined) === "none");
}

async function testSniffUint8Array() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var sealed = b.archive.wrap(Buffer.from("X"), { recipient: pair });
  var u8 = new Uint8Array(sealed);
  check("sniffEnvelope: Uint8Array carrying BAWRP returns \"recipient\"",
    b.archive.sniffEnvelope(u8) === "recipient");
}

async function run() {
  await testSniffRecipient();
  await testSniffPassphrase();
  await testSniffRawBytes();
  await testSniffEmpty();
  await testSniffNonBuffer();
  await testSniffUint8Array();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-sniff-envelope] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
