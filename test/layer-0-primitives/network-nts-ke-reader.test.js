// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
// SMOKE_RUN_SOLO: growth checks here compare wall-clock time across input sizes, which a CPU shared with the smoke pool distorts.
"use strict";
/**
 * The reader b.network.ntp.nts.performKeHandshake feeds each TLS chunk of an
 * NTS-KE response to (RFC 8915 section 4).
 *
 *   - It returns every record once the End of Message record arrives,
 *     however the response is split across chunks, including one byte at a
 *     time.
 *   - It refuses a record whose header puts its end past the 64 KiB
 *     handshake limit as soon as the header arrives.
 *   - The work per chunk does not grow with the bytes already received: a
 *     response written four bytes at a time costs time linear in its length.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var nts = b.network.ntp.nts;

var REC_END           = 0;
var REC_NEXT_PROTOCOL = 1;
var REC_AEAD          = 4;
var REC_NEW_COOKIE    = 5;
var AEAD_SIV          = 15;

function _u16(v) { var buf = Buffer.alloc(2); buf.writeUInt16BE(v, 0); return buf; }

function _rec(critical, type, body) {
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE((critical ? 0x8000 : 0) | (type & 0x7fff), 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

function _response(extraRecords, cookieBytes) {
  var parts = [
    _rec(true, REC_NEXT_PROTOCOL, _u16(0)),
    _rec(true, REC_AEAD, _u16(AEAD_SIV)),
    _rec(false, REC_NEW_COOKIE, Buffer.alloc(cookieBytes || 32, 0xaa)),
  ];
  for (var i = 0; i < extraRecords; i++) parts.push(_rec(false, 0x1234, Buffer.alloc(0)));
  parts.push(_rec(true, REC_END, Buffer.alloc(0)));
  return Buffer.concat(parts);
}

function _feed(buf, chunkBytes) {
  var reader = nts._createKeReader();
  var records = null;
  for (var off = 0; off < buf.length && !records; off += chunkBytes) {
    records = reader.push(buf.subarray(off, Math.min(buf.length, off + chunkBytes)));
  }
  return records;
}

function testReaderAssemblesSplitResponses() {
  var got = _feed(_response(50), 4);
  check("KE reader returns every record once the End record arrives",
        Array.isArray(got) && got.length === 54 && got[got.length - 1].type === REC_END,
        String(got && got.length));
  var one = _feed(_response(0, 37), 1);
  check("KE reader assembles a response delivered one byte at a time",
        Array.isArray(one) && one.length === 4 && one[2].body.length === 37, String(one && one.length));
  var whole = _feed(_response(3), 100000);
  check("KE reader reads a response delivered in one chunk",
        Array.isArray(whole) && whole.length === 7, String(whole && whole.length));
  var partial = nts._createKeReader().push(_response(3).subarray(0, 20));
  check("KE reader returns null before the End record", partial === null);
}

function testReaderRefusesAnOversizedRecordAtItsHeader() {
  var caught = null;
  try { nts._createKeReader().push(Buffer.from([0x00, 0x05, 0xff, 0xff])); } catch (e) { caught = e; }
  check("KE reader refuses a record that would end past the 64 KiB limit at its header",
        caught instanceof nts.NtsError && caught.code === "nts/ke-too-large",
        caught ? (caught.code + " :: " + caught.message) : "no error");

  var caught2 = null;
  var reader = nts._createKeReader();
  try {
    for (var i = 0; i < 70; i++) reader.push(_rec(false, 0x1234, Buffer.alloc(1000)));
  } catch (e) { caught2 = e; }
  check("KE reader refuses a response that passes the 64 KiB limit with no End record",
        caught2 instanceof nts.NtsError && caught2.code === "nts/ke-too-large",
        caught2 ? (caught2.code + " :: " + caught2.message) : "no error");
}

function testReaderWorkIsLinearInChunks() {
  var small = _response(4000);
  var large = _response(8000);
  var growth = helpers.superlinearRatio(function (buf) { _feed(buf, 4); }, { small: small, large: large });
  check("KE reader work grows linearly with the number of chunks", !growth.superlinear,
        "ratio " + growth.ratio);
}

async function run() {
  await helpers.withDrain("network-nts-ke-reader", async function () {
    testReaderAssemblesSplitResponses();
    testReaderRefusesAnOversizedRecordAtItsHeader();
    testReaderWorkIsLinearInChunks();
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
