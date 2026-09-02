// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var cms      = require("../lib/cms-codec");
var expected = require("./_expected");

// b.cms parses CMS SignedData / EnvelopedData from untrusted DER (S/MIME
// messages, signed timestamps, enveloped payloads) on top of asn1-der. decode /
// parseSignedData MUST refuse a malformed structure with a typed cms/* error,
// never crash with an uncaught RangeError / TypeError.
module.exports.fuzz = function (data) {
  try { cms.decode(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
  try { cms.parseSignedData(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
};
