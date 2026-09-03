// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: guardEnvelope.check
 *
 * Targets the RFC 9989 §4.4 DMARC Identifier Alignment primitive.
 * Engine mutates a JSON-encoded ctx; we decode + check.
 */

var guardEnvelope = require("../lib/guard-envelope");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var ctx;
  try { ctx = JSON.parse(data.toString("utf8")); }
  catch (_e) { return; }
  if (!ctx || typeof ctx !== "object") return;
  try {
    guardEnvelope.check(ctx);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("guard-envelope/") === 0) return;
    throw e;
  }
};
