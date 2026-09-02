// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: guardMailMove.validate
 */

var guardMailMove = require("../lib/guard-mail-move");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var move;
  try { move = JSON.parse(text); } catch (_e) { return; }
  try {
    guardMailMove.validate(move);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("mail-move/") === 0) return;
    throw e;
  }
};
