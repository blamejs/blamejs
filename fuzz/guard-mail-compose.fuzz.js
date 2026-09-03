// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: guardMailCompose.validate
 */

var guardMailCompose = require("../lib/guard-mail-compose");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var draft;
  try { draft = JSON.parse(text); } catch (_e) { return; }
  try {
    guardMailCompose.validate(draft);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("mail-compose/") === 0) return;
    throw e;
  }
};
