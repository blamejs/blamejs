// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: guardMailReply.validate
 */

var guardMailReply = require("../lib/guard-mail-reply");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var reply;
  try { reply = JSON.parse(text); } catch (_e) { return; }
  try {
    guardMailReply.validate(reply);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" &&
        (e.code.indexOf("mail-reply/") === 0 || e.code.indexOf("message-id/") === 0)) return;
    throw e;
  }
};
