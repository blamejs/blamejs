// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var safeUrl = require("../lib/safe-url");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    safeUrl.parse(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
