// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: guardTenantId.validate
 */

var guardTenantId = require("../lib/guard-tenant-id");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    guardTenantId.validate(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("tenant-id/") === 0) return;
    throw e;
  }
};
