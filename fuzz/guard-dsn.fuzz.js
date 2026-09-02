// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: guardDsn.parse
 *
 * Targets the RFC 3464 DSN parser's bounded-parse contract. The
 * primitive defends header-injection (CR/LF/NUL/C0 refusal at each
 * field line) + oversize bodies + per-recipient count caps +
 * malformed status / action vocabulary.
 */

var guardDsn = require("../lib/guard-dsn");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  try {
    guardDsn.parse(data);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("guard-dsn/") === 0) return;
    throw e;
  }
};
