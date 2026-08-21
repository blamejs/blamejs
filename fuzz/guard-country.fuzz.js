// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.guardCountry.validate / .sanitize / .isValid
 *
 * Targets the ISO 3166-1 alpha-2 guard: shape refusal for anything but two
 * ASCII letters (fullwidth and homoglyph spellings included), the
 * user-assigned / exceptionally-reserved / formerly-used tables, and the
 * BIDI / zero-width / control / null-byte universal refuse.
 *
 * `isValid` is driven alongside `validate` because it is documented never to
 * throw: a code path that escapes its catch is a defect the validate-only
 * target would not surface.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input = data.toString("utf8");
  try {
    b.guardCountry.validate(input);
    // Documented total function: any throw here is the finding.
    if (typeof b.guardCountry.isValid(input) !== "boolean") {
      throw new Error("guardCountry.isValid returned a non-boolean");
    }
    b.guardCountry.sanitize(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("country.") === 0) return;
    throw e;
  }
};
