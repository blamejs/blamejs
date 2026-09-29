// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Sorting a message's parts into body and files costs the number of parts.
 *
 * SMOKE_RUN_SOLO: this file measures growth, and a runner sharing its cores
 * with sixty-three siblings reads contention as a curve.
 *
 * Deciding whether a named part is a file or the body asks whether anything
 * else in its container can be the body instead. That is a question about the
 * container, and asking it once per part walks every other part again: a
 * message with 2000 parts, which `maxParts` allows, costs 2000 scans of 2000,
 * on the request thread, for a message an ordinary sender can compose. The
 * answer is taken once per container and read per part.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _attachmentsOnly(parts) {
  var lines = [
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
  ];
  for (var i = 0; i < parts; i += 1) {
    lines.push("--m", "Content-Type: application/octet-stream",
               'Content-Disposition: attachment; filename="f' + i + '.bin"',
               "", "payload");
  }
  lines.push("--m--", "");
  return b.safeMime.parse(Buffer.from(lines.join("\r\n"), "utf8"),
                          { maxParts: parts + 8 });
}

function testSelectionCostFollowsThePartCount() {
  var small = _attachmentsOnly(500);                                                                  // allow:raw-byte-literal — test-only part counts
  var large = _attachmentsOnly(2000);                                                                 // allow:raw-byte-literal — test-only part counts
  var reading = helpers.superlinearRatio(function (tree) {
    b.safeMime.selectBodyParts(tree);
  }, { small: small, large: large });
  check("selection cost follows the part count, not its square",
        reading.superlinear === false, JSON.stringify(reading));

  // The same shape read through the consumer an operator drives.
  var files = b.safeMime.extractAttachments(large);
  check("and every part is still classified",
        files.length === 2000, String(files.length));                                                 // allow:raw-byte-literal — test-only part counts
}

async function run() {
  testSelectionCostFollowsThePartCount();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[safe-mime-selection-cost] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
