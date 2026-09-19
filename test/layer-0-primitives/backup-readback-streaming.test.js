// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The read-back comparison walks each file in chunks instead of holding both
 * copies in memory.
 *
 * `_firstBundleDifference` read the staged file and the read-back file whole,
 * with `readFileSync` on each, and compared the two buffers. A bundle holding
 * a large encrypted database entry therefore doubled peak memory during every
 * backup, and `bundleAdapterStorage` allows multi-gigabyte bundles by default.
 *
 * The second half is worse than the memory: the comparison runs inside the
 * verification path, and a failure there is read as a corrupt bundle. So an
 * allocation or file-size error while reading, on a bundle that stored
 * perfectly well, makes the run delete it.
 *
 * Sizes are compared first, which needs no bytes at all, and equal-sized
 * files are then compared a chunk at a time.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Large enough that holding both copies is unmistakable against the
// threshold, small enough to stay cheap under a parallel runner.
var BIG_BYTES = 48 * 1024 * 1024;
var HOLD_BOTH_FLOOR = 32 * 1024 * 1024;

function _writeBig(file, fillByte, lastByte) {
  var chunk = Buffer.alloc(1024 * 1024, fillByte);
  var fd = fs.openSync(file, "w");
  try {
    for (var written = 0; written < BIG_BYTES; written += chunk.length) {
      fs.writeSync(fd, chunk);
    }
    if (lastByte !== undefined) {
      fs.writeSync(fd, Buffer.from([lastByte]), 0, 1, BIG_BYTES - 1);
    }
  } finally { fs.closeSync(fd); }
}

function testALargeFileIsNeverReadWholeIntoMemory() {
  // The comparison is synchronous, so a sampling timer can never observe it:
  // the event loop is blocked for its whole duration. What IS observable is
  // how much each read asks for. A chunked walk never allocates a buffer the
  // size of the file, whatever the file's size.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-readback-stream-"));
  var realReadFileSync = fs.readFileSync;
  var realReadSync = fs.readSync;
  var largestWholeRead = 0;
  var largestChunk = 0;
  try {
    var a = path.join(root, "a");
    var c = path.join(root, "b");
    fs.mkdirSync(a); fs.mkdirSync(c);
    _writeBig(path.join(a, "db.enc"), 0x41);
    _writeBig(path.join(c, "db.enc"), 0x41);

    fs.readFileSync = function (file, opts) {
      var out = realReadFileSync.call(fs, file, opts);
      var size = out && out.length ? out.length : 0;
      if (size > largestWholeRead) largestWholeRead = size;
      return out;
    };
    fs.readSync = function (fd, buffer, offset, length, position) {
      var n = realReadSync.call(fs, fd, buffer, offset, length, position);
      if (n > largestChunk) largestChunk = n;
      return n;
    };

    var difference = b.backup._firstBundleDifferenceForTest(a, c);
    check("identical large files still compare equal", difference === null, String(difference));
    check("no single read pulls in the whole " + Math.round(BIG_BYTES / (1024 * 1024)) +
          " MiB file (largest whole-file read was " +
          Math.round(largestWholeRead / (1024 * 1024)) + " MiB)",
          largestWholeRead < HOLD_BOTH_FLOOR);
    check("the bytes were read in bounded chunks instead (largest " +
          Math.round(largestChunk / 1024) + " KiB)",
          largestChunk > 0 && largestChunk < HOLD_BOTH_FLOOR);
  } finally {
    fs.readFileSync = realReadFileSync;
    fs.readSync = realReadSync;
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function testTheComparisonStillFindsEveryDifference() {
  // Streaming must not blunt the check: a trailing byte is the case a chunked
  // walk gets wrong if it stops early, and a size difference is the case it
  // should answer without reading content at all.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-readback-diff-"));
  try {
    var a = path.join(root, "a");
    var c = path.join(root, "b");
    fs.mkdirSync(a); fs.mkdirSync(c);

    _writeBig(path.join(a, "db.enc"), 0x41);
    _writeBig(path.join(c, "db.enc"), 0x41);
    check("identical large files compare equal",
          b.backup._firstBundleDifferenceForTest(a, c) === null,
          String(b.backup._firstBundleDifferenceForTest(a, c)));

    _writeBig(path.join(c, "db.enc"), 0x41, 0x42);
    var tail = b.backup._firstBundleDifferenceForTest(a, c);
    check("a difference in the final byte is still found",
          tail !== null && tail.indexOf("differs") !== -1, String(tail));

    fs.writeFileSync(path.join(c, "db.enc"), "short");
    var sized = b.backup._firstBundleDifferenceForTest(a, c);
    check("a size difference is reported as one",
          sized !== null && sized.indexOf("bytes in storage") !== -1, String(sized));

    fs.rmSync(path.join(c, "db.enc"));
    var missing = b.backup._firstBundleDifferenceForTest(a, c);
    check("a missing file is still reported",
          missing !== null && missing.indexOf("missing") !== -1, String(missing));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  testTheComparisonStillFindsEveryDifference();
  testALargeFileIsNeverReadWholeIntoMemory();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-readback-streaming] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
