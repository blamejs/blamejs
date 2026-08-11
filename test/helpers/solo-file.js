// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * Which test files run ALONE, and who decides.
 *
 * A file that declares `SMOKE_RUN_SOLO` near its top is telling the runner it
 * fans out internally — a worker-thread scan, a child process per batch — and
 * so must not also compete with the parallel pool for the same cores. It gets
 * the whole machine and the multiplied budget instead.
 *
 * This lives in its own module, with no dependencies, for two reasons. The
 * runner reads it before any framework code is loaded, so it cannot come from
 * the helpers barrel (which pulls in the framework). And both of the runner's
 * paths need the SAME answer: the parallel path decides which files to hold
 * back from the pool, the sequential path decides which files get the longer
 * watchdog. Read the marker in only one of them and the default `npm test`
 * path silently keeps the ordinary ceiling while the file's own comment
 * promises the longer one.
 */

var fs = require("node:fs");

// Only the head of the file is read: the marker belongs at the top, where a
// reader meets it before the code, and scanning whole test files here would
// cost the runner a read of the entire suite before it starts.
var HEAD_BYTES = 2048;

// Missing or unreadable is NOT solo — a file the runner cannot read is a
// problem the runner reports when it tries to RUN it, with a real error,
// rather than a scheduling decision made here on a guess.
function isSoloFile(fullPath) {
  try {
    return fs.readFileSync(fullPath, "utf8").slice(0, HEAD_BYTES).indexOf("SMOKE_RUN_SOLO") !== -1;
  } catch (_e) {
    return false;
  }
}

module.exports = { isSoloFile: isSoloFile, HEAD_BYTES: HEAD_BYTES };
