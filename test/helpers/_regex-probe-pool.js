// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * _regex-probe-pool measures how a pattern's match time grows with its input,
 * in child processes that run under a deadline.
 *
 * codebase-patterns.test.js builds probe subjects for every regex in lib/ and
 * hands them here. No pattern is ever matched in the calling process: a match
 * that backtracks cubically or worse cannot be interrupted, so it would stall
 * the run that exists to report it. Each child is killed when one match runs
 * past `perMatchMs`, and the pattern it was matching is reported as never
 * returning.
 *
 * The patterns are spread round-robin over a few children that run at once.
 * Each child reads its share from a JSON file, because an environment block is
 * capped at 32 KiB on Windows and the subject lists of one pattern exceed it.
 *
 * A child writes one line per event to stdout:
 *
 *   B                       the job file is read
 *   P <pos>                 pattern <pos> of this child's share has started
 *   T <pos> <next> <worst>  a heartbeat: subjects before <next> are done
 *   R <pos> <result>        pattern <pos> is finished
 *
 * After every match the child writes a heartbeat if `TICK_MS` has passed since
 * its last line. A match therefore starts at most `TICK_MS` after the last line
 * the parent read, and a silence of `perMatchMs` means one match has been
 * running for at least `perMatchMs - TICK_MS`.
 *
 * Run as a script, this file is that child:
 *
 *   node _regex-probe-pool.js <job-file> <start-pos> <subject-from> <worst-json>
 *
 * The child matches in a worker thread. Its main thread reads stdin, which the
 * parent holds open and never writes. When the parent exits, including by
 * SIGKILL, stdin reaches end-of-file and the main thread calls process.exit(),
 * which stops the worker even in the middle of a match. A write to stdout that
 * fails with EPIPE also ends the child.
 */

var childProcess = require("child_process");
var fs = require("fs");
var os = require("os");
var path = require("path");
var workerThreads = require("worker_threads");

// The steps each subject goes through, which the gate's verdict is defined
// against. A first look at LOOK_CHARS decides whether the subject is worth
// measuring, a match at COST_CHARS gives the cost, and GROWTH_SIZES give the
// growth from the first size to the last, which is four times the input.
var LOOK_CHARS   = 2048;
var LOOK_MS      = 0.3;
var COST_CHARS   = 8192;
var COST_MS      = 5;
var GROWTH_SIZES = [8192, 16384, 32768];
var GROWTH_FLAG  = 8;
// A ratio taken between two readings this small measures timer noise.
var RATIO_FLOOR_MS = 0.02;
var TICK_MS        = 50;

var DEFAULT_PER_MATCH_MS = 5000;
var DEFAULT_ROUND_MS     = 20000;
var DEFAULT_MAX_ROUNDS   = 4;
var DEFAULT_WORKERS_MAX  = 8;
var WATCH_INTERVAL_MS    = 100;

// The subject a tuple builds at a given size. Sizes are in characters, so a
// multi-character filler repeats fewer times.
function subjectAt(tuple, size) {
  var fill = tuple[1];
  return tuple[0] + fill.repeat(Math.max(1, Math.floor(size / fill.length))) + tuple[2];
}

// ---- child ---------------------------------------------------------------

function _runChild(argv) {
  function quit() { process.exit(1); }
  process.stdin.on("data", function () { /* the parent never writes */ });
  process.stdin.on("end", quit);
  process.stdin.on("close", quit);
  process.stdin.on("error", quit);
  var matcher = new workerThreads.Worker(__filename, { workerData: { regexProbeArgv: argv } });
  matcher.on("error", quit);
  matcher.on("exit", function (code) { process.exit(code); });
}

function _runMatcher(argv) {
  var job = JSON.parse(fs.readFileSync(argv[0], "utf8"));
  var start = Number(argv[1]) || 0;
  var resumeFrom = Number(argv[2]) || 0;
  var resumeWorst = argv[3] ? JSON.parse(argv[3]) : null;
  var clock0 = process.hrtime.bigint();
  var state = { pos: start, next: resumeFrom, worst: null, lastWrite: 0 };

  function now() { return Number(process.hrtime.bigint() - clock0) / 1e6; }
  function emit(line) {
    try { fs.writeSync(1, line + "\n"); }
    catch (e) {
      // The parent is gone. Any other failure is read by the parent as a stall.
      if (e && e.code === "EPIPE") process.exit(1);
    }
    state.lastWrite = now();
  }
  function timed(re, text) {
    var a = process.hrtime.bigint();
    try { re.lastIndex = 0; re.test(text); } catch (_e) { /* a throwing pattern is not timed */ }
    var d = Number(process.hrtime.bigint() - a) / 1e6;
    if (now() - state.lastWrite >= TICK_MS) {
      emit("T " + state.pos + " " + state.next + " " + JSON.stringify(state.worst));
    }
    return d;
  }
  function best(re, text) {
    timed(re, text);
    var b = Infinity;
    for (var k = 0; k < 3; k += 1) b = Math.min(b, timed(re, text));
    return b;
  }

  emit("B");
  for (var p = start; p < job.patterns.length; p += 1) {
    var pat = job.patterns[p];
    state.pos = p;
    state.next = p === start ? resumeFrom : 0;
    state.worst = p === start && resumeWorst ? resumeWorst : { cost: 0, growth: 0, subject: -1 };
    emit("P " + p);
    var re = null;
    try { re = new RegExp(pat.source, pat.flags); } catch (_e) { re = null; }
    if (re !== null) _measureSubjects(re, pat.subjects, state, timed, best);
    emit("R " + p + " " + JSON.stringify(re === null ? { compiled: false } : state.worst));
  }
}

function _measureSubjects(re, subjects, state, timed, best) {
  for (; state.next < subjects.length; state.next += 1) {
    var tuple = subjects[state.next];
    if (!tuple[1]) continue;
    if (timed(re, subjectAt(tuple, LOOK_CHARS)) < LOOK_MS) continue;
    var big = subjectAt(tuple, COST_CHARS);
    var cost = Math.min(timed(re, big), timed(re, big));
    if (cost < COST_MS) continue;
    var growth = _growthOf(re, tuple, best);
    // Contention adds time to a reading and never removes it, and it lands
    // on the small size as often as on the large one, so a reading just under
    // the threshold is taken again and the larger ratio kept.
    if (growth >= GROWTH_FLAG / 2 && growth < GROWTH_FLAG) {
      growth = Math.max(growth, _growthOf(re, tuple, best));
    }
    if (growth === 0) continue;
    if (growth > state.worst.growth) {
      state.worst = { cost: cost, growth: growth, subject: state.next };
    }
    // The verdict needs one subject over both thresholds, so the first one
    // ends the measurement.
    if (state.worst.growth >= GROWTH_FLAG && state.worst.cost >= COST_MS) {
      state.next = subjects.length;
      return;
    }
  }
}

// The ratio between the best readings at the last and first growth sizes, or
// 0 when the first is too small to take a ratio of.
function _growthOf(re, tuple, best) {
  var row = [];
  for (var si = 0; si < GROWTH_SIZES.length; si += 1) {
    row.push(best(re, subjectAt(tuple, GROWTH_SIZES[si])));
  }
  if (row[0] <= RATIO_FLOOR_MS) return 0;
  return row[row.length - 1] / row[0];
}

// ---- parent --------------------------------------------------------------

function defaultWorkers() {
  var n = typeof os.availableParallelism === "function" ? os.availableParallelism()
    : os.cpus().length;
  return Math.max(1, Math.min(DEFAULT_WORKERS_MAX, n));
}

/**
 * measure(patterns, opts) -> Promise<result[]>
 *
 *   patterns   [{ source, flags, subjects: [[prefix, filler, tail], ...] }]
 *   opts.workers     children run at once (default: the number of CPUs, at
 *                    most 8)
 *   opts.perMatchMs  one match running this long is reported as never
 *                    returning (default 5000)
 *   opts.roundMs     one pattern measuring this long without finishing is
 *                    resumed at its next subject in a fresh child (default
 *                    20000)
 *   opts.maxRounds   rounds a pattern may take before it is reported
 *                    unmeasured (default 4)
 *
 * Each result is { neverReturned, unmeasured, cost, growth, subject }, where
 * `subject` is the index of the subject the cost and growth were read on, or
 * -1. The promise always resolves: a pattern the children could not finish is
 * reported `unmeasured`, never left out.
 */
function measure(patterns, opts) {
  opts = opts || {};
  var perMatchMs = opts.perMatchMs || DEFAULT_PER_MATCH_MS;
  var roundMs = opts.roundMs || DEFAULT_ROUND_MS;
  var maxRounds = opts.maxRounds || DEFAULT_MAX_ROUNDS;
  var results = new Array(patterns.length).fill(null);
  var rounds = new Array(patterns.length).fill(0);
  if (patterns.length === 0) return Promise.resolve(results);
  var laneCount = Math.max(1, Math.min(opts.workers || defaultWorkers(), patterns.length));
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "regex-probe-"));

  var lanes = [];
  for (var l = 0; l < laneCount; l += 1) {
    lanes.push({ list: [], file: null, child: null, after: null, done: false });
  }
  for (var k = 0; k < patterns.length; k += 1) lanes[k % laneCount].list.push(k);
  lanes.forEach(function (lane, idx) {
    lane.file = path.join(dir, "lane-" + idx + ".json");
    fs.writeFileSync(lane.file, JSON.stringify({
      patterns: lane.list.map(function (gk) { return patterns[gk]; }),
    }));
  });

  function unmeasured(worst) {
    return { neverReturned: false, unmeasured: true,
             cost: worst ? worst.cost : 0, growth: worst ? worst.growth : 0,
             subject: worst ? worst.subject : -1 };
  }

  return new Promise(function (resolve) {
    var open = laneCount;
    var watch = null;

    function finishLane(lane) {
      lane.child = null;
      lane.done = true;
      open -= 1;
      if (open > 0) return;
      clearInterval(watch);
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* a temp dir left behind */ }
      for (var r = 0; r < results.length; r += 1) {
        if (results[r] === null) results[r] = unmeasured(null);
      }
      resolve(results);
    }

    function spawnLane(lane, pos, from, worst) {
      if (pos >= lane.list.length) { finishLane(lane); return; }
      var child;
      try {
        child = childProcess.spawn(process.execPath,
          [__filename, lane.file, String(pos), String(from), worst ? JSON.stringify(worst) : ""],
          { stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
      } catch (_e) {
        for (var q = pos; q < lane.list.length; q += 1) results[lane.list[q]] = unmeasured(null);
        finishLane(lane);
        return;
      }
      lane.child = child;
      lane.after = null;
      lane.booted = false;
      lane.spawnedAt = Date.now();
      lane.lastLineAt = lane.spawnedAt;
      lane.pos = pos;
      lane.started = false;
      lane.patternAt = 0;
      lane.next = 0;
      lane.roundFrom = 0;
      lane.worst = null;
      lane.resume = { pos: pos, from: from, worst: worst };
      var buffered = "";
      child.stdin.on("error", function () { /* the child closed its end; 'close' reports it */ });
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", function (chunk) {
        if (lane.child !== child) return;
        buffered += chunk;
        var nl;
        while ((nl = buffered.indexOf("\n")) !== -1) {
          onLine(lane, buffered.slice(0, nl));
          buffered = buffered.slice(nl + 1);
        }
      });
      child.on("error", function () { /* reported by 'close' */ });
      child.on("close", function () {
        if (lane.child !== child) return;
        var after = lane.after;
        if (after === null && lane.pos < lane.list.length) {
          // Exited without being told to, before its share was done. The
          // pattern it was on, or was about to start, was not measured, and
          // the share resumes after it, so a child that dies on one pattern
          // every time still lets the rest of its share finish.
          if (results[lane.list[lane.pos]] === null) {
            results[lane.list[lane.pos]] = unmeasured(lane.started ? lane.worst : null);
          }
          after = { pos: lane.pos + 1, from: 0, worst: null };
        }
        if (after === null) after = { pos: lane.list.length, from: 0, worst: null };
        spawnLane(lane, after.pos, after.from, after.worst);
      });
    }

    function onLine(lane, line) {
      lane.lastLineAt = Date.now();
      var kind = line.charAt(0);
      if (kind === "B") { lane.booted = true; return; }
      var sp1 = line.indexOf(" ");
      var pos = parseInt(line.slice(2), 10);
      if (!isFinite(pos)) return;
      if (kind === "P") {
        // The first pattern a child starts may be a resumed one, carrying the
        // subject it resumes at and the worst reading so far.
        var resume = lane.resume;
        lane.resume = null;
        var resumed = resume !== null && resume.pos === pos;
        lane.next = resumed ? resume.from : 0;
        lane.roundFrom = lane.next;
        lane.worst = resumed ? resume.worst : null;
        lane.pos = pos;
        lane.started = true;
        lane.patternAt = lane.lastLineAt;
        return;
      }
      var sp2 = line.indexOf(" ", sp1 + 1);
      if (kind === "T") {
        var sp3 = line.indexOf(" ", sp2 + 1);
        lane.next = parseInt(line.slice(sp2 + 1, sp3), 10);
        try { lane.worst = JSON.parse(line.slice(sp3 + 1)); } catch (_e) { /* keep the last one */ }
        return;
      }
      if (kind === "R") {
        var got = null;
        try { got = JSON.parse(line.slice(sp2 + 1)); } catch (_e) { got = null; }
        var gk = lane.list[pos];
        if (got && got.compiled === false) {
          results[gk] = { neverReturned: false, unmeasured: false, cost: 0, growth: 0, subject: -1 };
        } else if (got && isFinite(got.cost) && isFinite(got.growth)) {
          results[gk] = { neverReturned: false, unmeasured: false, cost: got.cost,
                          growth: got.growth, subject: got.subject };
        } else {
          results[gk] = unmeasured(lane.worst);
        }
        lane.started = false;
        lane.pos = pos + 1;
      }
    }

    function stop(lane, after) {
      lane.after = after;
      try { lane.child.kill(); } catch (_e) { /* already gone; 'close' still fires */ }
    }

    watch = setInterval(function () {
      var t = Date.now();
      lanes.forEach(function (lane) {
        if (lane.done || lane.child === null || lane.after !== null) return;
        var gk = lane.list[lane.pos];
        if (!lane.booted) {
          if (t - lane.spawnedAt < roundMs) return;
          results[gk] = unmeasured(null);
          stop(lane, { pos: lane.pos + 1, from: 0, worst: null });
          return;
        }
        if (!lane.started) return;
        if (t - lane.lastLineAt >= perMatchMs) {
          results[gk] = { neverReturned: true, unmeasured: false, cost: 0, growth: 0, subject: -1 };
          stop(lane, { pos: lane.pos + 1, from: 0, worst: null });
          return;
        }
        if (t - lane.patternAt < roundMs) return;
        rounds[gk] += 1;
        if (lane.next > lane.roundFrom && rounds[gk] < maxRounds) {
          stop(lane, { pos: lane.pos, from: lane.next, worst: lane.worst });
        } else {
          results[gk] = unmeasured(lane.worst);
          stop(lane, { pos: lane.pos + 1, from: 0, worst: null });
        }
      });
    }, WATCH_INTERVAL_MS);

    lanes.forEach(function (lane) { spawnLane(lane, 0, 0, null); });
  });
}

module.exports = {
  measure:      measure,
  subjectAt:    subjectAt,
  COST_CHARS:   COST_CHARS,
  COST_MS:      COST_MS,
  GROWTH_FLAG:  GROWTH_FLAG,
  GROWTH_SIZES: GROWTH_SIZES,
  PER_MATCH_MS: DEFAULT_PER_MATCH_MS,
};

if (!workerThreads.isMainThread && workerThreads.workerData &&
    workerThreads.workerData.regexProbeArgv) {
  _runMatcher(workerThreads.workerData.regexProbeArgv);
} else if (require.main === module) {
  _runChild(process.argv.slice(2));
}
