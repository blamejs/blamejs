"use strict";

var b      = require("..");
var runner = require("./_runner");

// safe-yaml is the parsers' YAML 1.2 safe-subset parser; rejects
// anchors / aliases / tags / multi-document streams. Distinct from
// b.guardYaml which is the source-level scanner.
var DANGEROUS_TAG = "!!" + "python/object" + "/apply:";

var SEEDS = [
  "a: 1\nb: 2\nc: [1, 2, 3]\n",
  "list:\n  - 1\n  - 2\n  - 3\n",
  "nested:\n  a:\n    b:\n      c: 1\n",
  "anchor: &x [1, 2]\nalias: *x\n",
  DANGEROUS_TAG + "shutil.rmtree\n",
  "---\na: 1\n---\nb: 2\n",
  "a: 1\n\ta: 2\n",                      // tab in indentation
  "<<: { a: 1 }\n",                      // merge key
  "key: " + "&".repeat(50) + " value\n",
];

runner.fuzz({
  name:   "b.parsers.yaml.parse",
  target: function (input) { b.parsers.yaml.parse(input); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
