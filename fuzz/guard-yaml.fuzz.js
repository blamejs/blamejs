"use strict";

var b      = require("..");
var runner = require("./_runner");

// Deserialization-tag prefixes the guard MUST refuse — held as
// fragments so static scanners don't flag this fuzz fixture as
// embedding the full attack payload.
var DANGEROUS_TAG_PREFIX = "!!" + "python/object" + "/new:";
var DANGEROUS_JAVA_TAG   = "!!" + "java.util.HashMap";

var SEEDS = [
  "a: 1\nb: 2\n",
  "a: &anchor [1, 2, 3]\nb: *anchor\n",
  DANGEROUS_TAG_PREFIX + "shutil.rmtree\n",
  DANGEROUS_JAVA_TAG + "\n",
  "country: NO\n",                       // Norway problem
  "ports: [001, 010, 077]\n",            // leading-zero octals
  "a: 1\na: 2\n",                        // duplicate keys
  "---\na: 1\n---\nb: 2\n",              // multi-document
  "a: " + "&".repeat(100) + " 1\n",
];

runner.fuzz({
  name:   "b.guardYaml.parse",
  target: function (input) { b.guardYaml.parse(input, { profile: "strict" }); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
