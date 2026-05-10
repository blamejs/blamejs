"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "[section]\nkey = value\n",
  "[a]\nx=1\ny=2\n[b]\nz=3\n",
  "; comment line\n[a]\nkey = value\n",
  "# alt comment\n[a]\nkey = value\n",
  "[a]\nkey = \"quoted value\"\n",
  "[__proto__]\npolluted = true\n",
  "[a]\nkey = " + "x".repeat(4000) + "\n",
  "[" + "a".repeat(500) + "]\nk=1\n",
  "[a.b.c]\nk=1\n",
];

runner.fuzz({
  name:   "b.parsers.ini.parse",
  target: function (input) { b.parsers.ini.parse(input); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
