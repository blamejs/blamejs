"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  'title = "TOML Example"\n[server]\nhost = "localhost"\nport = 8080\n',
  'a = 1\nb = 2.5\nc = true\nd = "x"\n',
  '[a.b.c]\nx = 1\n',
  'a = [1, 2, 3]\nb = ["x", "y"]\n',
  'd = 1979-05-27T07:32:00Z\nl = 1979-05-27\n',
  '[__proto__]\npolluted = true\n',
  'a = "' + 'x'.repeat(2000) + '"\n',
  '[a]\n[a]\n',                          // duplicate-table
  'k = 9999999999999999999\n',           // > MAX_SAFE_INTEGER
];

runner.fuzz({
  name:   "b.parsers.toml.parse",
  target: function (input) { b.parsers.toml.parse(input); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
