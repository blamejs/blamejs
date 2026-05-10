"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "$.a.b.c",
  "$['a']['b']",
  "$..deep",
  "$[*]",
  "$[0:5:2]",
  "$.a[?(@.b > 1)]",
  "$.a[?(@.length > 0)]",
  "$['a' + 'b']",
  "$." + "a.".repeat(50) + "z",
  "$[" + "0,".repeat(200) + "1]",
];

runner.fuzz({
  name:   "b.safeJsonPath.validateExpression",
  target: function (input) { b.safeJsonPath.validateExpression(input); },
  generator: function () {
    var r = Math.random();
    if (r < 0.4) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.6) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.8) return runner.randomAscii(512);
    return runner.randomControlSalt(runner.pick(SEEDS));
  },
});
