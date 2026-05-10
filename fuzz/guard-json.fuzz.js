"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  '{"a":1}',
  '{"__proto__":{"x":1}}',
  '{"constructor":{"prototype":{"x":1}}}',
  '[1,2,3]',
  '{"a":' + '{"b":'.repeat(50) + 'null' + '}'.repeat(50) + '}',
  '{"a":1,"a":2}',                       // duplicate keys
  'NaN',
  'Infinity',
  '/* comment */ {"a":1}',
  "'a'",                                   // JSON5
  '﻿{"a":1}',                         // BOM
];

runner.fuzz({
  name:   "b.guardJson.parse",
  target: function (input) { b.guardJson.parse(input, { profile: "strict" }); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
