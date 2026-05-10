"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  '{"a":1}',
  '[1,2,3,null,true,false]',
  '"hello"',
  'null',
  'true',
  '0.0',
  '1e308',
  '{"__proto__":{"polluted":true}}',
  '{"constructor":{"prototype":{}}}',
  '{"a":{"b":{"c":{"d":1}}}}',
  '[' + new Array(1000).fill('1').join(',') + ']',
  '{"a":"' + 'x'.repeat(10000) + '"}',
];

runner.fuzz({
  name:   "b.safeJson.parse",
  target: function (input) { b.safeJson.parse(input); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomAscii(2048);
    if (r < 0.7) return runner.randomUtf8(2048);
    if (r < 0.85) return runner.randomBidiSalt(runner.pick(SEEDS));
    return runner.randomBytes(((Math.random() * 4096) | 0) + 1).toString("utf8");
  },
});
