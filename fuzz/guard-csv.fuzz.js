"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "name,age\nalice,30\nbob,40",
  "=SUM(A1)\n",
  "@HYPERLINK\n",
  "+1+1\n",
  "-2-3\n",
  '"alice","30"\n"bob",40',
  "name,age\nalice‮,30",
  '"a""b","c"\n',
  "x,y,z\r\n1,2,3\r\n",
];

runner.fuzz({
  name:   "b.guardCsv.validate",
  target: function (input) { b.guardCsv.validate(input, { profile: "strict" }); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
