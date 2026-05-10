"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  '<svg xmlns="http://www.w3.org/2000/svg"><circle r="10"/></svg>',
  '<svg><script>alert(1)</script></svg>',
  '<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>',
  '<svg><animate attributeName="href" to="javascript:alert(1)"/></svg>',
  '<svg><use href="https://attacker.example/x.svg"/></svg>',
  '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
  '<svg onload="alert(1)"><circle/></svg>',
  '<svg viewBox="0 0 ' + 'X'.repeat(500) + ' 100"/>',
];

runner.fuzz({
  name:   "b.guardSvg.validate",
  target: function (input) { b.guardSvg.validate(input, { profile: "strict" }); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
