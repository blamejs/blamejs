"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeAgent(name) {
  return {
    name: name,
    folders: function (args) { return Promise.resolve({ folders: [{ name: "INBOX" }] }); },
    fetch:   function (args) { return Promise.resolve({ subject: name + ":" + args.objectId }); },
  };
}

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("create is fn",          typeof b.agent.orchestrator.create === "function");
  check("shardFor is fn",         typeof b.agent.orchestrator.shardFor === "function");
  check("AgentOrchestratorError", typeof b.agent.orchestrator.AgentOrchestratorError === "function");
  check("guards.registry",        b.agent.orchestrator.guards.registry === b.guardAgentRegistry);
  var e = new b.agent.orchestrator.AgentOrchestratorError("agent-orchestrator/test", "t");
  check("error carries code",     e.code === "agent-orchestrator/test");
}

async function testRegisterLookupUnregister() {
  var orch = b.agent.orchestrator.create({});
  var agent = _fakeAgent("acme");
  var r = await orch.register("tenant-acme.mail", agent, { agentKind: "mail", tenantId: "acme" });
  check("register: returns name",       r.name === "tenant-acme.mail");
  check("register: registeredAt is num", typeof r.registeredAt === "number");

  var looked = await orch.lookup("tenant-acme.mail");
  check("lookup: returns agent",         looked === agent);

  var miss = await orch.lookup("nope");
  check("lookup: miss returns null",     miss === null);

  await expectRejection("register: duplicate refused",
    orch.register("tenant-acme.mail", agent, { agentKind: "mail" }),
    "agent-orchestrator/duplicate");

  var u = await orch.unregister("tenant-acme.mail");
  check("unregister: returns name",     u.name === "tenant-acme.mail");

  await expectRejection("unregister: not-found refused",
    orch.unregister("tenant-acme.mail"),
    "agent-orchestrator/not-found");
}

async function testList() {
  var orch = b.agent.orchestrator.create({});
  await orch.register("tenant-a.mail",  _fakeAgent("a"), { agentKind: "mail", tenantId: "a" });
  await orch.register("tenant-b.mail",  _fakeAgent("b"), { agentKind: "mail", tenantId: "b" });
  await orch.register("tenant-a.dsr",   _fakeAgent("ad"), { agentKind: "dsr",  tenantId: "a" });
  var all = await orch.list({});
  check("list: 3 entries",              all.length === 3);
  var mail = await orch.list({ kind: "mail" });
  check("list filter kind",             mail.length === 2);
  var aOnly = await orch.list({ tenantId: "a" });
  check("list filter tenant",           aOnly.length === 2);
}

async function testGuardRefusals() {
  var orch = b.agent.orchestrator.create({});
  await expectRejection("register refuses bad name",
    orch.register("a/b", _fakeAgent("x"), { agentKind: "mail" }),
    "agent-registry/bad-name-char");
  await expectRejection("register refuses bad kind",
    orch.register("x", _fakeAgent("x"), { agentKind: "BAD-SHAPE!" }),
    "agent-registry/bad-kind-shape");
  await expectRejection("register refuses reserved",
    orch.register("ROOT", _fakeAgent("x"), { agentKind: "mail" }),
    "agent-registry/reserved-name");
}

async function testElect() {
  var orch = b.agent.orchestrator.create({
    cluster: { isClusterMode: function () { return false; } },
  });
  var elec = await orch.elect({ resource: "mail.mdn.dispatcher" });
  check("elect single-process: leader",  elec.isLeader === true);
  check("elect single-process: fencing", elec.fencingToken === 1);
}

async function testElectCluster() {
  var fakeCluster = {
    isClusterMode: function () { return true; },
    isLeader:      function () { return true; },
    fencingToken:  function () { return 42; },
    currentLeader: function () { return Promise.resolve({ nodeId: "node-1" }); },
  };
  var orch = b.agent.orchestrator.create({ cluster: fakeCluster });
  var elec = await orch.elect({ resource: "test-resource" });
  check("elect cluster: leader",         elec.isLeader === true);
  check("elect cluster: fencing token",  elec.fencingToken === 42);
  check("elect cluster: leaderId",       elec.leaderId === "node-1");
}

async function testSpawnConsumers() {
  var enqueued = [];
  var fakeQueue = {
    enqueue: async function (topic, payload) { enqueued.push({ topic: topic, payload: payload }); return { jobId: "j1" }; },
    consume: async function (topic, handler, opts) {
      // record subscription; no actual delivery in test.
      return { unsubscribe: async function () { /* noop */ } };
    },
  };
  var orch = b.agent.orchestrator.create({});
  var agent = _fakeAgent("test");
  var consumers = orch.spawnConsumers({
    agent: agent, queue: fakeQueue,
    shards: 3, taskTopic: "mail.agent.tasks",
  });
  check("spawn: 3 consumers",            consumers.length === 3);
  check("spawn: topic suffix",           consumers[0].topic === "mail.agent.tasks.0");
  check("spawn: topic suffix end",       consumers[2].topic === "mail.agent.tasks.2");
  for (var i = 0; i < consumers.length; i += 1) await consumers[i].start();
}

function testShardFor() {
  // FNV-1a determinism — same input maps to same shard.
  var s1 = b.agent.orchestrator.shardFor("tenant-acme", 8);
  var s2 = b.agent.orchestrator.shardFor("tenant-acme", 8);
  check("shardFor: deterministic",       s1 === s2);
  check("shardFor: in range",             s1 >= 0 && s1 < 8);
  check("shardFor: shards=1 always 0",   b.agent.orchestrator.shardFor("anything", 1) === 0);
  check("shardFor: empty key → 0",       b.agent.orchestrator.shardFor("", 8) === 0);
}

async function testDrain() {
  var stopCount = 0;
  var fakeQueue = {
    enqueue: async function () { return { jobId: "j" }; },
    consume: async function () { return { unsubscribe: async function () { stopCount += 1; } }; },
  };
  var orch = b.agent.orchestrator.create({});
  var consumers = orch.spawnConsumers({
    agent: _fakeAgent("x"), queue: fakeQueue, shards: 2,
  });
  for (var i = 0; i < consumers.length; i += 1) await consumers[i].start();
  var r = await orch.drain({});
  check("drain: drained count",          r.drained === 2);
  check("drain: stops subs",             stopCount === 2);
  check("drain: elapsedMs set",          typeof r.elapsedMs === "number");
  check("drain: isDraining true after",  orch.isDraining() === true);
}

async function testHealth() {
  var orch = b.agent.orchestrator.create({});
  await orch.register("a.mail", _fakeAgent("a"), { agentKind: "mail", tenantId: "a" });
  var h = await orch.health();
  check("health: agents listed",         h.agents.length === 1);
  check("health: overall ok",            h.overall === "ok");
  check("health: not draining",          h.draining === false);
  check("health: consumers list",        Array.isArray(h.consumers));
}

async function testStreamRegistry() {
  var orch = b.agent.orchestrator.create({});
  var id = orch.registerStream({ kind: "search", actor: { id: "u1" } });
  check("registerStream returns id",     typeof id === "string" && id.indexOf("stream-") === 0);
  var h = await orch.health();
  check("health: stream count = 1",      h.streams === 1);
  orch.unregisterStream(id);
  var h2 = await orch.health();
  check("health: stream count = 0",      h2.streams === 0);
}

async function testPermissions() {
  var perms = b.permissions.create({
    roles: { reader: { permissions: ["agent-registry:read"] }, writer: { permissions: ["agent-registry:read", "agent-registry:write"] } },
    auditFailures: false, auditSuccess: false,
  });
  var orch = b.agent.orchestrator.create({ permissions: perms });
  var reader = { id: "r1", roles: ["reader"] };
  var writer = { id: "w1", roles: ["writer"] };

  // writer can register
  await orch.register("tenant-x.mail", _fakeAgent("x"), { agentKind: "mail", actor: writer });
  // reader can lookup
  var hit = await orch.lookup("tenant-x.mail", { actor: reader });
  check("perms: reader can lookup",      hit !== null);
  // reader cannot register
  await expectRejection("perms: reader cannot register",
    orch.register("tenant-y.mail", _fakeAgent("y"), { agentKind: "mail", actor: reader }),
    "agent-orchestrator/permission-denied");
}

async function run() {
  testSurface();
  await testRegisterLookupUnregister();
  await testList();
  await testGuardRefusals();
  await testElect();
  await testElectCluster();
  await testSpawnConsumers();
  testShardFor();
  await testDrain();
  await testHealth();
  await testStreamRegistry();
  await testPermissions();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
