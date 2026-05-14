"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testSurface() {
  check("create is fn",         typeof b.agent.tenant.create === "function");
  check("AgentTenantError",     typeof b.agent.tenant.AgentTenantError === "function");
  check("CROSS_TENANT_ADMIN_SCOPE", typeof b.agent.tenant.CROSS_TENANT_ADMIN_SCOPE === "string");
  var e = new b.agent.tenant.AgentTenantError("agent-tenant/test", "t");
  check("error carries code",   e.code === "agent-tenant/test");
}

async function testRegisterLookupUnregister() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme-clinic", { posture: ["hipaa"] });
  var hit = await tenant.lookup("acme-clinic");
  check("lookup returns row",   hit && hit.tenantId === "acme-clinic");
  check("lookup posture array", Array.isArray(hit.posture) && hit.posture[0] === "hipaa");
  var miss = await tenant.lookup("nope");
  check("lookup miss is null",  miss === null);
  await expectRejection("duplicate register refused",
    tenant.register("acme-clinic", {}), "agent-tenant/duplicate");
}

async function testCheckCrossTenant() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme", {});
  await tenant.register("globex", {});
  // Same tenant — OK.
  tenant.check({ id: "u1", tenantId: "acme" }, "acme");
  // Cross-tenant — refused.
  expectThrows("cross-tenant refused",
    function () { tenant.check({ id: "u1", tenantId: "globex" }, "acme"); },
    "agent-tenant/cross-tenant-access-refused");
  // Missing tenantId — refused.
  expectThrows("missing actor.tenantId refused",
    function () { tenant.check({ id: "u1" }, "acme"); },
    "agent-tenant/no-tenant-actor");
  // No actor — refused.
  expectThrows("missing actor refused",
    function () { tenant.check(null, "acme"); }, "agent-tenant/no-actor");
  // Global-scoped agent — no check (tenant id null).
  tenant.check({ id: "u1" }, null);
}

async function testCrossTenantAdminScope() {
  var perms = b.permissions.create({
    roles: {
      admin: { permissions: ["framework-cross-tenant-admin"] },
    },
    auditFailures: false, auditSuccess: false,
  });
  var tenant = b.agent.tenant.create({ permissions: perms });
  await tenant.register("acme", {});
  // Admin actor can cross tenant boundary.
  tenant.check({ id: "admin", tenantId: "ROOT", roles: ["admin"] }, "acme");
}

async function testDerivedKey() {
  var tenant = b.agent.tenant.create({});
  var k1 = tenant.derivedKey("acme", "seal");
  var k2 = tenant.derivedKey("acme", "seal");
  var k3 = tenant.derivedKey("globex", "seal");
  var k4 = tenant.derivedKey("acme", "audit");
  check("derivedKey deterministic",        k1 === k2);
  check("derivedKey per-tenant differs",   k1 !== k3);
  check("derivedKey per-purpose differs",  k1 !== k4);
  check("derivedKey returns string",        typeof k1 === "string" && k1.length > 0);
}

async function testAuditFor() {
  var captured = [];
  var fakeAudit = {
    safeEmit: function (ev) { captured.push(ev); },
  };
  var tenant = b.agent.tenant.create({ audit: fakeAudit });
  var auditA = tenant.auditFor("acme");
  auditA.safeEmit({ action: "mail.fetch", outcome: "success", metadata: { count: 1 } });
  check("auditFor: emit captured",          captured.length === 1);
  check("auditFor: tenantId tagged",         captured[0].metadata.tenantId === "acme");
  check("auditFor: original metadata preserved", captured[0].metadata.count === 1);
}

async function testUnregisterArchiveDefault() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme", { posture: ["hipaa"], archivePolicy: "hipaa-6yr" });
  var r = await tenant.unregister("acme", { actor: { id: "admin" } });
  check("unregister default: mode = archived", r.mode === "archived");
  // Tenant no longer in active registry...
  var miss = await tenant.lookup("acme");
  check("unregister: lookup miss after archive", miss === null);
  // ...but visible in archived list.
  var archived = tenant.listArchived();
  check("unregister: archived list has entry",
    archived.length === 1 && archived[0].tenantId === "acme");
}

async function testDestroyRequiresPreconditions() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme", {});
  // Bare destroy: true → refused, requires step-up.
  await expectRejection("destroy refuses without step-up",
    tenant.unregister("acme", { destroy: true, actor: { id: "admin" } }),
    "agent-tenant/destroy-requires-step-up");
  await expectRejection("destroy refuses without dual-control",
    tenant.unregister("acme", {
      destroy: true, stepUpToken: "abc", actor: { id: "admin" },
    }),
    "agent-tenant/destroy-requires-dual-control");
  await expectRejection("destroy refuses without reason",
    tenant.unregister("acme", {
      destroy: true, stepUpToken: "abc", dualControlApprover: "admin2",
      actor: { id: "admin" },
    }),
    "agent-tenant/destroy-requires-reason");
  // All preconditions met → destroy succeeds.
  var r = await tenant.unregister("acme", {
    destroy: true, stepUpToken: "abc", dualControlApprover: "admin2",
    reason: "GDPR Art. 17 request #2026-05-14",
    actor: { id: "admin", roles: ["root"] },
  });
  check("destroy with preconditions: mode = destroyed", r.mode === "destroyed");
  // Destroyed tenant is gone — not in archive either.
  var archived = tenant.listArchived();
  check("destroy: not in archive", archived.length === 0);
}

async function testList() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("a", {});
  await tenant.register("b", {});
  var rows = await tenant.list({});
  check("list returns 2", rows.length === 2);
}

async function testGuardRefusalAtBoundary() {
  var tenant = b.agent.tenant.create({});
  await expectRejection("register refuses bad tenant id",
    tenant.register("a/b", {}), "tenant-id/bad-char");
}

async function run() {
  testSurface();
  await testRegisterLookupUnregister();
  await testCheckCrossTenant();
  await testCrossTenantAdminScope();
  await testDerivedKey();
  await testAuditFor();
  await testUnregisterArchiveDefault();
  await testDestroyRequiresPreconditions();
  await testList();
  await testGuardRefusalAtBoundary();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
