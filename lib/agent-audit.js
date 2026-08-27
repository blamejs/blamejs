// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.agent._audit — internal shared audit-emit helper for the agent
 * substrate (`b.agent.orchestrator` / `b.agent.idempotency` /
 * `b.agent.stream` / `b.agent.eventBus` / future substrate slices).
 *
 * Each agent primitive emits audit events at lifecycle boundaries
 * (registered / opened / closed / replay / denied / drop / etc). The
 * emit logic is identical: actor shape → audit.safeEmit() → swallow
 * any audit-side failures. Extracted here so the 4+ agent substrate
 * modules don't re-implement the same wrapper.
 *
 * Internal — operator-facing surface is each primitive's `.audit`
 * opt; this is the implementation detail.
 */

// The actor as `b.audit.record` reads one. It documents the 5W shape
// `{ userId, ip, userAgent, sessionId }` and stores `actor.userId` into
// `actorUserId`; the agent substrate speaks `{ id, roles }`, so emitting that
// shape unchanged left `actorUserId` null on every row these modules produce —
// eight of them share this wrapper — even when the consumer had passed an
// identity. An audit trail that cannot say who did something is the one thing
// an audit trail is for.
//
// `id` is kept alongside `userId` because it is the substrate's own vocabulary
// and consumers read it back off the event. The remaining 5W fields are carried
// when supplied rather than dropped: they are the difference between "user u1"
// and "user u1, from this address, in this session".
// The rest of audit's 5W actor fields, carried through under their own names.
var CARRIED_ACTOR_FIELDS = ["ip", "userAgent", "sessionId"];

function actorShape(actor) {
  if (!actor || typeof actor !== "object") return { id: "<system>", userId: null };
  var shaped = { id: actor.id, userId: actor.id, roles: actor.roles || [] };
  CARRIED_ACTOR_FIELDS.forEach(function (field) {
    if (actor[field] !== undefined) shaped[field] = actor[field];
  });
  return shaped;
}

function safeAudit(auditImpl, action, actor, metadata) {
  try {
    auditImpl.safeEmit({
      action: action,
      actor:  actorShape(actor),
      outcome: _outcomeFor(action),
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — audit failures don't crash the call */ }
}

// "denied" / "drop" / "threw" / "different_args" / "miss" / "not_implemented"
// all imply failure outcome; anything else is success. Per-primitive
// classification can override by passing a metadata.outcome — that's
// merged in by the caller, not here.
function _outcomeFor(action) {
  if (typeof action !== "string") return "success";
  if (action.indexOf("denied")          >= 0) return "failure";
  if (action.indexOf("drop")            >= 0) return "failure";
  if (action.indexOf("threw")           >= 0) return "failure";
  if (action.indexOf("different_args")  >= 0) return "failure";
  if (action.indexOf("miss")            >= 0) return "failure";
  if (action.indexOf("not_implemented") >= 0) return "failure";
  return "success";
}

module.exports = {
  safeAudit:  safeAudit,
  actorShape: actorShape,   // shared so a module with its own emitter does not re-derive it
};
