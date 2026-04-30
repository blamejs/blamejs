---
name: Feature request
about: Propose a new framework primitive, CLI subcommand, or operator-facing capability
title: ''
labels: enhancement
assignees: ''
---

<!--
Per CONTRIBUTING.md → "No-MVP rule": every framework primitive lands
v1-defensible, not "minimum viable with key features deferred." File
the issue first to discuss scope before opening a PR; it saves a
round of rework.
-->

## Problem

<!-- What operator pain are you solving? Concrete scenario preferred over abstract. -->

## Proposed primitive / surface

<!-- What does the operator's API look like? Show the call site as you imagine it. -->

```js
// Imagined usage
var foo = b.foo.create({
  ...
});
await foo.doThing(...);
```

If it's a CLI subcommand, the imagined invocation:

```bash
blamejs foo do-thing --flag value
```

## v1 scope (no-MVP rule)

What's IN this v1:
-

What's explicitly OUT (and why each "out" is a complete decision, not a deferred bullet):
-

## Tier-A validation surface

<!-- Which opts keys does the new primitive's create() accept? -->

```
allowedKeys: [
  "name",
  "audit",
  ...
]
```

## Failure modes

<!-- Per the validation tier policy: every primitive picks Tier A
(throw at config-time) / Tier B (drop silent in hot path) / Tier C
(return defaults for request reads). Decide consciously. -->

- Bad opts → Tier A (throw at create())
- Hot-path observability sink failure → Tier B
- Request-read with bad input → Tier C

## Crypto / audit / security implications

<!-- Does this primitive touch the vault / sealed columns / audit chain? -->

- [ ] No crypto state involved
- [ ] Reads sealed columns (uses `b.cryptoField` automatically)
- [ ] Writes new sealed-by-default schema (declares `sealedFields` in the collection definition)
- [ ] Emits audit events (which namespace? does it need `audit.registerNamespace`?)
- [ ] Adds a new envelope-versioned algorithm (which ID? back-compat with old data?)

## Operator-facing surface

<!-- Where does this show up for operators? -->

- [ ] Wiki seeded docs updated (which concern group?)
- [ ] DEPLOY.md env vars updated
- [ ] CLI subcommand
- [ ] Admin UI demo in the wiki
- [ ] None — internal-only primitive

## Alternatives considered

<!-- What did you rule out and why. Saves the reviewer asking. -->

## Additional context
