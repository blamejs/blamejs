# Fuzz harness

Hand-rolled fuzz harnesses against the parser / validator surface most
likely to crash on adversarial input. Each `<name>.fuzz.js` file
generates random / mutated inputs against ONE primitive target and
fails the run with a reproducer when the target throws an unexpected
error (vs. an operator-friendly framework error code).

## Targets

| File                          | Target                              |
| ----------------------------- | ----------------------------------- |
| `safe-json.fuzz.js`           | `b.safeJson.parse`                  |
| `safe-url.fuzz.js`            | `b.safeUrl.parse`                   |
| `safe-jsonpath.fuzz.js`       | `b.safeJsonPath.parse`              |
| `guard-csv.fuzz.js`           | `b.guardCsv.validate`               |
| `guard-html.fuzz.js`          | `b.guardHtml.validate`              |
| `guard-json.fuzz.js`          | `b.guardJson.parse`                 |
| `guard-yaml.fuzz.js`          | `b.guardYaml.parse`                 |
| `guard-xml.fuzz.js`           | `b.guardXml.validate`               |
| `guard-svg.fuzz.js`           | `b.guardSvg.validate`               |
| `guard-markdown.fuzz.js`      | `b.guardMarkdown.validate`          |
| `guard-email.fuzz.js`         | `b.guardEmail.validateMessage`      |

## Run locally

```sh
# Single target, 30s default budget:
node fuzz/safe-json.fuzz.js

# Longer budget for overnight runs:
FUZZ_BUDGET_MS=600000 node fuzz/guard-yaml.fuzz.js

# All targets sequentially:
node fuzz/_run-all.js
```

## CI

`.github/workflows/fuzz.yml` runs every target in a matrix:

- **Pull requests**: 60s budget per target — fast feedback, blocks on findings.
- **Daily schedule**: 300s per target — surfaces deeper paths.
- **Manual dispatch**: configurable budget via `FUZZ_BUDGET_MS` env.

The workflow runs on `node:24` (current LTS) and uses pinned action
SHAs per the repo's general workflow discipline.

## What counts as "expected" vs. "crash"

Each target is documented to refuse adversarial input via a
deterministic operator-friendly error (`err.code` matching a
documented vocabulary like `safejson/depth-cap` or
`guard-yaml/refused`). Those refusals are EXPECTED outcomes — the
runner moves on to the next iteration.

A FINDING (failure) is any throw the target wasn't expected to emit:

- Native `TypeError` with a non-input-shape message (suggests an
  internal invariant breach)
- `RangeError` outside the documented depth / length cap contract
  (suggests stack-overflow rather than guarded refusal)
- Unhandled prototype-pollution surface (operator-supplied key
  reaching internal lookup paths)
- Anything else lacking an operator-friendly `err.code`

When a finding fires, the runner prints the reproducer (input
stringification capped at 200 chars + first 6 stack frames) and
exits 1. Reproduce locally by setting `FUZZ_SEED` to the iteration
number, OR copying the printed input verbatim into a one-off test.

## Adding a new target

1. Find the primitive that's a parser / validator with adversarial
   input surface.
2. Identify the documented error vocabulary (the prefix of `err.code`
   values it throws).
3. Write `fuzz/<name>.fuzz.js`:

   ```js
   var b      = require("..");
   var runner = require("./_runner");

   runner.fuzz({
     name:        "b.<thing>.<method>",
     target:      function (input) { return b.<thing>.<method>(input); },
     generator:   function () { /* random / mutated input */ },
     expectThrow: /^<prefix>\//,
   });
   ```

4. Add the matrix entry in `.github/workflows/fuzz.yml`.
5. Run locally for at least 60s; commit only after a clean run.
