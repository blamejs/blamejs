// ESLint config for the blamejs framework + examples.
//
// Posture: catch bug-class problems (undefined references, unused
// variables, redeclarations, equality slips, control-flow issues).
// Don't enforce style ("var" vs "const", arrow-vs-function, etc.) —
// the codebase has settled conventions documented in CLAUDE.md that
// ESLint shouldn't second-guess.
//
// Target: Node 24 LTS, CommonJS modules, ES2024 syntax. Vendored
// dependencies under lib/vendor/, examples/wiki/public/vendor/, and
// any node_modules are excluded.
//
// Standalone (no @eslint/js / globals npm dependency) so this lints
// cleanly via `npx eslint@10` without resolving extra peer deps.

const NODE_GLOBALS = {
  // CommonJS module system
  module:           "readonly",
  require:          "readonly",
  exports:          "writable",
  __dirname:        "readonly",
  __filename:       "readonly",
  // Node runtime
  process:          "readonly",
  Buffer:           "readonly",
  global:           "readonly",
  globalThis:       "readonly",
  console:          "readonly",
  setTimeout:       "readonly",
  setInterval:      "readonly",
  setImmediate:     "readonly",
  clearTimeout:     "readonly",
  clearInterval:    "readonly",
  clearImmediate:   "readonly",
  queueMicrotask:   "readonly",
  performance:      "readonly",
  structuredClone:  "readonly",
  // Web-platform APIs that Node 24 ships
  fetch:            "readonly",
  crypto:           "readonly",
  URL:              "readonly",
  URLSearchParams:  "readonly",
  TextEncoder:      "readonly",
  TextDecoder:      "readonly",
  Worker:           "readonly",
  WorkerGlobalScope:"readonly",
  AbortController:  "readonly",
  AbortSignal:      "readonly",
  Event:            "readonly",
  EventTarget:      "readonly",
  MessageChannel:   "readonly",
  MessagePort:      "readonly",
  ReadableStream:   "readonly",
  WritableStream:   "readonly",
  TransformStream:  "readonly",
  Blob:             "readonly",
  File:             "readonly",
  FormData:         "readonly",
  Headers:          "readonly",
  Request:          "readonly",
  Response:         "readonly",
  // Modern intrinsics
  BigInt:           "readonly",
  Atomics:          "readonly",
  SharedArrayBuffer:"readonly",
  WeakRef:          "readonly",
  FinalizationRegistry: "readonly",
};

const COMMON_RULES = {
  // Bug-class rules
  "no-undef":                  "error",
  "no-redeclare":              "error",
  "no-const-assign":           "error",
  "no-delete-var":             "error",
  "no-shadow-restricted-names":"error",
  "no-global-assign":          "error",
  "no-import-assign":          "error",
  "no-func-assign":            "error",
  "no-class-assign":           "error",
  "no-this-before-super":      "error",
  "no-ex-assign":              "error",
  "no-cond-assign":            ["error", "except-parens"],
  "no-self-assign":            "error",
  "no-self-compare":           "error",
  "no-unreachable":            "error",
  "no-unsafe-finally":         "error",
  "no-unsafe-negation":        "error",
  "no-unsafe-optional-chaining": "error",
  "no-fallthrough":            "error",
  "no-async-promise-executor": "error",
  "use-isnan":                 "error",
  "valid-typeof":              "error",
  "getter-return":             "error",
  "no-compare-neg-zero":       "error",
  "no-constant-condition":     ["error", { checkLoops: false }],
  "no-constant-binary-expression": "error",
  "no-dupe-keys":              "error",
  "no-dupe-args":              "error",
  "no-dupe-else-if":           "error",
  "no-duplicate-case":         "error",
  "no-sparse-arrays":          "error",
  "no-invalid-regexp":         "error",
  "no-misleading-character-class": "error",
  "no-regex-spaces":           "error",
  "no-useless-backreference":  "error",
  "no-control-regex":          "error",
  "no-irregular-whitespace":   "error",
  "no-octal":                  "error",
  "no-debugger":               "error",
  "no-prototype-builtins":     "error",
  // Strict equality — `null` allowed for the `== null` / `!= null`
  // null-or-undefined idiom; everything else must use `===` / `!==`.
  "eqeqeq":                    ["error", "always", { null: "ignore" }],
  "no-throw-literal":          "error",
  "no-promise-executor-return":"error",
  "default-case":              "error",
  "no-loss-of-precision":      "error",

  // Hygiene rules — code clarity, dead-code removal.
  "no-unused-vars":            ["error", {
    args:                      "none",
    varsIgnorePattern:         "^_",
    caughtErrors:              "all",
    caughtErrorsIgnorePattern: "^_",
    destructuredArrayIgnorePattern: "^_",
  }],
  "no-useless-escape":         "error",
  "no-empty":                  ["error", { allowEmptyCatch: true }],
  "no-extra-boolean-cast":     "error",
  "no-unused-expressions":     ["error", { allowShortCircuit: true, allowTernary: true }],
  "no-unused-private-class-members": "error",
};

export default [
  {
    ignores: [
      "**/node_modules/**",
      "lib/vendor/**",
      "examples/wiki/public/vendor/**",
      "examples/wiki/public/dist/**",
      "**/data/**",
      "**/data-e2e/**",
      "**/.git/**",
      ".test-output/**",
      ".scratch/**",
      ".claude/**",
      // Wiki snippets are embedded into pages where `b` / `db` /
      // `req` / `res` are in scope; some use top-level await. They're
      // executed by the wiki e2e harness inside a wrapping context,
      // not standalone.
      "examples/wiki/snippets/**",
    ],
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "commonjs",
      globals:     NODE_GLOBALS,
    },
    rules: COMMON_RULES,
  },
  {
    files: ["**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "module",
      globals:     NODE_GLOBALS,
    },
    rules: COMMON_RULES,
  },
  // Browser-side scripts (wiki client bundle source, prism-test etc.).
  {
    files: ["examples/*/public/**/*.js", "examples/*/src/**/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "script",
      globals: {
        // Browser globals — supplements the Node set above.
        window:        "readonly",
        document:      "readonly",
        navigator:     "readonly",
        location:      "readonly",
        localStorage:  "readonly",
        sessionStorage:"readonly",
        Element:       "readonly",
        HTMLElement:   "readonly",
        Node:          "readonly",
        Prism:         "readonly",
        IntersectionObserver: "readonly",
        MutationObserver:     "readonly",
        ResizeObserver:       "readonly",
        getComputedStyle:     "readonly",
        history:              "readonly",
        alert:                "readonly",
        confirm:              "readonly",
        prompt:               "readonly",
        XMLHttpRequest:       "readonly",
        WebSocket:            "readonly",
      },
    },
    rules: COMMON_RULES,
  },
  // A module binding introduced by `require` names a module for the whole
  // file. Reusing that name for a local — `var cookies = parseCookieHeader(...)`
  // in a file that also requires `../cookies` — hides the module behind a
  // value of a completely different kind, and `var` hoists the local over the
  // ENTIRE function, so a call further down silently reads the local instead.
  // It fails at the call, far from the declaration, with a message about the
  // wrong thing: `cookies.serialize is not a function`, where `cookies` is a
  // parsed request jar.
  //
  // Scope analysis is what makes this decidable. Matching names by text would
  // have to guess which `var net = ...` is a re-declaration of the required
  // `net` and which is an unrelated local in a file that never required it;
  // eslint has already resolved every reference to the variable it actually
  // binds, so the rule asks the resolver rather than the source text.
  //
  // Only require-derived bindings count. General shadowing (`no-shadow`) fires
  // on every nested loop counter and says nothing about correctness; a module
  // binding is different in kind — it is the only name in the file that a
  // reader assumes is stable everywhere.
  {
    files: ["lib/**/*.js", "scripts/**/*.js", "test/**/*.js"],
    ignores: ["lib/vendor/**"],
    plugins: {
      blamejs: {
        rules: {
          "no-shadowed-module-binding": {
            meta: {
              type: "problem",
              docs: { description: "a local must not reuse the name of a required module binding" },
              schema: [],
            },
            create(context) {
              const sourceCode = context.sourceCode || context.getSourceCode();

              // `require("x")`, `lazyRequire(() => require("x"))`, and the
              // destructured `var { a } = require("x")` all bind module
              // identity to a name. Anything else initialised at module scope
              // is ordinary data and is not what this rule protects.
              function isModuleInit(node) {
                if (!node) return false;
                if (node.type !== "CallExpression" || !node.callee) return false;
                if (node.callee.type !== "Identifier") return false;
                return node.callee.name === "require" || node.callee.name === "lazyRequire";
              }

              // Which scopes hold the file's top-level names depends on the
              // source type, and the scope TYPE is the wrong thing to test. An
              // ESM file puts them in a scope of type "module"; a CommonJS file
              // puts them in one of type "FUNCTION" — the require/module/exports
              // wrapper eslint models around the file — nested inside "global".
              // Testing for `type === "module" || type === "global"` therefore
              // matched nothing at all in this codebase, and the rule reported
              // zero findings on seventeen real shadows. What every top-level
              // scope does share, and no nested one does, is that its `block` is
              // the Program node.
              function isModuleLevel(scope) {
                return scope.block && scope.block.type === "Program";
              }

              return {
                "Program:exit"(node) {
                  const top = sourceCode.getScope
                    ? sourceCode.getScope(node)
                    : context.getScope();

                  const moduleLevel = [];
                  (function collectTop(scope) {
                    if (!isModuleLevel(scope)) return;
                    moduleLevel.push(scope);
                    for (const child of scope.childScopes) collectTop(child);
                  })(top);

                  const required = new Set();
                  for (const scope of moduleLevel) {
                    for (const variable of scope.variables) {
                      for (const def of variable.defs) {
                        if (def.type === "Variable" && isModuleInit(def.node.init)) {
                          required.add(variable.name);
                        }
                      }
                    }
                  }
                  if (required.size === 0) return;

                  const reported = new Set();
                  (function walk(scope) {
                    if (!isModuleLevel(scope)) {
                      for (const variable of scope.variables) {
                        if (!required.has(variable.name)) continue;
                        for (const def of variable.defs) {
                          // Declarations only — a PARAMETER is deliberately out
                          // of scope, and that is not an oversight to close
                          // later. The two shadow the same way but differ in
                          // how visible they are. A parameter is part of the
                          // signature the reader has just read, one line above
                          // the body; naming a SQL-string parameter `sql` or a
                          // connection-handle parameter `db` is the clearest
                          // name available, and 51 of the 69 shadows in this
                          // codebase are exactly that. A `var` is the opposite:
                          // it hoists, so it owns the name from the function's
                          // FIRST line — including lines above its own
                          // declaration — and a reader looking at
                          // `cookies.serialize(...)` has nothing nearby telling
                          // them `cookies` is no longer the module.
                          if (def.type !== "Variable") continue;
                          if (reported.has(def.name)) continue;
                          reported.add(def.name);
                          context.report({
                            node: def.name,
                            message: "`" + variable.name + "` is the name of a required module " +
                              "in this file — a local of the same name hides it for the whole " +
                              "enclosing function (`var` hoists), so a later `" + variable.name +
                              ".<member>` silently reads this value instead. Rename the local to " +
                              "say what it holds.",
                          });
                        }
                      }
                    }
                    for (const child of scope.childScopes) walk(child);
                  })(top);
                },
              };
            },
          },
          // A `var` read above its own assignment is `undefined`, not an error,
          // so the expression around it produces a plausible wrong value and
          // runs on. `maxAnnouncedLiteralBytes` was resolved from a `profile`
          // assigned eight lines lower: `PROFILES[undefined]` took the fallback
          // and bounded a permissive ManageSieve listener at the strict number,
          // refusing scripts the profile allows.
          //
          // The stock `no-use-before-define` reports 138 sites here, and nearly
          // all of them are a function body naming a module-level `var` declared
          // below it — safe, because the call happens after the assignment. What
          // separates the two is whether a FUNCTION BOUNDARY sits between the
          // reference and the declaration: with none, the reference evaluates
          // immediately, while the binding still holds `undefined`. This rule
          // reports that case only.
          "no-var-read-before-assignment": {
            meta: {
              type: "problem",
              docs: { description: "a var must not be read above its own assignment in the same scope" },
              schema: [],
            },
            create(context) {
              const sourceCode = context.sourceCode || context.getSourceCode();

              function enclosingFunction(node) {
                for (let n = node; n; n = n.parent) {
                  if (n.type === "FunctionDeclaration" || n.type === "FunctionExpression" ||
                      n.type === "ArrowFunctionExpression" || n.type === "Program") {
                    return n;
                  }
                }
                return null;
              }

              return {
                "Program:exit"(node) {
                  const top = sourceCode.getScope
                    ? sourceCode.getScope(node)
                    : context.getScope();

                  (function walk(scope) {
                    for (const variable of scope.variables) {
                      for (const def of variable.defs) {
                        // `var` only. `let`/`const` throw on the same read, and
                        // a parameter or function declaration is bound before
                        // any statement runs.
                        if (def.type !== "Variable" || def.parent.kind !== "var") continue;
                        if (!def.node.init) continue;
                        const declaredAt = def.node.init.range[1];
                        const owner = enclosingFunction(def.node);
                        for (const ref of variable.references) {
                          if (!ref.identifier.range) continue;
                          if (ref.identifier.range[0] >= declaredAt) continue;
                          if (ref.isWrite() && !ref.isRead()) continue;
                          // A reference inside a nested function runs when that
                          // function is CALLED, which is the idiomatic and safe
                          // form. Only a reference evaluated in the declaring
                          // scope itself reads the hole.
                          if (enclosingFunction(ref.identifier) !== owner) continue;
                          context.report({
                            node: ref.identifier,
                            message: "`" + variable.name + "` is read here but assigned lower in " +
                              "the same scope, so it is `undefined` at this point rather than an " +
                              "error — the surrounding expression yields a wrong value and runs " +
                              "on. Move the declaration above this line.",
                          });
                        }
                      }
                    }
                    for (const child of scope.childScopes) walk(child);
                  })(top);
                },
              };
            },
          },
          // Content-safety primitives screen input by walking characters, never
          // with a regular expression — an attacker supplies the subject, and a
          // pattern with nested quantifiers turns that into a denial of service.
          //
          // The check asks the PARSER whether a `/` opened a literal. Deciding
          // that by hand means implementing the ECMAScript lexical grammar, and
          // the previous scanner kept meeting parts of it that were not
          // implemented yet — template substitutions nest, `of` is contextual, a
          // labelled `break` ends at the terminator after its label, `<!--` is a
          // comment, a shebang is not JavaScript. Every one of those is already
          // settled here, for free, because eslint has parsed the file before
          // the rule runs.
          //
          // It is defined alongside the rule above because the `blamejs` plugin
          // may be named by exactly ONE config block — two blocks declaring it
          // is a ConfigError even when the definitions are identical. The block
          // that declares it therefore has to cover every file any of its rules
          // apply to, and the narrower block below only switches this one on.
          //
          // Suppression is the standard `// eslint-disable-next-line
          // blamejs/no-regex-in-content-safety`, with the reason on the line
          // above.
          "no-regex-in-content-safety": {
            meta: {
              type: "problem",
              docs: { description: "no regular expressions in guard-* / safe-* primitives" },
              schema: [],
            },
            create(context) {
              const ADVICE = " — screen the characters instead " +
                "(codepointClass.isRunOf / indexOfAny / firstInRanges, markupTokenizer for " +
                "markup, safeBuffer for byte shapes), or run it on b.regexLinear when a " +
                "pattern is genuinely the input";
              // A pattern built at runtime is reported too. It carries the same
              // cost as a literal and is harder to see, and leaving it out to
              // spare one audited exception would mean every other file in the
              // family could construct patterns unchecked.
              //
              // Every spelling of the callee counts. `RegExp(src)` puts an
              // Identifier there; `globalThis.RegExp(src)` a MemberExpression;
              // `globalThis["RegExp"](src)` a COMPUTED MemberExpression whose
              // key is a plain string literal. All three are ordinary syntax, so
              // recognising only the first two leaves the gate bypassable
              // without doing anything unusual.
              //
              // A computed key that is not a literal — `globalThis[name]` — is
              // not resolved here, and cannot be without following the value.
              function isRegExpRef(callee) {
                if (!callee) return false;
                if (callee.type === "Identifier") return callee.name === "RegExp";
                if (callee.type !== "MemberExpression" || !callee.property) return false;
                if (!callee.computed) return callee.property.name === "RegExp";
                return callee.property.type === "Literal" && callee.property.value === "RegExp";
              }
              return {
                Literal(node) {
                  if (!node.regex) return;
                  context.report({ node, message: "regular expression `/" + node.regex.pattern + "/`" + ADVICE });
                },
                NewExpression(node) {
                  if (!isRegExpRef(node.callee)) return;
                  context.report({ node, message: "`new RegExp(...)` builds a pattern at runtime" + ADVICE });
                },
                CallExpression(node) {
                  if (!isRegExpRef(node.callee)) return;
                  context.report({ node, message: "`RegExp(...)` builds a pattern at runtime" + ADVICE });
                },
              };
            },
          },
        },
      },
    },
    rules: {
      "blamejs/no-shadowed-module-binding":    "error",
      "blamejs/no-var-read-before-assignment": "error",
    },
  },
  {
    // `test/` is in the block above so `no-var-read-before-assignment` covers
    // it — a test that reads a hole asserts against `undefined` and passes for
    // the wrong reason, which is worse than a failure. `no-shadowed-module-
    // binding` stays off there: it reports 43 sites, and a fixture naming a
    // local `db` or `net` is the clearest name available inside a test that
    // never calls the module afterwards.
    files: ["test/**/*.js"],
    rules: { "blamejs/no-shadowed-module-binding": "off" },
  },
  {
    // Nested primitives are in scope too. The scanner this replaces selected on
    // `lib/(safe-|guard-)[^/]+\.js`, so `lib/parsers/` was never examined and 55
    // pattern literals sat there — in the five parsers that consume adversarial
    // bytes, which is where the rule matters most. These paths are a subset of
    // the block above, so its plugin declaration is in scope here.
    files: ["lib/**/safe-*.js", "lib/**/guard-*.js"],
    rules: { "blamejs/no-regex-in-content-safety": "error" },
  },
];
