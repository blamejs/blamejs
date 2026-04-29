"use strict";
// Default wiki content. rerunnable: true so each boot UPSERTs the latest
// text. Admin edits set updatedBy to the user id; the seeder writes
// "seeder" so the audit chain can distinguish framework-supplied vs
// operator-authored content.

var WELCOME = [
  '<h1>Welcome to blamejs</h1>',
  '<p>blamejs is a Node framework that <strong>owns its stack</strong>: zero npm runtime dependencies, post-quantum crypto from the start, sealed-by-default storage, an audit chain on every operator action.</p>',
  '<p>This wiki is the docs <em>and</em> a working reference app. Every page renders through the framework\'s own primitives — <code>b.template</code>, <code>b.cache</code>, <code>b.audit</code>, <code>b.permissions</code>. If you\'re reading this, you\'re also seeing what an operator-built blamejs app looks like.</p>',

  '<h2 id="install">Install <a class="anchor" href="#install">#</a></h2>',
  '<p>Node 24 LTS or newer. The framework targets <code>node:sqlite</code>, <code>Intl.PluralRules</code>, modern <code>crypto</code> primitives, and other recent built-ins.</p>',
  '<pre><code class="language-bash">npm install @blamejs/core</code></pre>',
  '<p>That\'s the entire dependency. The package itself ships with all crypto vendored under <code>lib/vendor/</code> — no transitive deps, no node-gyp builds beyond the optional Argon2id native module (prebuilt for 8 platforms).</p>',

  '<h2 id="hello-world">Hello world <a class="anchor" href="#hello-world">#</a></h2>',
  '<pre><code class="language-javascript">var b = require("@blamejs/core");',
  '',
  '(async function () {',
  '  var app = await b.createApp({',
  '    dataDir: "./data",',
  '    routes: function (router) {',
  '      router.get("/", function (req, res) {',
  '        b.render.htmlString(res, "&lt;h1&gt;Hello from blamejs&lt;/h1&gt;");',
  '      });',
  '    },',
  '  });',
  '  await app.listen({ port: 3000 });',
  '})();</code></pre>',
  '<p><code>createApp</code> wires the dependency-ordered boot: vault → external-DB (cluster mode only) → cluster lease → framework schema → local DB → router → middleware stack → operator routes → error handler. Each underlying module remains accessible (<code>b.vault</code>, <code>b.db</code>, <code>b.cluster</code>) — <code>createApp</code> doesn\'t hide them, it orchestrates.</p>',

  '<aside class="callout">',
  '  <p class="callout-title">Note</p>',
  '  <p>The first boot generates a vault keypair, an audit-signing keypair, a SQLite DB, and an audit chain. All of that lives under <code>./data/</code>. Production deployments should use <code>vault: { mode: "wrapped" }</code> (the default) and supply a passphrase via <code>BLAMEJS_VAULT_PASSPHRASE</code>; the example apps run plaintext for convenience.</p>',
  '</aside>',

  '<h2 id="design-tenets">Design tenets <a class="anchor" href="#design-tenets">#</a></h2>',
  '<ul>',
  '  <li><strong>Zero npm runtime deps.</strong> Every dependency is vendored under <code>lib/vendor/</code> with a manifest pinning version + license + provenance. Operators can audit the dependency graph without traversing <code>node_modules</code>.</li>',
  '  <li><strong>PQC from the start.</strong> ML-KEM-1024 + P-384 hybrid KEM, XChaCha20-Poly1305 cipher, SHAKE256 KDF, SLH-DSA-SHAKE-256f signatures. No classical-only fallbacks. See <a href="/crypto-vault/index">Crypto &amp; Vault</a>.</li>',
  '  <li><strong>Sealed-by-default storage.</strong> Every database field except IDs / timestamps / FK references goes through <code>vault.seal()</code> or a derived hash. See <a href="/storage-state/index">Storage &amp; State</a>.</li>',
  '  <li><strong>Audit chain on every operator action.</strong> Login, page edit, cache clear, key rotation, seed apply — all emit with the 5 W\'s (WHO / WHAT / WHEN / WHERE / HOW). See <a href="/observability/index">Observability</a>.</li>',
  '  <li><strong>Forward-looking defaults.</strong> Node 24 LTS, modern ECMAScript, current HTTP semantics. Operators who need older runtimes pin to an older release; the active line targets what current Node ships.</li>',
  '</ul>',

  '<h2 id="next">Where to go next <a class="anchor" href="#next">#</a></h2>',
  '<p>Pick the concern group matching your current work:</p>',
  '<ul>',
  '  <li><a href="/auth-permissions/index">Auth &amp; Permissions</a> — sessions, passwords, passkeys, RBAC, API keys</li>',
  '  <li><a href="/storage-state/index">Storage &amp; State</a> — SQLite + sealed columns, migrations, seeders, cache, queue</li>',
  '  <li><a href="/http-middleware/index">HTTP &amp; Middleware</a> — router, CSRF, CORS, rate limiting, body parsing</li>',
  '  <li><a href="/crypto-vault/index">Crypto &amp; Vault</a> — PQC envelope, vault sealing, signed webhooks</li>',
  '  <li><a href="/observability/index">Observability</a> — audit chain, metrics, tracing, redaction</li>',
  '  <li><a href="/testing/index">Testing</a> — fixtures, fakes, captures, middleware runner</li>',
  '  <li><a href="/notify-mail/index">Notify &amp; Mail</a> — generic notification dispatcher, mail with bounce processing</li>',
  '  <li><a href="/i18n-locale/index">i18n &amp; Locale</a> — translations, plural rules, formatters, RTL</li>',
  '  <li><a href="/production-essentials/index">Production Essentials</a> — cluster mode, scheduler, jobs, retry, backup</li>',
  '</ul>',

  '<aside class="callout callout-tip">',
  '  <p class="callout-title">Tip</p>',
  '  <p>Looking for the source layout of THIS wiki? It\'s at <a href="https://github.com/blamejs/blamejs/tree/main/examples/wiki">examples/wiki</a> in the framework repo. Every primitive in that app is one you\'ll find documented here.</p>',
  '</aside>',
].join("\n");


var OBSERVABILITY = [
  '<h1>Observability</h1>',
  '<p>blamejs ships four observability primitives that compose: <code>b.audit</code> (tamper-evident chain), <code>b.metrics</code> (counter taps), <code>b.tracing</code> (span taps), and <code>b.redact</code> (PII scrubbing). The wrapper <code>b.observability.tap</code> unifies span + counter into one call so primitives don\'t have to interleave them.</p>',
  '<p>Every framework primitive emits audit events on operator-action paths by default. High-throughput verifiers can disable success-event audit with <code>auditSuccess: false</code>; failures emit regardless.</p>',

  '<h2 id="audit">Audit chain <a class="anchor" href="#audit">#</a></h2>',
  '<p>The audit chain is hash-chained, signed, tamper-evident, and append-only. Every framework primitive that mutates operator-visible state emits an audit event when wired with <code>audit: b.audit</code>:</p>',
  '<pre><code class="language-javascript">var b = require("@blamejs/core");',
  '',
  'var keys = b.apiKey.create({',
  '  namespace: "wiki",',
  '  audit:     b.audit,         // wires the chain',
  '});',
  '',
  '// Every issue / verify / revoke / rotate emits with the 5 W\'s',
  'await keys.issue({ ownerId: "u-42", req: req });',
  '// → audit row: { action: "apikey.issue", actor: { ip, userAgent,',
  '//                  sessionId, requestId, method, route, userId },',
  '//                resource: { kind: "apikey", id: "wiki:abc..." },',
  '//                outcome: "success", ... }</code></pre>',

  '<h3 id="five-ws">The 5 W\'s <a class="anchor" href="#five-ws">#</a></h3>',
  '<p>Audit rows carry WHO, WHAT, WHEN, WHERE, and HOW for every operator action. <code>b.requestHelpers.extractActorContext(req, override?)</code> derives the actor from the inbound request:</p>',
  '<table>',
  '  <thead><tr><th>5 W</th><th>Field</th><th>Source</th></tr></thead>',
  '  <tbody>',
  '    <tr><td>WHO</td><td><code>actor.userId</code></td><td><code>req.user.id</code> / <code>req.apiKey.ownerId</code> / explicit override</td></tr>',
  '    <tr><td>WHEN</td><td><code>recordedAt</code></td><td>framework-set unix ms (NTP-validated)</td></tr>',
  '    <tr><td>WHERE</td><td><code>actor.ip</code></td><td><code>req.ip</code> / <code>req.socket.remoteAddress</code> / <code>req.connection.remoteAddress</code></td></tr>',
  '    <tr><td>HOW</td><td><code>actor.userAgent</code></td><td><code>req.headers["user-agent"]</code></td></tr>',
  '    <tr><td>HOW</td><td><code>actor.sessionId</code></td><td><code>req.session.id</code></td></tr>',
  '    <tr><td>HOW</td><td><code>actor.requestId</code></td><td><code>req.requestId</code> / <code>req.headers["x-request-id"]</code></td></tr>',
  '    <tr><td>HOW</td><td><code>actor.method</code></td><td><code>req.method</code></td></tr>',
  '    <tr><td>HOW</td><td><code>actor.route</code></td><td><code>req.url</code></td></tr>',
  '    <tr><td>WHAT</td><td><code>resource.kind / .id</code></td><td>per-primitive (e.g. <code>"wiki.page"</code>, <code>"apikey"</code>)</td></tr>',
  '  </tbody>',
  '</table>',

  '<aside class="callout">',
  '  <p class="callout-title">Note</p>',
  '  <p>Audit chain treats null fields as "unknown" — partial context is safe. Pass <code>{ req }</code> to any primitive method and the framework threads <code>extractActorContext</code> through every emission. Add per-call overrides via <code>{ context: { ip: "10.0.0.1" } }</code> for proxy scenarios.</p>',
  '</aside>',

  '<h3 id="audit-emit">Manual emission <a class="anchor" href="#audit-emit">#</a></h3>',
  '<p>For operator-authored events, <code>b.audit.safeEmit</code> is the drop-silent (Tier-B) emitter:</p>',
  '<pre><code class="language-javascript">b.audit.safeEmit({',
  '  action:   "wiki.page.published",',
  '  outcome:  "success",                 // "success" | "failure"',
  '  actor:    b.requestHelpers.extractActorContext(req),',
  '  resource: { kind: "wiki.page", id: groupName + "/" + slug },',
  '  metadata: { title: title, byteLength: body.length },',
  '  reason:   null,                       // string when outcome === "failure"',
  '});</code></pre>',
  '<p>Audit emit failures (DB unreachable, etc.) drop silently — the framework\'s audit primitive must never crash the request that triggered it. Operators monitor audit health via the metrics emitted by <code>audit-chain</code> itself.</p>',

  '<h3 id="audit-chain-verify">Tamper detection <a class="anchor" href="#audit-chain-verify">#</a></h3>',
  '<p>Each row carries <code>prevHash</code>, <code>rowHash</code>, <code>nonce</code>, and <code>fencingToken</code>. Boot-time verification (<code>auditChain.verifyChain</code>) replays the chain and rejects any mismatch. The signing keypair (SLH-DSA-SHAKE-256f by default) seals checkpoint signatures to the audit signing key — corrupting a row breaks the chain at that point and refuses subsequent appends until the operator restores from backup.</p>',
  '<aside class="callout callout-warning">',
  '  <p class="callout-title">Operator note</p>',
  '  <p>Production deployments should set <code>auditSigning: { mode: "wrapped" }</code> (default) and supply <code>BLAMEJS_AUDIT_SIGNING_PASSPHRASE</code>. The plaintext-signing-key files generated in dev mode print a boot warning — never ship a deployment with <code>WARNING: PLAINTEXT mode — audit-sign.key is unprotected on disk</code> in the logs.</p>',
  '</aside>',

  '<h2 id="metrics">Metrics <a class="anchor" href="#metrics">#</a></h2>',
  '<p>Every framework primitive emits structured counters via <code>b.observability.event(name, value, labels)</code>:</p>',
  '<pre><code class="language-javascript">var notify = b.notify.create({',
  '  channels: { ... },',
  '  observability: b.observability,',
  '});',
  'await notify.send({ channel: "slack", message: { text: "Deploy started" } });',
  '// Emits these events (counter taps):',
  '//   notify.send.attempt   { channel: "slack", attempt: 1 }',
  '//   notify.send.success   { channel: "slack", durationMs: 124 }',
  '// Plus a span via observability.tap (next section).</code></pre>',
  '<p>Operators wire a real backend (Prometheus exporter, OTel collector, etc.) by replacing the framework default with <code>b.metrics.tap = function (name, value, labels) { ... }</code>. Bad input drops silently so a malformed metric can\'t crash the request that emitted it.</p>',

  '<h2 id="tracing">Tracing <a class="anchor" href="#tracing">#</a></h2>',
  '<p><code>b.observability.tap(name, attrs, fn)</code> wraps an async operation in BOTH a span AND a counter. This is the canonical pattern primitives use:</p>',
  '<pre><code class="language-javascript">// Inside b.cache, b.api-key, b.notify, b.permissions, etc:',
  'return b.observability.tap("apikey.verify", { namespace: ns }, async function (span) {',
  '  // span is null when no real OTel tracer wired (pass-through);',
  '  // span is a real OTel Span when operators install @opentelemetry/api',
  '  // and call b.tracing.useTracer(otelTrace).',
  '  if (span) span.setAttribute("apikey.id", id);',
  '  var result = await _verifyImpl(secret);',
  '  return result;',
  '});',
  '// → emits notify.send (span + counter), AND',
  '//    routes the span up the operator\'s tracer if one is wired.</code></pre>',
  '<p>Without OTel installed, tracing is pass-through: <code>fn(null)</code> runs, return value propagates, throws escape, no spans produced. With OTel: <code>otel.trace.getTracer().startSpan(name, opts)</code> + <code>otel.context.with(ctx, fn)</code> so child spans nest correctly across <code>async</code> suspension points.</p>',
  '<p>W3C <code>traceparent</code> parsing/emission works in both modes so trace IDs propagate through logs and HTTP for correlation regardless of OTel.</p>',

  '<h2 id="redact">Redaction <a class="anchor" href="#redact">#</a></h2>',
  '<p><code>b.redact.redact(value)</code> walks an arbitrary value and strips PII-shaped fields. The default detectors catch:</p>',
  '<ul>',
  '  <li>Field names matching <code>password</code>, <code>secret</code>, <code>token</code>, <code>ssn</code>, <code>api_key</code>, <code>credit_card</code>, …</li>',
  '  <li>Values matching email-like, phone-number-like, JWT-like, credit-card-like patterns</li>',
  '</ul>',
  '<pre><code class="language-javascript">b.redact.redact({',
  '  user: { email: "alice@example.com" },',
  '  password: "hunter2",',
  '  body: "Reset link: https://app/reset?token=eyJhbGc..."',
  '});',
  '// → {',
  '//     user: { email: "[REDACTED-EMAIL]" },',
  '//     password: "[REDACTED]",',
  '//     body: "Reset link: https://app/reset?token=[REDACTED-JWT]",',
  '//   }</code></pre>',
  '<p>Operators register custom rules via <code>b.redact.registerFieldRule(name, replacement)</code> and <code>b.redact.registerValueDetector(name, testFn, replacement)</code>. <code>b.notify</code> uses <code>b.redact.redact</code> as its default audit-metadata redactor; operators can override per primitive.</p>',

  '<h2 id="primitive-internals">How primitives wire it <a class="anchor" href="#primitive-internals">#</a></h2>',
  '<p>The wiring inside framework primitives threads through <code>b.observability.tap</code>, <code>b.audit.safeEmit</code>, and <code>b.redact.redact</code>. Excerpt from <code>lib/notify.js</code>:</p>',
  '<pre><code class="language-javascript">// notify.send — the hot path:',
  'return b.observability.tap("notify.send", { channel: ch }, async function () {',
  '  try {',
  '    var result = await b.retry.withRetry(_oneAttempt, retryOpts);',
  '    if (auditSuccess) {',
  '      b.audit.safeEmit({',
  '        action:   "notify.send.success",',
  '        actor:    b.requestHelpers.extractActorContext(req),',
  '        resource: { kind: "notify.channel", id: ch },',
  '        outcome:  "success",',
  '        metadata: _redactedMetadata(ch, message),  // b.redact.redact',
  '      });',
  '    }',
  '    return result;',
  '  } catch (e) {',
  '    if (auditFailures) b.audit.safeEmit({ ... });',
  '    throw e;',
  '  }',
  '});</code></pre>',
  '<p>This pattern repeats across every primitive: <code>b.cache</code>, <code>b.api-key</code>, <code>b.permissions</code>, <code>b.seeders</code>, <code>b.webhook</code>, <code>b.i18n</code>. Operators inherit it by default; turning audit off requires explicit opt-out.</p>',
].join("\n");


// Stub pages — replaced as each concern group gets its full write-up.
function _stub(group, title, primitives) {
  return [
    '<h1>' + title + '</h1>',
    '<p>Primitives covered here: ' + primitives.map(function (p) { return '<code>' + p + '</code>'; }).join(', ') + '.</p>',
    '<aside class="callout">',
    '  <p class="callout-title">Coming soon</p>',
    '  <p>Full coverage page in progress. Until then, the source modules under <a href="https://github.com/blamejs/blamejs/tree/main/lib">lib/</a> have JSDoc-shaped headers explaining the primitive\'s contract, defaults, and validation tier.</p>',
    '</aside>',
  ].join("\n");
}

var STUBS = [
  ["auth-permissions", "Auth &amp; Permissions",
    ["b.auth.password", "b.auth.passkey", "b.auth.totp", "b.auth.jwt", "b.auth.oauth",
     "b.session", "b.permissions", "b.apiKey", "b.credentialHash"]],
  ["storage-state", "Storage &amp; State",
    ["b.db", "b.migrations", "b.seeders", "b.storage", "b.objectStore",
     "b.queue", "b.cache", "b.cryptoField"]],
  ["http-middleware", "HTTP &amp; Middleware",
    ["b.router", "b.middleware", "b.httpClient", "b.safeUrl", "b.requestHelpers"]],
  ["crypto-vault", "Crypto &amp; Vault",
    ["b.crypto", "b.vault", "b.cryptoField", "b.mtlsCa", "b.pqcGate", "b.webhook"]],
  ["testing", "Testing",
    ["b.testing"]],
  ["notify-mail", "Notification &amp; Mail",
    ["b.notify", "b.mail", "b.mailBounce", "b.websocket", "b.websocketChannels"]],
  ["i18n-locale", "i18n &amp; Locale",
    ["b.i18n"]],
  ["production-essentials", "Production Essentials",
    ["b.cluster", "b.externalDb", "b.backup", "b.restore",
     "b.scheduler", "b.jobs", "b.retry", "b.appShutdown", "b.ntpCheck"]],
];


// ---- Final page list ----
var GROUPS = [
  { slug: "welcome",       title: "Welcome",       body: WELCOME },
  { slug: "observability", title: "Observability", body: OBSERVABILITY },
];
for (var i = 0; i < STUBS.length; i++) {
  GROUPS.push({
    slug:  STUBS[i][0],
    title: STUBS[i][1],
    body:  _stub(STUBS[i][0], STUBS[i][1], STUBS[i][2]),
  });
}


module.exports = {
  description: "Default wiki content",
  envs:        ["prod", "dev"],
  rerunnable:  true,
  run: async function (db, ctx) {
    var now = ctx.clock();
    for (var i = 0; i < GROUPS.length; i++) {
      var g = GROUPS[i];
      db.prepare(
        "INSERT INTO pages (groupName, slug, title, body, updatedAt, updatedBy) " +
        "VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT (groupName, slug) DO UPDATE SET " +
        "  title = excluded.title, body = excluded.body, " +
        "  updatedAt = excluded.updatedAt, updatedBy = excluded.updatedBy"
      ).run(
        g.slug,             // groupName === slug for landing pages
        "index",
        g.title,
        g.body,
        now,
        "seeder"
      );
    }
  },
};
