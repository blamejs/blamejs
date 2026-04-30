"use strict";
/**
 * Bot-guard middleware — fingerprint-based detection of obviously-non-
 * browser requests. Cheap heuristics; not a substitute for proper
 * authentication, but catches drive-by scrapers and most low-effort bots.
 *
 * Heuristics (all combined):
 *   - Missing Accept-Language header (real browsers always send one)
 *   - Missing Sec-Fetch-Mode header (modern browsers send these on every
 *     navigation; absence is suspicious for HTML routes but not API)
 *   - User-Agent matches known automation libraries (curl, wget, python-
 *     requests, axios, Go-http-client) — operators can add or remove
 *     entries via config
 *
 * Options:
 *   {
 *     mode:            'block' | 'tag'          (default 'block')
 *     onlyForHtml:     true                     (skip checks for /api/*)
 *     allowedAgents:   ['<regex>', ...]         (allow-list overrides)
 *     blockedAgents:   ['<regex>', ...]         (extra deny-list)
 *     skipPaths:       ['/healthz', '/api/...'] (always skip)
 *     statusOnBlock:   403
 *     bodyOnBlock:     'Forbidden'
 *   }
 *
 * In 'tag' mode, suspected bots get req.suspectedBot = true and the
 * request continues — apps can rate-limit them differently.
 *
 * Audit: every block emits system.botguard.block with the matched
 * heuristic; every tag emits system.botguard.tag.
 */
var DEFAULT_BLOCKED_AGENTS = [
  /^curl\//i,
  /^wget\//i,
  /^python-requests\//i,
  /^python-urllib\//i,
  /^axios\//i,
  /^Go-http-client\//i,
  /^node-fetch\//i,
  /^okhttp\//i,
  /^java\//i,
  /^libwww-perl\//i,
  /^Ruby$/i,
  /^Apache-HttpClient\//i,
];

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var audit = lazyRequire(function () { return require("../audit"); });

// Bot-guard's "trust the proxy header" semantics for actor.ip — the
// audit event records the apparent source even when behind a CDN.
// extractActorContext defaults to socket.remoteAddress; we override.
function _xffIp(req) {
  var xff = req.headers && req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || null;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "mode", "onlyForHtml", "allowedAgents", "blockedAgents",
    "skipPaths", "statusOnBlock", "bodyOnBlock",
  ], "middleware.botGuard");
  var mode = opts.mode || "block";
  var onlyForHtml = opts.onlyForHtml !== false;
  var allowedAgents = (opts.allowedAgents || []).map(function (r) { return r instanceof RegExp ? r : new RegExp(r); });
  var blockedAgents = DEFAULT_BLOCKED_AGENTS.concat((opts.blockedAgents || []).map(function (r) { return r instanceof RegExp ? r : new RegExp(r); }));
  var skipPaths = opts.skipPaths || [];
  var statusOnBlock = opts.statusOnBlock || 403;
  var bodyOnBlock = opts.bodyOnBlock !== undefined ? opts.bodyOnBlock : "Forbidden";

  function _shouldSkip(req) {
    var path = req.pathname || req.url || "/";
    for (var i = 0; i < skipPaths.length; i++) {
      if (typeof skipPaths[i] === "string" ? path.indexOf(skipPaths[i]) === 0 : skipPaths[i].test(path)) {
        return true;
      }
    }
    return false;
  }

  function _looksLikeApi(req) {
    var path = req.pathname || req.url || "/";
    return /^\/api\//.test(path);
  }

  function _checkHeuristics(req) {
    var headers = req.headers || {};
    var ua = headers["user-agent"] || "";
    // User-agent allow-list overrides everything
    for (var i = 0; i < allowedAgents.length; i++) {
      if (allowedAgents[i].test(ua)) return null;
    }
    for (var j = 0; j < blockedAgents.length; j++) {
      if (blockedAgents[j].test(ua)) return "blocked-agent";
    }
    if (onlyForHtml && _looksLikeApi(req)) {
      // Skip browser-fingerprint checks for API routes
      return null;
    }
    if (!headers["accept-language"]) return "missing-accept-language";
    if (req.method === "GET" && !headers["sec-fetch-mode"]) return "missing-sec-fetch-mode";
    return null;
  }

  return function botGuard(req, res, next) {
    if (_shouldSkip(req)) return next();
    var hit = _checkHeuristics(req);
    if (!hit) return next();

    if (mode === "tag") {
      req.suspectedBot = hit;
      try {
        audit().emit({
          actor:    requestHelpers.extractActorContext(req, { ip: _xffIp(req) }),
          action:   "system.botguard.tag",
          outcome:  "denied",
          reason:   hit,
          metadata: { method: req.method, path: req.pathname || req.url, requestId: req.requestId },
          requestId: req.requestId,
        });
      } catch (_e) {}
      return next();
    }

    try {
      audit().emit({
        actor:    requestHelpers.extractActorContext(req, { ip: _xffIp(req) }),
        action:   "system.botguard.block",
        outcome:  "denied",
        reason:   hit,
        metadata: { method: req.method, path: req.pathname || req.url, requestId: req.requestId },
        requestId: req.requestId,
      });
    } catch (_e) {}

    if (res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(statusOnBlock, { "Content-Type": "text/plain" });
      res.end(bodyOnBlock);
    }
    // Don't call next() — terminate the chain
  };
}

module.exports = {
  create:                 create,
  DEFAULT_BLOCKED_AGENTS: DEFAULT_BLOCKED_AGENTS,
};
