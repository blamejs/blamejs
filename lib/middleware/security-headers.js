"use strict";
/**
 * Security headers middleware. Sets the headers every modern app should
 * send, regardless of content. Deliberately strict by default — operators
 * who need to soften a header opt in explicitly per option.
 *
 *   Strict-Transport-Security        — force HTTPS (HSTS); 2-year max-age + includeSubDomains + preload
 *   X-Content-Type-Options: nosniff  — block MIME sniffing
 *   X-Frame-Options: DENY            — prevent clickjacking via iframes
 *   Referrer-Policy: no-referrer     — don't leak full URL to outbound links
 *   Permissions-Policy               — disable common-attack APIs (camera, geolocation, payment, etc.)
 *   Cross-Origin-Opener-Policy: same-origin
 *   Cross-Origin-Embedder-Policy: require-corp   (off by default — breaks images from CDNs)
 *   Cross-Origin-Resource-Policy: same-origin
 *   Origin-Agent-Cluster: ?1        — origin-keyed agent cluster; extra process isolation
 *   X-DNS-Prefetch-Control: off     — don't pre-resolve DNS for off-page links
 *   Content-Security-Policy          — operator-supplied; framework provides a safe default that
 *                                       only allows same-origin and prevents inline scripts
 *
 * These are the OWASP-aligned defaults. Apps that need different policies
 * (e.g. allow-list for analytics scripts, embed iframes from a known
 * partner) override per-option without losing the others.
 *
 * Options:
 *   {
 *     hsts:                 '<value>' or false to disable
 *     contentTypeOptions:   'nosniff' or false
 *     frameOptions:         'DENY' | 'SAMEORIGIN' or false
 *     referrerPolicy:       '<value>' or false
 *     permissionsPolicy:    '<value>' or false
 *     coop / coep / corp:   '<value>' or false
 *     originAgentCluster:   '?1' (default) or '?0' or false
 *     dnsPrefetchControl:   'off' (default) or 'on' or false
 *     csp:                  '<full CSP string>' or false to disable
 *   }
 */

var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");

var DEFAULT_PERMISSIONS = [
  "accelerometer=()", "ambient-light-sensor=()", "autoplay=()",
  "camera=()", "display-capture=()", "encrypted-media=()", "fullscreen=(self)",
  "geolocation=()", "gyroscope=()", "magnetometer=()", "microphone=()",
  "midi=()", "payment=()", "picture-in-picture=()", "publickey-credentials-get=()",
  "screen-wake-lock=()", "sync-xhr=()", "usb=()", "web-share=()", "xr-spatial-tracking=()",
];

// Strict CSP — no 'unsafe-inline' on script-src OR style-src. Operators
// with inline styles / scripts wire `b.middleware.cspNonce()` and use
// `{{ cspNonce }}` in their views (or req.cspNonce in handlers); the
// nonce hooks into the policy via the `csp` opt or a custom value.
// Operators in transitional environments who genuinely need inline
// styles set `csp` explicitly to the loose form.
var DEFAULT_CSP =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data:; " +
  "font-src 'self'; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "object-src 'none';";

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "hsts", "contentTypeOptions", "frameOptions", "referrerPolicy",
    "permissionsPolicy", "coop", "coep", "corp",
    "originAgentCluster", "dnsPrefetchControl", "csp", "trustProxy",
  ], "middleware.securityHeaders");
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var hsts = opts.hsts === undefined ? "max-age=63072000; includeSubDomains; preload" : opts.hsts;
  var ctOpts = opts.contentTypeOptions === undefined ? "nosniff" : opts.contentTypeOptions;
  var frameOpts = opts.frameOptions === undefined ? "DENY" : opts.frameOptions;
  var refPolicy = opts.referrerPolicy === undefined ? "no-referrer" : opts.referrerPolicy;
  var permPolicy = opts.permissionsPolicy === undefined ? DEFAULT_PERMISSIONS.join(", ") : opts.permissionsPolicy;
  var coop  = opts.coop === undefined ? "same-origin" : opts.coop;
  var coep  = opts.coep === undefined ? false : opts.coep;
  var corp  = opts.corp === undefined ? "same-origin" : opts.corp;
  var oac   = opts.originAgentCluster === undefined ? "?1" : opts.originAgentCluster;
  var dpc   = opts.dnsPrefetchControl === undefined ? "off" : opts.dnsPrefetchControl;
  var csp   = opts.csp === undefined ? DEFAULT_CSP : opts.csp;

  return function securityHeaders(req, res, next) {
    if (typeof res.setHeader !== "function") return next();
    // RFC 6797 §7.2: HSTS over plain HTTP is meaningless (UAs ignore
    // it). Skip the header on non-TLS requests so dev-over-HTTP doesn't
    // surface confusing "Strict-Transport-Security on http://" lines.
    // requestProtocol respects trustProxy — operators behind a TLS
    // terminator opt in to read X-Forwarded-Proto.
    if (hsts && requestHelpers.requestProtocol(req, { trustProxy: trustProxy }) === "https") {
      res.setHeader("Strict-Transport-Security", hsts);
    }
    if (ctOpts)     res.setHeader("X-Content-Type-Options", ctOpts);
    if (frameOpts)  res.setHeader("X-Frame-Options", frameOpts);
    if (refPolicy)  res.setHeader("Referrer-Policy", refPolicy);
    if (permPolicy) res.setHeader("Permissions-Policy", permPolicy);
    if (coop)       res.setHeader("Cross-Origin-Opener-Policy", coop);
    if (coep)       res.setHeader("Cross-Origin-Embedder-Policy", coep);
    if (corp)       res.setHeader("Cross-Origin-Resource-Policy", corp);
    if (oac)        res.setHeader("Origin-Agent-Cluster", oac);
    if (dpc)        res.setHeader("X-DNS-Prefetch-Control", dpc);
    if (csp)        res.setHeader("Content-Security-Policy", csp);
    next();
  };
}

module.exports = {
  create:               create,
  DEFAULT_PERMISSIONS:  DEFAULT_PERMISSIONS,
  DEFAULT_CSP:          DEFAULT_CSP,
};
