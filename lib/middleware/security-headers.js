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
 *   Content-Security-Policy          — operator-supplied; framework provides a safe default that
 *                                       only allows same-origin and prevents inline scripts
 *
 * These are the OWASP-aligned defaults. Apps that need different policies
 * (e.g. allow-list for analytics scripts, embed iframes from a known
 * partner) override per-option without losing the others.
 *
 * Options:
 *   {
 *     hsts:           '<value>' or false to disable
 *     contentTypeOptions: 'nosniff' or false
 *     frameOptions:   'DENY' | 'SAMEORIGIN' or false
 *     referrerPolicy: '<value>' or false
 *     permissionsPolicy: '<value>' or false
 *     coop / coep / corp: '<value>' or false
 *     csp:            '<full CSP string>' or false to disable
 *   }
 */

var validateOpts = require("../validate-opts");

var DEFAULT_PERMISSIONS = [
  "accelerometer=()", "ambient-light-sensor=()", "autoplay=()",
  "camera=()", "display-capture=()", "encrypted-media=()", "fullscreen=(self)",
  "geolocation=()", "gyroscope=()", "magnetometer=()", "microphone=()",
  "midi=()", "payment=()", "picture-in-picture=()", "publickey-credentials-get=()",
  "screen-wake-lock=()", "sync-xhr=()", "usb=()", "web-share=()", "xr-spatial-tracking=()",
];

var DEFAULT_CSP =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; " +
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
    "permissionsPolicy", "coop", "coep", "corp", "csp",
  ], "middleware.securityHeaders");
  var hsts = opts.hsts === undefined ? "max-age=63072000; includeSubDomains; preload" : opts.hsts;
  var ctOpts = opts.contentTypeOptions === undefined ? "nosniff" : opts.contentTypeOptions;
  var frameOpts = opts.frameOptions === undefined ? "DENY" : opts.frameOptions;
  var refPolicy = opts.referrerPolicy === undefined ? "no-referrer" : opts.referrerPolicy;
  var permPolicy = opts.permissionsPolicy === undefined ? DEFAULT_PERMISSIONS.join(", ") : opts.permissionsPolicy;
  var coop  = opts.coop === undefined ? "same-origin" : opts.coop;
  var coep  = opts.coep === undefined ? false : opts.coep;
  var corp  = opts.corp === undefined ? "same-origin" : opts.corp;
  var csp   = opts.csp === undefined ? DEFAULT_CSP : opts.csp;

  return function securityHeaders(req, res, next) {
    if (typeof res.setHeader !== "function") return next();
    if (hsts)       res.setHeader("Strict-Transport-Security", hsts);
    if (ctOpts)     res.setHeader("X-Content-Type-Options", ctOpts);
    if (frameOpts)  res.setHeader("X-Frame-Options", frameOpts);
    if (refPolicy)  res.setHeader("Referrer-Policy", refPolicy);
    if (permPolicy) res.setHeader("Permissions-Policy", permPolicy);
    if (coop)       res.setHeader("Cross-Origin-Opener-Policy", coop);
    if (coep)       res.setHeader("Cross-Origin-Embedder-Policy", coep);
    if (corp)       res.setHeader("Cross-Origin-Resource-Policy", corp);
    if (csp)        res.setHeader("Content-Security-Policy", csp);
    next();
  };
}

module.exports = {
  create:               create,
  DEFAULT_PERMISSIONS:  DEFAULT_PERMISSIONS,
  DEFAULT_CSP:          DEFAULT_CSP,
};
