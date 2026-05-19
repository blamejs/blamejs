"use strict";
/**
 * @module b.fedcm
 * @nav    Identity
 * @title  FedCM Identity Provider
 * @order  375
 *
 * @intro
 *   W3C FedCM (Federated Credential Management API, candidate
 *   recommendation 2024) identity-provider-side helpers. Operators
 *   running an IdP wire four endpoints per the spec; this module
 *   ships response-shape builders + the well-known config emitter.
 *
 *   Endpoints (FedCM §5):
 *     - `/.well-known/web-identity` — discovery
 *     - `<config_url>` — IdP config doc (FedCM §6.3 IdentityProviderAPIConfig)
 *     - `accounts_endpoint` — returns the user's accounts at this IdP
 *     - `id_assertion_endpoint` — mints the id_token / verifiable
 *       credential bound to the relying-party origin
 *
 *   The framework does NOT make the FedCM browser API call itself —
 *   that's user-agent surface. Operators wire response builders into
 *   their router and supply the per-account session state.
 *
 * @card
 *   FedCM IdP-side response builders (well-known + config + accounts + id_assertion) per W3C FedCM 2024 candidate recommendation.
 */

var validateOpts  = require("./validate-opts");
var safeUrl       = require("./safe-url");
var { defineClass } = require("./framework-error");

var FedcmError = defineClass("FedcmError", { alwaysPermanent: true });

/**
 * @primitive b.fedcm.wellKnown
 * @signature b.fedcm.wellKnown({ provider_urls })
 * @since     0.10.16
 * @status    stable
 *
 * Build the `/.well-known/web-identity` JSON body. `provider_urls`
 * lists the operator's IdP config URLs (FedCM §5).
 *
 * @example
 *   res.setHeader("Content-Type", "application/json");
 *   res.end(JSON.stringify(b.fedcm.wellKnown({
 *     provider_urls: ["https://idp.example/fedcm/config.json"],
 *   })));
 */
function wellKnown(opts) {
  opts = validateOpts.requireObject(opts, "fedcm.wellKnown", FedcmError, "fedcm/bad-opts");
  if (!Array.isArray(opts.provider_urls) || opts.provider_urls.length === 0) {
    throw new FedcmError("fedcm/no-provider-urls",
      "wellKnown: provider_urls must be a non-empty array");
  }
  for (var i = 0; i < opts.provider_urls.length; i += 1) {
    var u = opts.provider_urls[i];
    var parsed;
    try { parsed = safeUrl.parse(u); }
    catch (_e) {
      throw new FedcmError("fedcm/bad-provider-url",
        "wellKnown: provider_urls[" + i + "] is not a parseable URL");
    }
    if (parsed.protocol !== "https:") {
      throw new FedcmError("fedcm/bad-provider-url",
        "wellKnown: provider_urls[" + i + "] must be https");
    }
  }
  return { provider_urls: opts.provider_urls.slice() };
}

/**
 * @primitive b.fedcm.config
 * @signature b.fedcm.config(opts)
 * @since     0.10.16
 * @status    stable
 *
 * Build the IdentityProviderAPIConfig JSON body served at the
 * operator's `config_url` per FedCM §6.3. Required fields:
 * accounts_endpoint, client_metadata_endpoint, id_assertion_endpoint,
 * login_url, branding (icon / name / colors).
 *
 * @example
 *   res.end(JSON.stringify(b.fedcm.config({
 *     accounts_endpoint:        "/fedcm/accounts",
 *     client_metadata_endpoint: "/fedcm/client_metadata",
 *     id_assertion_endpoint:    "/fedcm/id_assertion",
 *     login_url:                "https://idp.example/login",
 *     branding: { background_color: "#000", color: "#fff", name: "Example IdP" },
 *   })));
 */
function config(opts) {
  opts = validateOpts.requireObject(opts, "fedcm.config", FedcmError, "fedcm/bad-opts");
  validateOpts(opts, ["accounts_endpoint", "client_metadata_endpoint",
                       "id_assertion_endpoint", "login_url", "branding",
                       "disconnect_endpoint"], "fedcm.config");
  var required = ["accounts_endpoint", "client_metadata_endpoint",
                   "id_assertion_endpoint", "login_url"];
  for (var i = 0; i < required.length; i += 1) {
    validateOpts.requireNonEmptyString(opts[required[i]], required[i],
      FedcmError, "fedcm/missing-" + required[i]);
  }
  if (!opts.branding || typeof opts.branding !== "object") {
    throw new FedcmError("fedcm/missing-branding", "config: opts.branding required");
  }
  var out = {
    accounts_endpoint:        opts.accounts_endpoint,
    client_metadata_endpoint: opts.client_metadata_endpoint,
    id_assertion_endpoint:    opts.id_assertion_endpoint,
    login_url:                opts.login_url,
    branding: {
      name:             opts.branding.name             || "",
      background_color: opts.branding.background_color || "#000000",
      color:            opts.branding.color            || "#ffffff",
    },
  };
  if (opts.branding.icons) out.branding.icons = opts.branding.icons.slice();
  if (opts.disconnect_endpoint) out.disconnect_endpoint = opts.disconnect_endpoint;
  return out;
}

/**
 * @primitive b.fedcm.accountsResponse
 * @signature b.fedcm.accountsResponse({ accounts })
 * @since     0.10.16
 * @status    stable
 *
 * Build the JSON body for the accounts_endpoint response. Each
 * account: { id, name, email, picture?, approved_clients? }
 * Operator supplies the per-user account state.
 *
 * @example
 *   res.setHeader("Set-Cookie", "Sec-FedCM-CSRF=...");
 *   res.end(JSON.stringify(b.fedcm.accountsResponse({
 *     accounts: [{
 *       id: "1234", name: "Alice", email: "alice@example.com",
 *       approved_clients: ["rp.example"],
 *     }],
 *   })));
 */
function accountsResponse(opts) {
  opts = validateOpts.requireObject(opts, "fedcm.accountsResponse",
    FedcmError, "fedcm/bad-opts");
  if (!Array.isArray(opts.accounts)) {
    throw new FedcmError("fedcm/no-accounts",
      "accountsResponse: opts.accounts must be an array");
  }
  var sanitized = opts.accounts.map(function (a, i) {
    if (!a || typeof a !== "object") {
      throw new FedcmError("fedcm/bad-account",
        "accountsResponse: accounts[" + i + "] must be an object");
    }
    if (typeof a.id !== "string" || a.id.length === 0) {
      throw new FedcmError("fedcm/bad-account",
        "accountsResponse: accounts[" + i + "].id required (string)");
    }
    var out = { id: a.id, name: a.name || "", email: a.email || "" };
    if (a.given_name)   out.given_name   = a.given_name;
    if (a.picture)      out.picture      = a.picture;
    if (Array.isArray(a.approved_clients)) out.approved_clients = a.approved_clients.slice();
    return out;
  });
  return { accounts: sanitized };
}

/**
 * @primitive b.fedcm.idAssertionResponse
 * @signature b.fedcm.idAssertionResponse({ token })
 * @since     0.10.16
 * @status    stable
 *
 * Build the JSON body for the id_assertion_endpoint response. The
 * operator mints the `token` (typically a signed JWT or verifiable
 * credential) and the framework wraps it in the FedCM-spec shape.
 *
 * @example
 *   res.end(JSON.stringify(b.fedcm.idAssertionResponse({ token: jwt })));
 */
function idAssertionResponse(opts) {
  opts = validateOpts.requireObject(opts, "fedcm.idAssertionResponse",
    FedcmError, "fedcm/bad-opts");
  validateOpts.requireNonEmptyString(opts.token, "token",
    FedcmError, "fedcm/missing-token");
  return { token: opts.token };
}

module.exports = {
  wellKnown:           wellKnown,
  config:              config,
  accountsResponse:    accountsResponse,
  idAssertionResponse: idAssertionResponse,
  FedcmError:          FedcmError,
};
