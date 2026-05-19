"use strict";
/**
 * @module b.jsonApi
 * @nav    HTTP
 * @title  JSON:API
 * @order  172
 *
 * @intro
 *   JSON:API v1.1 (jsonapi.org/format/1.1/) response-shape helpers.
 *   The framework's wire-format primitives compose this so operators
 *   building JSON:API services get the right top-level shape + the
 *   right Content-Type without re-implementing the spec each time.
 *
 *   Content-Type: `application/vnd.api+json`
 *
 *   Top-level shapes:
 *     - `dataResponse(data, opts?)` — `{ data: [...] | {...}, included?, links?, meta? }`
 *     - `errorResponse(errors)`     — `{ errors: [...] }`
 *     - `linkObject(url, opts?)`    — string href OR `{ href, rel, meta }`
 *
 * @card
 *   JSON:API v1.1 response shape builders. Content-Type negotiation, top-level data/errors/included/links/meta wrappers, error-object shape per §7.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var JsonApiError = defineClass("JsonApiError", { alwaysPermanent: true });

var CONTENT_TYPE = "application/vnd.api+json";

/**
 * @primitive b.jsonApi.dataResponse
 * @signature b.jsonApi.dataResponse(data, opts?)
 * @since     0.10.16
 * @status    stable
 *
 * Build a JSON:API v1.1 success response. `data` can be a Resource
 * Object, an array of Resource Objects, or null (for single-resource
 * 404 / empty-collection responses). Each Resource Object must carry
 * `type` + `id` (§7.2).
 *
 * @opts
 *   included: ResourceObject[],   // compound documents §7.7
 *   links:    object,             // top-level links §7.5
 *   meta:     object,             // non-standard top-level meta §7.4
 *   jsonapi:  object,             // jsonapi-object §7.3 (version etc.)
 *
 * @example
 *   res.setHeader("Content-Type", "application/vnd.api+json");
 *   res.end(JSON.stringify(b.jsonApi.dataResponse(
 *     { type: "articles", id: "1", attributes: { title: "Hello" } },
 *     { links: { self: "/articles/1" } }
 *   )));
 */
function dataResponse(data, opts) {
  opts = opts || {};
  validateOpts(opts, ["included", "links", "meta", "jsonapi"], "jsonApi.dataResponse");
  if (data !== null && data !== undefined) {
    if (Array.isArray(data)) {
      for (var i = 0; i < data.length; i += 1) _assertResource(data[i], i);
    } else {
      _assertResource(data, null);
    }
  }
  var out = { data: data === undefined ? null : data };
  if (opts.included) {
    if (!Array.isArray(opts.included)) {
      throw new JsonApiError("json-api/bad-included",
        "dataResponse: opts.included must be an array");
    }
    for (var j = 0; j < opts.included.length; j += 1) _assertResource(opts.included[j], j);
    out.included = opts.included;
  }
  if (opts.links)   out.links   = opts.links;
  if (opts.meta)    out.meta    = opts.meta;
  if (opts.jsonapi) out.jsonapi = opts.jsonapi;
  return out;
}

/**
 * @primitive b.jsonApi.errorResponse
 * @signature b.jsonApi.errorResponse(errors, opts?)
 * @since     0.10.16
 * @status    stable
 *
 * Build a JSON:API v1.1 error response per §7.6. Each error object
 * can carry `id` / `status` / `code` / `title` / `detail` / `source` /
 * `links` / `meta`. The framework refuses errors lacking BOTH
 * `status` and `title` (most JSON:API consumers need at least one).
 *
 * @example
 *   res.statusCode = 422;
 *   res.end(JSON.stringify(b.jsonApi.errorResponse([
 *     { status: "422", code: "INVALID", title: "Invalid email",
 *       source: { pointer: "/data/attributes/email" } },
 *   ])));
 */
function errorResponse(errors, opts) {
  opts = opts || {};
  if (!Array.isArray(errors) || errors.length === 0) {
    throw new JsonApiError("json-api/no-errors",
      "errorResponse: errors must be a non-empty array");
  }
  var checked = errors.map(function (e, idx) {
    if (!e || typeof e !== "object") {
      throw new JsonApiError("json-api/bad-error",
        "errorResponse: errors[" + idx + "] must be an object");
    }
    if (typeof e.status !== "string" && typeof e.title !== "string") {
      throw new JsonApiError("json-api/empty-error",
        "errorResponse: errors[" + idx + "] must have at least 'status' or 'title' (string)");
    }
    return e;
  });
  var out = { errors: checked };
  if (opts.meta)    out.meta    = opts.meta;
  if (opts.jsonapi) out.jsonapi = opts.jsonapi;
  if (opts.links)   out.links   = opts.links;
  return out;
}

function _assertResource(r, idx) {
  if (!r || typeof r !== "object") {
    throw new JsonApiError("json-api/bad-resource",
      "Resource at " + (idx === null ? "<root>" : "index " + idx) + " must be an object");
  }
  if (typeof r.type !== "string" || r.type.length === 0) {
    throw new JsonApiError("json-api/missing-type",
      "Resource at " + (idx === null ? "<root>" : "index " + idx) + " missing 'type'");
  }
  // id is OPTIONAL only on client-side create requests; we don't have
  // a way to distinguish, so we accept missing id (the operator's
  // responsibility to set it for non-create paths).
}

module.exports = {
  dataResponse:  dataResponse,
  errorResponse: errorResponse,
  CONTENT_TYPE:  CONTENT_TYPE,
  JsonApiError:  JsonApiError,
};
