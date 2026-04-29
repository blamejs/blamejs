"use strict";
/**
 * Public page routes — landing, group/page lookups, search.
 *
 * Composition (per feedback_compose_existing_primitives.md):
 *   - b.cache for rendered-HTML cache (per page key)
 *   - b.render.html for SSR
 *   - b.template (mounted by createApp via opts.routes pattern)
 *   - DB lookups via b.db.prepare(...).get(...)
 */

var b = require("@blamejs/core");

function _renderLayoutData(req) {
  // Per-request fields the layout expects. Most come from middleware
  // (cspNonce from b.middleware.cspNonce, locale from b.i18n.middleware,
  // user from b.session). Defaults make the views safe even when those
  // middlewares haven't been wired.
  return {
    cspNonce:    (req.res && req.res.locals && req.res.locals.cspNonce) || "",
    locale:      req.locale || "en",
    dir:         req.dir ? req.dir() : "ltr",
    user:        req.user || null,
    csrfToken:   req.csrfToken || "",
    searchQuery: "",
    title:       "",
  };
}

// Wikis read-heavy → cache rendered HTML keyed by `<group>/<slug>`. The
// admin save route invalidates the cache key on edit. b.cache.create
// returns a memory-backed instance per process; cluster-mode operators
// could swap in cluster backend with one opt change.
function _buildPageCache() {
  return b.cache.create({
    namespace: "wiki.page",
    ttlMs:     b.constants.TIME.minutes(5),
  });
}

// Specific routes (literal paths, registered FIRST so they match before
// the /:group catch-all). The catch-all `/:group` would otherwise
// intercept /login, /admin, /logout, etc. — operator-supplied paths
// must register between the specifics and the catch-all.
function registerSpecific(router, ctx) {
  var db = ctx.db;
  var template = ctx.template;

  // ---- Landing ----
  router.get("/", function (req, res) {
    var data = Object.assign(_renderLayoutData(req), {
      title: "blamejs",
    });
    var html = template.render("home", data);
    b.render.htmlString(res, html);
  });

  // /healthz / /readyz / /startupz are handled by b.middleware.health
  // mounted at the top of the chain; no route registered here.

  // ---- Search (FTS5 — operator-side recipe) ----
  router.get("/search", async function (req, res) {
    var url = new URL(req.url, "http://localhost");
    var q = (url.searchParams.get("q") || "").trim();
    var hits = [];
    if (q.length > 0 && q.length < 200) {
      try {
        // FTS5 MATCH; snippet() builds a contextual excerpt around hits.
        // Operator-supplied query is bound via parameter; FTS5 escapes
        // its own MATCH grammar, but we still cap length to bound work.
        hits = db.prepare(
          "SELECT groupName, slug, title, snippet(pages_fts, 3, '<mark>', '</mark>', '…', 16) AS snippet " +
          "FROM pages_fts WHERE pages_fts MATCH ? LIMIT 50"
        ).all(q);
      } catch (_e) {
        // FTS5 throws on malformed MATCH expressions (operator typed
        // raw operators). Fall back to empty hits — user-friendly.
        hits = [];
      }
    }
    var data = Object.assign(_renderLayoutData(req), {
      title:       "Search",
      searchQuery: q,
      hits:        hits,
    });
    var html = template.render("search", data);
    b.render.htmlString(res, html);
  });
}

// Catch-all routes (parameterized paths). Register LAST after every
// specific path is in place; the router matches in registration order.
function registerCatchAll(router, ctx) {
  var pageCache = ctx.pageCache;
  var db = ctx.db;
  var template = ctx.template;

  // ---- Group/page lookup ----
  // /<group> redirects to /<group>/index for the landing page; the
  // index slug is the framework convention used by the seeder.
  router.get("/:group", function (req, res) {
    var group = req.params.group;
    if (!/^[a-z0-9-]+$/.test(group)) return b.render.htmlString(res, "Not found", { status: 404 });
    return b.render.redirect(res, "/" + group + "/index");
  });

  router.get("/:group/:slug", async function (req, res) {
    var group = req.params.group;
    var slug = req.params.slug;
    if (!/^[a-z0-9-]+$/.test(group) || !/^[a-z0-9-]+$/.test(slug)) {
      return b.render.htmlString(res, "Not found", { status: 404 });
    }
    var cacheKey = group + "/" + slug;
    var html = await pageCache.wrap(cacheKey, async function () {
      var row = db.prepare(
        "SELECT groupName, slug, title, body, updatedAt, updatedBy " +
        "FROM pages WHERE groupName = ? AND slug = ?"
      ).get(group, slug);
      if (!row) return null;
      var data = Object.assign(_renderLayoutData(req), {
        title:        row.title,
        groupName:    row.groupName,
        slug:         row.slug,
        body:         row.body,
        updatedAtIso: new Date(row.updatedAt).toISOString(),
        updatedBy:    row.updatedBy || "unknown",
      });
      return template.render("page", data);
    });
    if (!html) {
      res.statusCode = 404;
      return b.render.htmlString(res, "<h1>Not found</h1><p>No such page.</p>", { status: 404 });
    }
    b.render.htmlString(res, html);
  });
}

module.exports = {
  registerSpecific: registerSpecific,
  registerCatchAll: registerCatchAll,
  _buildPageCache:  _buildPageCache,
};
