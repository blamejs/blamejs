"use strict";
// Public page routes — landing, group/page lookups, search.
// Uses b.cache for rendered-HTML cache, b.render.html for SSR,
// b.template (mounted by createApp), and b.db.prepare for lookups.

var b = require("@blamejs/core");

// Layout-data shape shared by both the per-request render path and the
// cacheable render path. The cspNonce field is the only thing that
// differs: live paths get the real nonce, cacheable paths get the
// framework's stable placeholder (substituted at serve time via
// b.middleware.cspNonce's substitute helper).
function _layoutData(req, ctx, nonce) {
  return {
    cspNonce:    nonce,
    locale:      req.locale || "en",
    dir:         req.dir ? req.dir() : "ltr",
    user:        req.user || null,
    csrfToken:   req.csrfToken || "",
    searchQuery: "",
    title:       "",
    assets:      (ctx && ctx.assets) || {},
  };
}
function _layoutDataLive(req, ctx) {
  return _layoutData(req, ctx, req.cspNonce || (req.res && req.res.locals && req.res.locals.cspNonce) || "");
}
function _layoutDataForCache(req, ctx) {
  return _layoutData(req, ctx, ctx.nonceMw.PLACEHOLDER);
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
    var data = Object.assign(_layoutDataLive(req, ctx), {
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
    var data = Object.assign(_layoutDataLive(req, ctx), {
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
  // Convention: each group has a landing page stored at slug "index".
  // /<group>          serves the group's index directly (no redirect).
  // /<group>/<slug>   serves the named page within the group.
  // /<group>/index    301-redirects to /<group> so there's one canonical URL.
  async function _renderPage(req, res, group, slug) {
    var cacheKey = group + "/" + slug;
    var html = await pageCache.wrap(cacheKey, async function () {
      var row = db.prepare(
        "SELECT groupName, slug, title, body, updatedAt, updatedBy " +
        "FROM pages WHERE groupName = ? AND slug = ?"
      ).get(group, slug);
      if (!row) return null;
      var data = Object.assign(_layoutDataForCache(req, ctx), {
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
      return b.render.htmlString(res, "<h1>Not found</h1><p>No such page.</p>", { status: 404 });
    }
    b.render.htmlString(res, ctx.nonceMw.substitute(html, req));
  }

  router.get("/:group", async function (req, res) {
    var group = req.params.group;
    if (!/^[a-z0-9-]+$/.test(group)) {
      return b.render.htmlString(res, "Not found", { status: 404 });
    }
    return _renderPage(req, res, group, "index");
  });

  router.get("/:group/:slug", async function (req, res) {
    var group = req.params.group;
    var slug = req.params.slug;
    if (!/^[a-z0-9-]+$/.test(group) || !/^[a-z0-9-]+$/.test(slug)) {
      return b.render.htmlString(res, "Not found", { status: 404 });
    }
    // Canonicalize: /<group>/index permanently redirects to /<group>.
    if (slug === "index") {
      return b.render.redirect(res, "/" + group, { status: 301 });
    }
    return _renderPage(req, res, group, slug);
  });
}

module.exports = {
  registerSpecific: registerSpecific,
  registerCatchAll: registerCatchAll,
};
