"use strict";
/**
 * Admin auth + page editor routes.
 *
 * Composition:
 *   - b.auth.password for credential check (PBKDF-shaped via Argon2id)
 *   - b.session for cookie-bound session token
 *   - b.permissions to gate /admin behind admin scope
 *   - b.audit.safeEmit for every page edit (5 W's via b.requestHelpers)
 *   - b.cache (the page cache) — invalidated on save
 *   - b.slug for slug-from-title coercion (operator-supplied admin form)
 *   - b.middleware.csrf for form-POST protection
 *
 * Single-admin model (per Phase 11 scope): one admin seeded from
 * WIKI_ADMIN_EMAIL + WIKI_ADMIN_PASSWORD env vars at first boot.
 * Operators wanting team-of-editors swap b.auth.password for whatever
 * larger auth surface they prefer; the route shapes here remain.
 */

var b = require("@blamejs/core");

function _layoutData(req) {
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

function register(router, ctx) {
  var db = ctx.db;
  var template = ctx.template;
  var audit = ctx.audit;
  var pageCache = ctx.pageCache;
  var perms = ctx.perms;
  var passwordAuth = ctx.passwordAuth;
  var session = ctx.session;

  // ---- Login form ----
  router.get("/login", function (req, res) {
    if (req.user) return b.render.redirect(res, "/admin");
    var data = Object.assign(_layoutData(req), { title: "Sign in", error: null });
    b.render.htmlString(res, template.render("login", data));
  });

  // ---- Login submit ----
  router.post("/login", async function (req, res) {
    var body = req.body || {};
    var email = String(body.email || "").trim().toLowerCase();
    var password = String(body.password || "");
    var data = Object.assign(_layoutData(req), { title: "Sign in" });

    function _showError(msg) {
      data.error = msg;
      res.statusCode = 401;
      return b.render.htmlString(res, template.render("login", data), { status: 401 });
    }

    if (!email || !password) return _showError("Email and password are required.");

    // Look up admin row. Single-admin shape — table has at most one row.
    var row = db.prepare(
      "SELECT id, email, passwordHash FROM admin_users WHERE email = ? LIMIT 1"
    ).get(email);
    if (!row) {
      audit.safeEmit({
        action:   "wiki.login.failure",
        outcome:  "failure",
        actor:    b.requestHelpers.extractActorContext(req),
        reason:   "no-such-user",
      });
      return _showError("Invalid credentials.");
    }
    // b.auth.password.verify(stored, plain) — argument order matters
    var ok = await passwordAuth.verify(row.passwordHash, password);
    if (!ok) {
      audit.safeEmit({
        action:   "wiki.login.failure",
        outcome:  "failure",
        actor:    b.requestHelpers.extractActorContext(req, { userId: row.id }),
        reason:   "bad-password",
      });
      return _showError("Invalid credentials.");
    }
    // Build a session bound to this admin
    var sid = await session.create({ userId: row.id, data: { email: row.email, scopes: ["admin"] } });
    res.setHeader("Set-Cookie",
      "wiki_sid=" + sid + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400");
    audit.safeEmit({
      action:   "wiki.login.success",
      outcome:  "success",
      actor:    b.requestHelpers.extractActorContext(req, { userId: row.id }),
    });
    b.render.redirect(res, "/admin");
  });

  // ---- Logout ----
  router.post("/logout", async function (req, res) {
    if (req.session && req.session.id) {
      await session.destroy(req.session.id);
    }
    res.setHeader("Set-Cookie", "wiki_sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    audit.safeEmit({
      action:   "wiki.logout",
      outcome:  "success",
      actor:    b.requestHelpers.extractActorContext(req),
    });
    b.render.redirect(res, "/");
  });

  // ---- Admin gate ----
  // perms.require("admin") returns a 3-arg middleware that emits a
  // 401/403 if the actor lacks the role. Routes below are gated by it.
  var requireAdmin = perms.require("admin");

  router.get("/admin", requireAdmin, function (req, res) {
    var pages = db.prepare(
      "SELECT groupName, slug, title, updatedAt, updatedBy " +
      "FROM pages ORDER BY groupName, slug"
    ).all().map(function (r) {
      return Object.assign(r, { updatedAtIso: new Date(r.updatedAt).toISOString() });
    });
    var data = Object.assign(_layoutData(req), {
      title: "Admin",
      pages: pages,
    });
    b.render.htmlString(res, template.render("admin/dashboard", data));
  });

  // GET /admin/edit  → new page
  // GET /admin/edit/:group/:slug → edit existing
  router.get("/admin/edit", requireAdmin, function (req, res) {
    var data = Object.assign(_layoutData(req), {
      title:     "New page",
      isNew:     true,
      groupName: "",
      slug:      "",
      titleField: "",
      body:      "",
      error:     null,
    });
    // Template var collision — use `titleField` for the form's title
    // because `title` is the page-meta title in the layout.
    data.title = data.title;       // explicit "page meta" stays
    data.titleField = "";
    b.render.htmlString(res, template.render("admin/edit", data));
  });

  router.get("/admin/edit/:group/:slug", requireAdmin, function (req, res) {
    var row = db.prepare(
      "SELECT groupName, slug, title, body FROM pages WHERE groupName = ? AND slug = ?"
    ).get(req.params.group, req.params.slug);
    if (!row) return b.render.htmlString(res, "Not found", { status: 404 });
    var data = Object.assign(_layoutData(req), {
      title:     "Edit " + row.title,
      isNew:     false,
      groupName: row.groupName,
      slug:      row.slug,
      titleField: row.title,
      body:      row.body,
      error:     null,
    });
    b.render.htmlString(res, template.render("admin/edit", data));
  });

  // ---- Save (create or update) ----
  router.post("/admin/save", requireAdmin, async function (req, res) {
    var body = req.body || {};
    // b.slug normalizes user-typed input into URL-safe shapes — same
    // transform across this app and any operator code building slugs.
    // Fallback "page" / "untitled" prevents an empty input from ever
    // hitting the DB (b.slug returns "" on whitespace-only input).
    var groupName = b.slug(String(body.groupName || ""), { fallback: "" });
    var slug = b.slug(String(body.slug || ""), { fallback: "" });
    var title = String(body.title || "").trim();
    var content = String(body.body || "");
    if (!groupName || !slug || !title) {
      res.statusCode = 400;
      return b.render.htmlString(res, "<h1>Bad request</h1><p>Invalid group/slug/title.</p>", { status: 400 });
    }
    var now = Date.now();
    var userId = req.user ? req.user.userId : "unknown";
    db.prepare(
      "INSERT INTO pages (groupName, slug, title, body, updatedAt, updatedBy) " +
      "VALUES (?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT (groupName, slug) DO UPDATE SET " +
      "  title = excluded.title, body = excluded.body, " +
      "  updatedAt = excluded.updatedAt, updatedBy = excluded.updatedBy"
    ).run(groupName, slug, title, content, now, userId);

    // Invalidate the page cache for this key so readers see the edit.
    await pageCache.del(groupName + "/" + slug);

    audit.safeEmit({
      action:   "wiki.page.edited",
      outcome:  "success",
      actor:    b.requestHelpers.extractActorContext(req),
      resource: { kind: "wiki.page", id: groupName + "/" + slug },
      metadata: { title: title, byteLength: content.length },
    });

    b.render.redirect(res, "/" + groupName + "/" + slug);
  });
}

module.exports = { register: register };
