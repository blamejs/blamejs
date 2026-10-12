// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Search indexes a text rendition of each page instead of its HTML.
 *
 * `pages.body` is operator-authored HTML. Indexing it put markup in the
 * index: a CSS class name such as `pill` matched fifty pages, and
 * `snippet()` cut its excerpt at a token boundary inside the markup, so an
 * excerpt could open a tag it never closed and a highlight could land
 * inside an `href`, which produced result links to `/<mark>csv</mark>`.
 *
 * `pages.bodyText` holds the text a reader sees. The FTS5 mirror indexes
 * that column in the slot `body` held, so `snippet(pages_fts, 3, ...)`
 * keeps its column number.
 */

var { htmlToSearchText } = require("../lib/html-entities");

module.exports = {
  description: "Index a text rendition of each page body for search",
  up: function (db) {
    db["exec"]("ALTER TABLE pages ADD COLUMN bodyText TEXT NOT NULL DEFAULT ''");

    // Triggers and the mirror go first, so the backfill below writes
    // `pages` rows without each UPDATE re-inserting an FTS row.
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_update");
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_delete");
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_insert");
    db["exec"]("DROP TABLE IF EXISTS pages_fts");

    var rows = db.prepare("SELECT groupName, slug, body FROM pages").all();
    var update = db.prepare(
      "UPDATE pages SET bodyText = ? WHERE groupName = ? AND slug = ?"
    );
    for (var i = 0; i < rows.length; i++) {
      update.run(htmlToSearchText(rows[i].body), rows[i].groupName, rows[i].slug);
    }

    db["exec"](
      "CREATE VIRTUAL TABLE pages_fts USING fts5(" +
      "  groupName UNINDEXED," +
      "  slug      UNINDEXED," +
      "  title," +
      "  bodyText," +
      "  tokenize = 'porter'" +
      ")"
    );
    db["exec"](
      "CREATE TRIGGER pages_fts_insert AFTER INSERT ON pages BEGIN " +
      "  INSERT INTO pages_fts (groupName, slug, title, bodyText) " +
      "  VALUES (new.groupName, new.slug, new.title, new.bodyText); " +
      "END"
    );
    db["exec"](
      "CREATE TRIGGER pages_fts_delete AFTER DELETE ON pages BEGIN " +
      "  DELETE FROM pages_fts WHERE groupName = old.groupName AND slug = old.slug; " +
      "END"
    );
    db["exec"](
      "CREATE TRIGGER pages_fts_update AFTER UPDATE ON pages BEGIN " +
      "  DELETE FROM pages_fts WHERE groupName = old.groupName AND slug = old.slug; " +
      "  INSERT INTO pages_fts (groupName, slug, title, bodyText) " +
      "  VALUES (new.groupName, new.slug, new.title, new.bodyText); " +
      "END"
    );
    db["exec"](
      "INSERT INTO pages_fts (groupName, slug, title, bodyText) " +
      "SELECT groupName, slug, title, bodyText FROM pages"
    );
  },
  down: function (db) {
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_update");
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_delete");
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_insert");
    db["exec"]("DROP TABLE IF EXISTS pages_fts");
    db["exec"](
      "CREATE VIRTUAL TABLE pages_fts USING fts5(" +
      "  groupName UNINDEXED," +
      "  slug      UNINDEXED," +
      "  title," +
      "  body," +
      "  tokenize = 'porter'" +
      ")"
    );
    db["exec"](
      "CREATE TRIGGER pages_fts_insert AFTER INSERT ON pages BEGIN " +
      "  INSERT INTO pages_fts (groupName, slug, title, body) " +
      "  VALUES (new.groupName, new.slug, new.title, new.body); " +
      "END"
    );
    db["exec"](
      "CREATE TRIGGER pages_fts_delete AFTER DELETE ON pages BEGIN " +
      "  DELETE FROM pages_fts WHERE groupName = old.groupName AND slug = old.slug; " +
      "END"
    );
    db["exec"](
      "CREATE TRIGGER pages_fts_update AFTER UPDATE ON pages BEGIN " +
      "  DELETE FROM pages_fts WHERE groupName = old.groupName AND slug = old.slug; " +
      "  INSERT INTO pages_fts (groupName, slug, title, body) " +
      "  VALUES (new.groupName, new.slug, new.title, new.body); " +
      "END"
    );
    db["exec"](
      "INSERT INTO pages_fts (groupName, slug, title, body) " +
      "SELECT groupName, slug, title, body FROM pages"
    );
    db["exec"]("ALTER TABLE pages DROP COLUMN bodyText");
  },
};
