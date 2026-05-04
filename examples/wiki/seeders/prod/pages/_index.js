"use strict";

// Ordered list of wiki pages — imported from the per-page modules.
// Order matches navigation in views/home.html and the welcome page
// at pages/welcome.js. Adding a new page is an explicit edit here.

module.exports = [
  require("./" + "welcome"),
  require("./" + "database"),
  require("./" + "object-store"),
  require("./" + "queue-cache"),
  require("./" + "auth"),
  require("./" + "access-control"),
  require("./" + "crypto-vault"),
  require("./" + "network-crypto"),
  require("./" + "routing"),
  require("./" + "middleware"),
  require("./" + "outbound-http"),
  require("./" + "network-config"),
  require("./" + "safe-parsers"),
  require("./" + "websockets"),
  require("./" + "mail"),
  require("./" + "notifications"),
  require("./" + "file-upload"),
  require("./" + "guard-csv"),
  require("./" + "observability"),
  require("./" + "testing"),
  require("./" + "i18n-locale"),
  require("./" + "format-helpers"),
  require("./" + "compliance-patterns"),
  require("./" + "cluster"),
  require("./" + "reliability"),
  require("./" + "backup-restore"),
  require("./" + "quality-contract"),
];
