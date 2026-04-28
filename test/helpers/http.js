"use strict";
/**
 * HTTP test helpers — mostly the listenOnRandomPort utility that
 * collapsed the `await new Promise(r => server.listen(0, host, r));
 * var port = server.address().port;` boilerplate every consumer test
 * was repeating.
 *
 * Works with anything that has the listen(port, host, cb) + address()
 * shape (http.Server, http2.Server, net.Server, tls.Server).
 */

function listenOnRandomPort(server, host) {
  host = host || "127.0.0.1";
  return new Promise(function (resolve, reject) {
    server.once("error", reject);
    server.listen(0, host, function () {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

module.exports = {
  listenOnRandomPort: listenOnRandomPort,
};
