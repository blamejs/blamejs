#!/bin/sh
# MongoDB needs the cert + key concatenated into a single PEM file
# and readable by the mongodb user. Copy from the cert volume into
# a writable location and chown.
set -eu
mkdir -p /etc/mongo-tls
cp /certs/mongo.combined.pem /etc/mongo-tls/server.pem
cp /certs/ca.crt /etc/mongo-tls/ca.pem
chmod 600 /etc/mongo-tls/server.pem
chmod 644 /etc/mongo-tls/ca.pem
# mongo container runs as `mongodb` user; chown if the user exists.
id mongodb >/dev/null 2>&1 && chown mongodb:mongodb /etc/mongo-tls/* || true
