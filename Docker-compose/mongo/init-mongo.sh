#!/usr/bin/env bash
# MongoDB init script: creates the oidcop database, user, indexes, and a test client.
# Reference only. In Docker, the init is executed by relying-party-demo at startup
# (init_oidcop_mongo.py). For manual use, run this inside the mongo container with
# mongosh after setting MONGO_INITDB_* env vars.

mongosh -- "$MONGO_INITDB_DATABASE"<<EOF

var rootUser = '$MONGO_INITDB_ROOT_USERNAME';
var rootPassword = '$MONGO_INITDB_ROOT_PASSWORD';
 
var admin = db.getSiblingDB('admin');

admin.auth(rootUser, rootPassword);

var user = '$MONGO_INITDB_ROOT_USERNAME';
var passwd = '$MONGO_INITDB_ROOT_PASSWORD';

db.createUser(
  {
    user: user,
    pwd:  passwd,
    roles: [
        { role: "readWrite" , db: '$MONGO_INITDB_DATABASE'}
    ]
  }
);

EOF

