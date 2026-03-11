#!/usr/bin/env bash

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
)

// make client_id unique
db.client.createIndex( { "client_id": 1 }, { unique: true } )
db.client.createIndex( { "registration_access_token": 1 }, { unique: true, partialFilterExpression: { registration_access_token: { \$type: "string" } } } )
// make access_token and sid unique
db.session.createIndex( { "sid": 1 }, { unique: true } )

// create expired session deletion
db.session.createIndex(
  { expires_at: 1 },
  { expireAfterSeconds: 0, partialFilterExpression: { count: { \$gt: 2 } } }
);

// insert a test client like this
db.client.insertOne(
   {
     "client_id":"jbxedfmfyc",
     "client_name":"ciro",
     "client_salt":"6flfsj0Z",
     "registration_access_token":"z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY",
     "registration_client_uri":"https://iam-proxy-italia.example.org/registration_api?client_id=jbxedfmfyc",
     "client_id_issued_at":1630952311.410208,
     "client_secret":"19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1",
     "client_secret_expires_at":1802908740.410214,
     "application_type":"web",
     "contacts":[
       "ops@example.com"
     ],
     "token_endpoint_auth_method":"client_secret_basic",
     "redirect_uris":[
      [
         "http://localhost:8090/authz_cb/satosa",
         {}
      ]
     ],
     "post_logout_redirect_uris":[
      [
         "https://localhost:8090/session_logout/satosa",
         null
      ]
     ],
      "response_types":[
        "code"
     ],
     "grant_types":[
      "authorization_code"
     ],
     "allowed_scopes":[
      "openid",
      "profile",
      "email",
      "offline_access"
    ]
  }
);

EOF

