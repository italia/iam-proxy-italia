#!/usr/bin/env python3
"""
MongoDB init script for oidcop: creates database user, indexes, and test OIDC client.
Executed by relying-party-demo-mongo at startup. Idempotent.
All test client fields are configurable via OIDC_RP_DEMO_* env vars; see docs/demo-oidc-rp.md.
"""

import os
import sys

try:
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure
except ImportError:
    print("init_oidcop_mongo: pymongo not installed, skipping MongoDB init", file=sys.stderr)
    sys.exit(0)

# MongoDB connection
MONGO_URL = os.environ.get("MONGO_URL", "satosa-mongo")
MONGO_PORT = os.environ.get("MONGO_PORT", "27017")
MONGO_DBUSER = os.environ.get("MONGO_DBUSER", "satosa")
MONGO_DBPASSWORD = os.environ.get("MONGO_DBPASSWORD", "thatpassword")
MONGO_INITDB_DATABASE = os.environ.get("MONGO_INITDB_DATABASE", "oidcop")

# OIDC RP Demo test client — all from env (see docs/demo-oidc-rp.md)
def _get_test_client() -> dict:
    client_id = os.environ.get("OIDC_RP_DEMO_CLIENT_ID", "jbxedfmfyc")
    op_base = os.environ.get(
        "OIDC_RP_DEMO_OP_BASE_URL",
        os.environ.get("SATOSA_BASE", "https://iam-proxy-italia.example.org"),
    )
    redirect_uri = os.environ.get(
        "OIDC_RP_DEMO_REDIRECT_URI", "http://localhost:8090/authz_cb/satosa"
    )
    post_logout_uri = os.environ.get(
        "OIDC_RP_DEMO_POST_LOGOUT_REDIRECT_URI",
        "https://localhost:8090/session_logout/satosa",
    )
    contacts_str = os.environ.get("OIDC_RP_DEMO_CLIENT_CONTACTS", "ops@example.com")
    scopes_str = os.environ.get(
        "OIDC_RP_DEMO_ALLOWED_SCOPES", "openid,profile,email,offline_access"
    )
    return {
        "client_id": client_id,
        "client_name": os.environ.get("OIDC_RP_DEMO_CLIENT_NAME", "ciro"),
        "client_salt": os.environ.get("OIDC_RP_DEMO_CLIENT_SALT", "6flfsj0Z"),
        "registration_access_token": os.environ.get(
            "OIDC_RP_DEMO_REGISTRATION_ACCESS_TOKEN",
            "z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY",
        ),
        "registration_client_uri": f"{op_base.rstrip('/')}/registration_api?client_id={client_id}",
        "client_id_issued_at": float(
            os.environ.get("OIDC_RP_DEMO_CLIENT_ID_ISSUED_AT", "1630952311.410208")
        ),
        "client_secret": os.environ.get(
            "OIDC_RP_DEMO_CLIENT_SECRET",
            "19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1",
        ),
        "client_secret_expires_at": float(
            os.environ.get("OIDC_RP_DEMO_CLIENT_SECRET_EXPIRES_AT", "1802908740.410214")
        ),
        "application_type": os.environ.get("OIDC_RP_DEMO_APPLICATION_TYPE", "web"),
        "contacts": [c.strip() for c in contacts_str.split(",") if c.strip()],
        "token_endpoint_auth_method": os.environ.get(
            "OIDC_RP_DEMO_TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_basic"
        ),
        "redirect_uris": [[redirect_uri, {}]],
        "post_logout_redirect_uris": [[post_logout_uri, None]],
        "response_types": os.environ.get("OIDC_RP_DEMO_RESPONSE_TYPES", "code").split(","),
        "grant_types": os.environ.get(
            "OIDC_RP_DEMO_GRANT_TYPES", "authorization_code"
        ).split(","),
        "allowed_scopes": [s.strip() for s in scopes_str.split(",") if s.strip()],
    }


def main():
    uri = f"mongodb://{MONGO_DBUSER}:{MONGO_DBPASSWORD}@{MONGO_URL}:{MONGO_PORT}/admin"
    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
    try:
        client.admin.command("ping")
    except Exception as e:
        print(f"init_oidcop_mongo: MongoDB unreachable: {e}", file=sys.stderr)
        sys.exit(1)

    db = client[MONGO_INITDB_DATABASE]

    # Create user in oidcop (idempotent: ignore if exists)
    try:
        db.command(
            "createUser",
            MONGO_DBUSER,
            pwd=MONGO_DBPASSWORD,
            roles=[{"role": "readWrite", "db": MONGO_INITDB_DATABASE}],
        )
    except OperationFailure as e:
        if e.code != 51003:  # 51003 = user already exists
            raise

    # Indexes (idempotent)
    # Use db["client"] — db.client is the MongoClient, not the "client" collection
    client_coll = db["client"]
    session_coll = db["session"]
    client_coll.create_index([("client_id", 1)], unique=True)
    client_coll.create_index(
        [("registration_access_token", 1)],
        unique=True,
        partialFilterExpression={"registration_access_token": {"$type": "string"}},
    )
    session_coll.create_index([("sid", 1)], unique=True)
    session_coll.create_index(
        [("expires_at", 1)],
        expireAfterSeconds=0,
        partialFilterExpression={"count": {"$gt": 2}},
    )

    # Upsert test client (idempotent)
    test_client = _get_test_client()
    client_coll.update_one(
        {"client_id": test_client["client_id"]},
        {"$set": test_client},
        upsert=True,
    )
    client.close()


if __name__ == "__main__":
    main()
