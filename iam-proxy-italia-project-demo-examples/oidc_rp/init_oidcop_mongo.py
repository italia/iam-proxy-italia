#!/usr/bin/env python3
"""
MongoDB init script for oidcop: creates database user, indexes, and test OIDC client.
Executed by relying-party-demo at startup (before uvicorn). Idempotent.
"""

import os
import sys

try:
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure
except ImportError:
    print("init_oidcop_mongo: pymongo not installed, skipping MongoDB init", file=sys.stderr)
    sys.exit(0)

# Env vars: MONGO_URL, MONGO_PORT, MONGO_DBUSER, MONGO_DBPASSWORD, MONGO_INITDB_DATABASE
MONGO_URL = os.environ.get("MONGO_URL", "satosa-mongo")
MONGO_PORT = os.environ.get("MONGO_PORT", "27017")
MONGO_DBUSER = os.environ.get("MONGO_DBUSER", "satosa")
MONGO_DBPASSWORD = os.environ.get("MONGO_DBPASSWORD", "thatpassword")
MONGO_INITDB_DATABASE = os.environ.get("MONGO_INITDB_DATABASE", "oidcop")

TEST_CLIENT = {
    "client_id": "jbxedfmfyc",
    "client_name": "ciro",
    "client_salt": "6flfsj0Z",
    "registration_access_token": "z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY",
    "registration_client_uri": "https://iam-proxy-italia.example.org/registration_api?client_id=jbxedfmfyc",
    "client_id_issued_at": 1630952311.410208,
    "client_secret": "19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1",
    "client_secret_expires_at": 1802908740.410214,
    "application_type": "web",
    "contacts": ["ops@example.com"],
    "token_endpoint_auth_method": "client_secret_basic",
    "redirect_uris": [["http://localhost:8090/authz_cb/satosa", {}]],
    "post_logout_redirect_uris": [["https://localhost:8090/session_logout/satosa", None]],
    "response_types": ["code"],
    "grant_types": ["authorization_code"],
    "allowed_scopes": ["openid", "profile", "email", "offline_access"],
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
    db.client.create_index([("client_id", 1)], unique=True)
    db.client.create_index(
        [("registration_access_token", 1)],
        unique=True,
        partialFilterExpression={"registration_access_token": {"$type": "string"}},
    )
    db.session.create_index([("sid", 1)], unique=True)
    db.session.create_index(
        [("expires_at", 1)],
        expireAfterSeconds=0,
        partialFilterExpression={"count": {"$gt": 2}},
    )

    # Upsert test client (idempotent)
    db.client.update_one(
        {"client_id": TEST_CLIENT["client_id"]},
        {"$set": TEST_CLIENT},
        upsert=True,
    )
    client.close()


if __name__ == "__main__":
    main()
