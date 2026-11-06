"""Seed OpenID4VCI credential users from conf/frontends/openid4vci/users.json.

The credential endpoint looks up a pre-existing user record. Authentication
stores attributes on the authorization session and does not create that
record, so issuance fails with "User with {} not found" until these users
exist. Each document is upserted by fiscal_code.
"""

import json
import os
import sys
from pathlib import Path

from pymongo import MongoClient

USERS_FILE = Path(__file__).with_name("users.json")


def load_users(path: Path) -> list[dict]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError(f"{path} must contain a JSON array of users")
    for index, user in enumerate(document):
        if not isinstance(user, dict) or not user.get("fiscal_code"):
            raise ValueError(f"{path} entry {index} is missing fiscal_code")
    return document


def main() -> None:
    users_path = Path(os.environ.get("OPENID4VCI_DEMO_USERS_FILE", USERS_FILE))
    demo_users = load_users(users_path)
    client = MongoClient(
        os.environ["MONGO_PYEUDIW_OPENID4VCI_HOST"],
        username=os.environ["MONGODB_PYEUDIW_OPENID4VCI_USERNAME"],
        password=os.environ["MONGODB_PYEUDIW_OPENID4VCI_PASSWORD"],
        authSource="admin",
        serverSelectionTimeoutMS=5000,
    )
    users = client["pyeudiw_openid4vci"]["users"]
    for user in demo_users:
        users.update_one(
            {"fiscal_code": user["fiscal_code"]},
            {"$set": user},
            upsert=True,
        )
        print(f"openid4vci demo user ready: {user['fiscal_code']}", file=sys.stderr)


if __name__ == "__main__":
    main()
