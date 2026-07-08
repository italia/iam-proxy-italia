#!/usr/bin/env python3
"""
MongoDB initialization script for the OpenID4VCIFrontend module.

This module populates the MongoDB database with the user data required by the OID4VCI Issuer.

To simulate the Authentic Source database, it uses data from the CIE provider dump, which contains the identity
and personal information of test users.

WARNING: this script is intended exclusively for DEMO and local development purposes.
It must not be used in production environments.
"""
import json
import os
import sys

from pymongo import MongoClient
from pyeudiw.satosa.frontends.openid4vci.openid4vci import OpenID4VCIFrontend
from satosa.plugin_loader import load_frontends
from satosa.satosa_config import SATOSAConfig


config_file = os.environ.get("SATOSA_CONFIG", "proxy_conf.yaml")
satosa_config = SATOSAConfig(config_file)

def init_db(_config: dict):
    print("Initializing Database...")

    mongo_cnf = _config.get("mongo_db", {}).get("storage", {})
    params = mongo_cnf.get("init_params", {})
    db_name = params.get("conf", {}).get("db_name", "")
    client = None

    # sync dataset
    try:
        client = MongoClient(
            params.get("url"),
            username=params.get("connection_params", {}).get("username"),
            password=params.get("connection_params", {}).get("password"),
            serverSelectionTimeoutMS=10000)

        db = client[db_name]
        collection = db[params.get("conf", {}).get("db_users_collection", "")]

        inserted = 0; updated = 0; unchanged = 0; errors = 0
        for _user_cie in _parse_user_provider():
            try:
                result = collection.update_one(
                    {"fiscal_code": _user_cie.get("fiscal_code")},
                    {"$set": _user_cie},
                    upsert=True,
                )
                if result.upserted_id is not None:
                    inserted += 1
                elif result.modified_count > 0:
                    updated += 1
                else:
                    unchanged += 1
            except Exception as e:
                errors += 1
                print(f"An error occurred: {e}", file=sys.stderr)
                continue
    except Exception as e:
        print(f"An error occurred while syncing the dataset: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if client is not None:
            client.close()

    print(f"Dataset sync completed — inserted: {inserted}, updated: {updated}, unchanged: {unchanged}, errors: {errors}")
    sys.exit(0)

def load_config():
    """Load SATOSA plugin config"""
    def _callback(*args):
        pass

    frontends = load_frontends(satosa_config, _callback, satosa_config["INTERNAL_ATTRIBUTES"])
    for f in frontends:
        if isinstance(f, OpenID4VCIFrontend):
            config = f.config
            break
    else:
        print("OpenID4VCIFrontend plugin module not found")
        sys.exit(1)
    return config.get("user_storage", {})


def _parse_user_provider() -> list[dict]:
    """Parse non-superuser spid_cie_oidc_accounts.user from the spid_cie_oidc_django (provider) sqlite dump."""

    path_dump = os.environ.get("PATH_DUMP")
    with open(path_dump, encoding="utf-8") as f:
        data = json.load(f)
    users = []
    for entry in data:
        if entry.get("model") == "spid_cie_oidc_accounts.user" and not entry["fields"].get("is_superuser", False):
            fields = entry["fields"]
            attrs = fields.get("attributes", {})
            place_of_birth = attrs.get("place_of_birth", {})
            address = attrs.get("address", {})
            country_code = address.get("country_code", "IT")

            users.append({
                "name": attrs.get("given_name", ""),
                "surname": attrs.get("family_name", ""),
                "dateOfBirth": attrs.get("birthdate", ""),
                "mail": attrs.get("email", fields.get("email", "")),
                "fiscal_code": attrs.get("https://attributes.eid.gov.it/fiscal_number", ""),
                "placeOfBirth": address.get("locality", place_of_birth.get("locality", "")),
                "countyOfBirth": place_of_birth.get("region", ""),
                "nationalities": [country_code] if country_code else [],
            })
    return users

if __name__ == "__main__":
    _config = load_config()
    init_db(_config)