import os

MONGO_URL = os.environ.get("MONGO_URL", "mongodb://satosa-mongo:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cie_oidc")
MONGO_AUTH_COLLECTION = os.getenv("MONGO_AUTH_COLLECTION", "authentication")
MONGO_TOKEN_COLLECTION = os.getenv("MONGO_TOKEN_COLLECTION", "authentication_token")
MONGO_USER_COLLECTION = os.getenv("MONGO_USER_COLLECTION", "users")
