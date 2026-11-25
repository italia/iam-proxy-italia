from typing import Optional
from pydantic import BaseModel
from .user import OidcUser
from datetime import datetime


class OidcAuthentication(BaseModel):

    # --- Authentication info ---
    id: Optional[str] = None
    client_id: Optional[str]
    state: Optional[str]
    endpoint: Optional[str]
    data: Optional[str]
    provider_id: Optional[str] = None
    provider_configuration: dict

    user: Optional[OidcUser] = None

    # --- Token info ---
    access_token: Optional[str] = None
    code: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None  # *
    scope: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    revoked: Optional[str] = None  # *

    # Set when the authorization response is accepted. The callback is single-use.
    completed: bool = False

    # --- Audit fields ---
    created: Optional[datetime] = None
    modified: Optional[datetime] = None


def authorization_already_used(authorization: "OidcAuthentication | dict") -> bool:
    """True when this authorization session must not be redeemed again.

    A session is spent once the callback has consumed it, or once a previous
    attempt already stored a code, access token, or user on it.
    """
    if isinstance(authorization, OidcAuthentication):
        completed = authorization.completed
        access_token = authorization.access_token
        code = authorization.code
        user = authorization.user
    else:
        completed = authorization.get("completed")
        access_token = authorization.get("access_token")
        code = authorization.get("code")
        user = authorization.get("user")
    return bool(completed or access_token or code or user)


def unused_authorization_filter(state: str) -> dict:
    """Mongo filter matching authorization_already_used() == False for ``state``."""
    return {
        "state": state,
        "completed": {"$ne": True},
        "access_token": None,
        "code": None,
        "user": None,
    }
