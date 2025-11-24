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
    refresh_token: Optional[str] = None #*
    scope: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    revoked: Optional[str] = None #*

    # --- Audit fields ---
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
