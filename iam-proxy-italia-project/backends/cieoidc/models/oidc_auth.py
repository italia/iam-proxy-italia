from typing import Optional
from pydantic import BaseModel
from .user import OidcUser
from datetime import datetime


# class OidcAuthenticationOld(BaseModel):
#     """
#     Fields marked as Optional and without a default value must be entered (even if they are null).
#     """
#     id: Optional[str] = None
#     name: Optional[str] = None
#     client_id : Optional[str]
#     state : Optional[str]
#     endpoint : Optional[str]
#     data : Optional[str]
#     successful : Optional[bool] = None
#     provider_id : Optional[str] = None
#     provider_configuration : dict
#     created : Optional[str] = None
#     modified : Optional[str] = None
#
#
# class OidcAuthenticationToken(BaseModel):
#     """
#     Fields marked as Optional and without a default value must be entered (even if they are null).
#     """
#     user : Optional[str] = None
#     authz_request : Optional[dict]
#     access_token : Optional[str]
#     code: Optional[str]
#     id_token : Optional[str]
#     refresh_token : Optional[str] = None
#     scope : Optional[str]
#     token_type : Optional[str]
#     expires_in : Optional[int]
#     created : Optional[str] = None
#     modified : Optional[str] = None
#     revoked : Optional[str] = None


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

