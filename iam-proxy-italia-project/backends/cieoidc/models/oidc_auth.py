from typing import Optional

from pydantic import BaseModel


class OidcAuthentication(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None#todo check if can be optional
    client_id : str
    state : str
    endpoint : str
    data : str
    successful : Optional[bool] = None #todo check if can be optional
    provider_id : Optional[str] = None #todo check if can be optional
    provider_configuration : dict
    created : Optional[str] = None #todo check if can be optional
    modified : Optional[str] = None  #todo check if can be optional


class OidcAuthenticationToken(BaseModel):
    user : Optional[str] = None
    authz_request : dict
    access_token : str
    code: str
    id_token : str
    refresh_token : Optional[str] = None
    scope : str
    token_type : str
    expires_in : int
    created : Optional[str] = None
    modified : Optional[str] = None
    revoked : Optional[str] = None

