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
    user : str
    authz_request : str
    access_token : str
    id_token : str
    refresh_token : str
    scope : str
    token_type : str
    expires_in : int
    created : str
    modified : str
    revoked : str
