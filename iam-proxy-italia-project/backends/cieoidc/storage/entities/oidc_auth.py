from typing import Optional

from pydantic import BaseModel


class OidcAuthentication(BaseModel):
    id: Optional[int] = None
    name: str = None
    client_id : str
    state : str
    endpoint : str
    data : str
    successful : bool
    provider_id : str
    provider_configuration : dict
    created : str
    modified : str

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