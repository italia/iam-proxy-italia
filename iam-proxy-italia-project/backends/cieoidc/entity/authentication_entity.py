from typing import Optional

from pydantic import BaseModel


class OidcAuthentication(BaseModel):

    client_id = str
    state = str
    endpoint = str
    data = str
    successful = bool
    provider_id = str
    provider_configuration = dict

