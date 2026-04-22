from typing import Optional

from pydantic import BaseModel


class OidcUser(BaseModel):
    username: str
    given_name: str
    family_name: str
    email: str
    sub: str
    fiscal_number: str
    attributes: Optional[dict] = None
