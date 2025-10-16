from typing import Optional

from pydantic import BaseModel


class OidcUser(BaseModel):
    username: str
    first_name: str
    last_name: str
    email: str
    sub: str
    fiscal_number: str
    attributes : Optional[dict] = None

    def __str__(self):
        return f"username: {self.username}, first_name: {self.first_name}, last_name: {self.last_name}, email: {self.email}, sub: {self.sub}, fiscal_number: {self.fiscal_number}, attributes: {self.attributes}"


