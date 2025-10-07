from typing import Optional, Any
from dataclasses import dataclass, field


@dataclass
class DbConnectionConfig:
    host: str
    port: Optional[int]
    driver: Optional[str]
    username: Optional[str]
    password: Optional[str]
    database: Optional[str]
    tls: bool = False
    params: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> bool:
        ...