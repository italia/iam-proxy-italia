"""
Model for cached trust chain data persisted in storage.
Stores the subject configuration payload needed to reconstruct a usable trust chain.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class TrustChainCache(BaseModel):
    """
    Cached trust chain for a provider, persisted in MongoDB.
    The payload is subject_configuration.payload from TrustChainBuilder.
    """

    provider_url: str
    payload: dict  # subject_configuration.payload
    created: Optional[datetime] = None
    # Optional expiration from the entity statement; used when loading to skip stale entries
    exp: Optional[int] = None
