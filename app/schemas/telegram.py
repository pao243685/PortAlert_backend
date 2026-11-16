from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class TelegramStatusOut(BaseModel):
    state: Literal["none", "pending", "linked", "expired"]
    available: bool
    expires_at: datetime | None = None


class TelegramLinkOut(BaseModel):
    url: str
    web_url: str
    expires_at: datetime
