from dataclasses import dataclass
from typing import Dict


@dataclass
class ProxyResponse:
    """Proxy response."""
    status_code: int
    headers: Dict[str, str]
    body: str
