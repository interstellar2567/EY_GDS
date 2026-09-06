from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Finding:
    scanner: str
    severity: str
    title: str
    description: str
    resource: str
    recommendation: str
    evidence: Optional[str] = None

    def to_dict(self):
        return asdict(self)