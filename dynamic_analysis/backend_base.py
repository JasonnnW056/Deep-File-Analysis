from dataclasses import dataclass, field, asdict
from typing import Any, Callable

class detonation_error(Exception):
    """The sandbox could not run or finish the file detonation"""

class detonation_timeout(detonation_error):
    """The analysis did not finish within the wait time set"""

@dataclass
class sandbox_report:
    task_id: str
    cape_score: float | None
    max_score: float
    file: dict
    detonation_duration: int
    malware_detected: Any
    signatures: list[dict]
    ttps: list[str]
    behavior: dict
    network: dict
    dropped_files: list[dict]
    total_extracted_payloads: int
    total_seconds: float | None=None

    raw:dict= field(default_factory=dict, repr=False)

    def to_dict(self, include_raw: bool= False) -> dict:
        data= asdict(self)
        if not include_raw:
            data.pop("raw", None)
        return data

status_callback= Callable[[str], None]