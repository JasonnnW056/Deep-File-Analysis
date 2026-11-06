from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4


from dynamic_analysis.backend_base import sandbox_report

MALWARE_MIN_SCORE= 0.5
MAX_CONFIDENCE_SCORE= 95.0

VERDICT_COLORS={
    "MALWARE": colors.red(),
    "BENIGN": colors.green(),
    "INCONCLUSIVE": colors.gray()
}

@dataclass
class verdict:
    verdict:str #
    confidence_score: float
