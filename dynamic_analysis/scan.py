import json
import os

from pathlib import Path
from backend_base import sandbox_report, status_callback
from cape import cape_backend

DEFAULT_TIMEOUT= 120

def scan(path: str|Path, *, timeout: int= DEFAULT_TIMEOUT, status: status_callback| None=None) -> sandbox_report:
    backend= cape_backend(base_url= os.getenv("CAPE_URL", "http://localhost:8000"))
    report= backend.detonate(path, timeout=timeout, status=status)
    save_report(report, Path(path), status)

    return report

def save_report(report: sandbox_report, sample: Path, status)-> None:
    try:
        out_dir = Path(os.getenv("RAW_REPORT_DIR", "raw_reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = f"{sample.stem}_{report.task_id}"

        (out_dir / f"{stem}_raw.json").write_text(json.dumps(report.raw, default=str))
        (out_dir / f"{stem}_summary.json").write_text(
            json.dumps(report.to_dict(), indent=2, default=str)
        )
        if status:
            status(f"reports saved to {out_dir}/{stem}_*.json")
    except OSError as exc:
        if status:
            status(f"could not save reports: {exc}")