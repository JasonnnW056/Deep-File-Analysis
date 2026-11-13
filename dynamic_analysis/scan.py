import os
from pathlib import Path
from .backend_base import sandbox_report, status_callback
from .cape import cape_backend

DEFAULT_TIMEOUT= 200

def dynamic_scan(path: str|Path, *, timeout: int= DEFAULT_TIMEOUT, status: status_callback| None=None) -> sandbox_report:
    backend= cape_backend(base_url= os.getenv("CAPE_URL", "http://localhost:8000"),  submit_options={"options": "ignore_junk_filter=1"},)
    report= backend.detonate(path, timeout=timeout, status=status)
    
    return report