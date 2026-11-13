from pathlib import Path
from typing import Any
import requests
import time

from .backend_base import detonation_error, detonation_timeout, sandbox_report, status_callback

#Task status
STATUS_REPORTED= {"reported"}
STATUS_FAILED= {"failed", "failed_analysis", "failed_reporting"}


class cape_client:
    def __init__(self, cape_url="http://localhost:8000", token=None, timeout=60, is_tls=True, max_retries=3):
        self.api= cape_url.rstrip("/") + "/apiv2"
        self.timeout= timeout
        self.session= requests.Session()
        self.is_tls= is_tls
        self.max_retries= max_retries
        if token:
            self.session.headers["Authorization"]= f"Token {token}"

    @staticmethod
    def delay_retry(resp: requests.Response, attempt: int) -> float:
        try:
            delay= float(resp.headers.get("Retry-After", ""))
        except ValueError:
            delay= 2.0** (attempt+1)
        return max(0.0, min(delay,60.0))

    #Make request to the CAPE Backend
    def make_request(self, method:str, path:str, **kwargs):
        url= f"{self.api}{path}"
        attempt= 0 

        while True:
            try: 
                response= self.session.request(method, url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                print("error")
                raise detonation_error(f"Cannot reach CAPE at {url}: {exc}") from exc
            
            if response.status_code != 429:
                break
            if attempt >= self.max_retries:
                raise detonation_error(
                    f"CAPE throttled {url} (429) and {self.max_retries} retries did not solve the issue. Raise this user limit in CAPE's admin page"
                )
            time.sleep(self.delay_retry(response, attempt))
            attempt +=1
        try:
            body= response.json()
        except ValueError:
            raise detonation_error(f"{response.status_code} from {url}: Response was not in JSON format")

        failed= response.status_code >= 400 or (
            isinstance(body, dict) and body.get("error") is True
        )
        if failed:
            msg = body
            if isinstance(body, dict):
                msg = body.get("error_value") or body.get("data") or body
                if body.get("errors"):
                    msg = f"{msg}: {body['errors']}"
            raise detonation_error(f"{response.status_code} from {url}: {msg}")
        return body

    @staticmethod
    def unwrap(body):
        if isinstance(body, dict) and "data" in body and "error" in body:
            return body["data"]
        return body


    def submit_file(self, path: Path, *, timeout=120, package= None, machine=None, platform=None, options=None, tags=None,
                    priority=1, enforce_timeout=False, memory=False)-> int:
        data={"timeout":timeout, "priority":priority}
        for key, value in (("package",package),("machine",machine),("platform",platform),("options",options),("tags",tags)):
            if value:
                data[key]= value

        if enforce_timeout:
            data["enforce_timeout"]= 1

        if memory:
            data["memory"]= 1

        content= path.read_bytes()
        body= self.make_request(
            "POST",
            "/tasks/create/file/",
            files={"file": (path.name, content)},
            data=data
        )
        resp= self.unwrap(body)
        task_ids= resp.get("task_ids") if isinstance(resp, dict) else None

        if not task_ids:
            print("Error")
            raise detonation_error(f"Unexpected response: {body}")
        return int(task_ids[0])

    def get_status(self, task_id:int):
        body= self.make_request("GET", f"/tasks/status/{task_id}/")
        return str(self.unwrap(body))
    def get_report(self, task_id:int):
        body= self.make_request("GET",f"/tasks/get/report/{task_id}/json/")
        if isinstance(body, dict) and "info" not in body:
            body= self.unwrap(body)
        return body


def get_head(items: Any, n: int= 50):
        return list(items)[:n] if items else []

#To parse the TTPS
def collect_ttps(report: dict, signatures: list) -> list:
    found = []

    def add(t):
        if isinstance(t, dict):
            t = t.get("ttp") or t.get("t_id") or t.get("id")
        if t:
            found.append(str(t))

    raw = report.get("ttps") or []
    if isinstance(raw, dict):
        raw = list(raw.keys())
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("ttps"), list):
            for t in item["ttps"]:
                add(t)
        else:
            add(item)

    for s in signatures:
        for t in s.get("ttps") or []:
            add(t)

    return list(dict.fromkeys(found))

def detection_families(detections) -> list[str]:
    """CAPE gives [{'family': 'XWorm', 'details': [...]}] (older versions: a plain string)."""
    if not detections:
        return []
    if isinstance(detections, (str, dict)):
        detections = [detections]
    names = []
    for d in detections:
        if isinstance(d, dict):
            d = d.get("family") or d.get("name")
        if d:
            names.append(str(d))
    return list(dict.fromkeys(names)) 

#To normalize report from the raw report generated
def normalize_report(report:dict, task_id:int)-> sandbox_report:
    info= report.get("info",{}) or {}
    target= (report.get("target",{})or {}).get("file",{}) or {}
    behavior= (report.get("behavior",{})or {}).get("summary",{}) or {}
    network= report.get("network",{}) or {}

    signatures=[]
    for s in report.get("signatures") or []:
        signatures.append({
            "name": s.get("name"),
            "description": s.get("description"),
            "severity": s.get("severity",0),
            "ttps": s.get("ttps") or s.get("attack") or []
        })
    signatures.sort(key=lambda s: s["severity"] or 0, reverse= True) 

    ttps = collect_ttps(report, signatures)
    
    file_dropped = []

    for f in report.get("dropped", []) or []:
        name = f.get("name")
        if isinstance(name, (list, tuple)):
            name = ", ".join(str(n) for n in name)
        file_dropped.append({
            "name": name,
            "size": f.get("size"),
            "type": f.get("type"),
            "sha256": f.get("sha256"),
        })

    return sandbox_report(
        task_id=str(info.get("id", task_id)),
        cape_score=report.get("malscore", info.get("score")),
        max_score=10.0,
        file={
            "name": target.get("name"),
            "size": target.get("size"),
            "type": target.get("type"),
            "md5": target.get("md5"),
            "sha1": target.get("sha1"),
            "sha256": target.get("sha256"),
        },
        detonation_duration=info.get("duration"),
        malware_detected=detection_families(report.get("detections")),
        signatures=signatures,
        ttps=ttps,
        behavior={
            "executed_commands": get_head(behavior.get("executed_commands")),
            "files_written": get_head(behavior.get("write_files")),
            "files_deleted": get_head(behavior.get("delete_files")),
            "registry_written": get_head(behavior.get("write_keys")),
            "mutexes": get_head(behavior.get("mutexes")),
            "services_created": get_head(behavior.get("created_services")),
        },
        network={
            "hosts": get_head(network.get("hosts")),
            "domains": get_head(network.get("domains")),
            "http": get_head(network.get("http")),
            "tcp_count": len(network.get("tcp", []) or []),
            "udp_count": len(network.get("udp", []) or []),
        },
        dropped_files=get_head(file_dropped),
        total_extracted_payloads=len(((report.get("CAPE") or {}).get("payloads")) or []),
        raw=report,
    )

class cape_backend():
    def __init__(self, base_url: str= "http://localhost:8000", token:str |None=None, 
                 *, poll_interval: float= 15, extra_time: float= 600, submit_options: dict | None=None,
                 max_retries: int= 3):
        self.client= cape_client(base_url, token, max_retries= max_retries)
        self.poll_interval= poll_interval
        self.extra_time= extra_time
        self.submit_options= submit_options or {}

    def detonate(self, path:str | Path,
                 *, timeout:int= 120, status:status_callback| None=None)-> sandbox_report:
        path= Path(path)
        if not path.is_file():
            raise detonation_error(f"File is not valid") 
        start_timer= time.monotonic()
        task_id= self.client.submit_file(path, timeout=timeout, **self.submit_options)
        if status:
            status(f"Submitted file. Task id= {task_id}")

        deadline= start_timer+ timeout+ self.extra_time
        last_status= None

        while True:
            current_status= self.client.get_status(task_id)
            if current_status != last_status:
                last_status= current_status
                if status:
                    status(current_status)
            if current_status in STATUS_REPORTED:
                break
            if current_status in STATUS_FAILED:
                raise detonation_error(f"CAPE task {task_id} ended with status {current_status}")
            if time.monotonic()> deadline:
                raise detonation_timeout(f"CAPE task {task_id} still {current_status} after {timeout + self.extra_time}s")
            time.sleep(self.poll_interval)

        report= self.client.get_report(task_id)
        result= normalize_report(report, task_id)
        result.total_seconds = round(time.monotonic() - start_timer, 2)
        return result