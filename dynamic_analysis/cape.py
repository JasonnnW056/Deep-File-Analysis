from pathlib import Path
from typing import Any
import requests
import time

from backend_base import detonation_error, detonation_timeout, sandbox_report, status_callback
class cape_client:
    def __init__(self, cape_url="http://localhost:8000", token=None, timeout=60, is_tls=True, max_retries=3):
        self.api= cape_url.rstrip("/") + "/apiv2"
        self.timeout= timeout
        self.session= requests.Session()
        self.is_tls= is_tls
        self.max_retries= max_retries
        if token:
            self.session.headers["Authorization"]= f"Token {token}"

    def delay_retry(resp: requests.Response, attempt: int) -> float:
        try:
            delay= float(resp.headers.get("Retry-After", ""))
        except ValueError:
            delay= 2.0** (attempt+1)
        return max(0.0, min(delay,60.0))

    def make_request(self, method:str, path:str, **kwargs):
        url= f"{self.api}{path}"
        attempt= 0 

        while True:
            try: 
                response= self.session.request(method,url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                print("error")
                raise detonation_error(f"Cannot reach CAPE at {url}: {exc}") from exc
            
            if response.status_code != 429:
                break
            if attempt >= self.max_retries:
                print("error")
                raise detonation_error(
                    f"CAPE throttled {url} (429) and {self.max_retries} retries did not solve the issue. Raise this user limit in CAPE's admin page"
                )
            time.sleep(self.delay_retry(response, attempt))
            
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
        resp= self.session.post(
            f"{self.api}/tasks/create/file/",
            files={"file": (path.name, content)},
            data=data,
            timeout= self.timeout
        )
        resp.raise_for_status()
        # body= resp.json()
        # print(body)
        # return int(body["data"]["task_ids"][0])
        return int(resp.json()["data"]["task_ids"][0])

def get_head(items: Any, n: int= 50):
        return list(items)[:n] if items else []

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

    ttps= report.get("ttps") or []
    if isinstance(ttps, dict):
        ttps= list(ttps.keys)
    else:
        #If ttps in different key name
        ttps= [t.get("ttp") if isinstance(t, dict) else t for t in ttps]
    ttps= list(dict.fromkeys(t for t in ttps if t))

    file_dropped= []

    for f in report.get("dropped", []) or []:
        file_dropped.append({
            "name": f.get("name"),
            "size": f.get("size"),
            "type": f.get("type"),
            "sha256": f.get("sha256")
        })

    return sandbox_report(
        backend="cape",
        task_id=str(info.get("id", task_id)),
        score=report.get("malscore", info.get("score")),
        score_max=10.0,
        file={
            "name": target.get("name"),
            "size": target.get("size"),
            "type": target.get("type"),
            "md5": target.get("md5"),
            "sha1": target.get("sha1"),
            "sha256": target.get("sha256"),
        },
        duration=info.get("duration"),
        detections=report.get("detections"),
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
        extracted_payloads=len(((report.get("CAPE") or {}).get("payloads")) or []),
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
        # if not path.is_file():
        #     raise detonation_error(f"File is not valid")    
    
     
client= cape_client("http://localhost:8000", token=None)
task= client.submit_file(Path("/home/jason/test.bat"))
print(task)