from pathlib import Path
import requests
import time

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
                # raise DetonationError(f"Cannot reach CAPE at {url}: {exc}") from exc
            
            if response.status_code != 429:
                break
            if attempt >= self.max_retries:
                print("error")
                # raise DetonationError(
                #     f"CAPE throttled {url} (429) and {self.max_retries} retries did not solve the issue. Raise this user limit in CAPE's admin page"
                # )
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

client= cape_client("http://localhost:8000", token=None)
task= client.submit_file(Path("/home/jason/test.bat"))
print(task)