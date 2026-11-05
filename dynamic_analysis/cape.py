from pathlib import Path
import requests
import time

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

    def make_request(self, method:str, path:str, **kwargs):
        url= f"{self.api}{path}"
        attempt= 0 

        while True:
            try: 
                response= self.session.request(method, url, timeout=self.timeout, **kwargs)
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
            attempt +=1
        try:
            body= response.json()
        except ValueError:
            print("Error")
            # raise DetonationError(f"{response.status_code} from {url}: Response was not in JSON format")

        failed= response.status_code >= 400 or (
            isinstance(body, dict) and body.get("error") is True
        )
        if failed:
            msg= body
            if isinstance(body, dict):
                msg= body.get("error_value") or body.get("data") or body.get("data") or body
            # raise DetonationError(f"{response.status_code} from {url}: {msg}")
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
            #raise DetonationError(f"Unexpected response: {body}")
        return int(task_ids[0])
        # body= resp.json()
        # print(body)
        # return int(body["data"]["task_ids"][0])
        # return int(resp.json()["data"]["task_ids"][0])

    def get_status(self, task_id:int):
        body= self.make_request("GET", f"/tasks/status/{task_id}/")
        return str(self.unwrap(body))
    def get_report(self, task_id:int):
        body= self.make_request("GET",f"/tasks/get/report/{task_id}/json/")
        if isinstance(body, dict) and "info" not in body:
            body= self.unwrap(body)
        return body

class cape_backend:
    def __init__(self, base_url= "http://localhost:8000", token=None ):
        pass
client= cape_client("http://localhost:8000", token=None)
task= client.submit_file(Path("/home/jason/test.bat"))
print(task)
