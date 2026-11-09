import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

_client: Client | None = None

def get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_SERVICE_KEY"],
        )
    return _client

def save_scan(filename, file_type, file_size, hashes: dict, verdict, report: dict):
    row = {
        "filename": filename,
        "file_type": file_type,
        "file_size": file_size,
        "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"),
        "sha256": hashes["sha256"],
        "verdict": verdict,
        "report": report,
    }
    return get_client().table("scan_history").insert(row).execute()

def get_history(limit=50):
    return (get_client().table("scan_history")
            .select("id, created_at, filename, file_type, sha256, verdict")
            .order("created_at", desc=True)
            .limit(limit).execute().data)

def get_scan(scan_id):
    res = (get_client().table("scan_history")
           .select("*").eq("id", scan_id).single().execute())
    return res.data

def find_by_hash(sha256):
    res = (get_client().table("scan_history")
           .select("*").eq("sha256", sha256)
           .order("created_at", desc=True).limit(1).execute())
    return res.data[0] if res.data else None