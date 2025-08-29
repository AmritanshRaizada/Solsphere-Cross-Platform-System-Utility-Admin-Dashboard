from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class Machine(BaseModel):
    machine_id: str
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    last_seen: Optional[datetime] = None
    latest_hash: Optional[str] = None

class Antivirus(BaseModel):
    present: bool
    healthy: Optional[bool] = None

class SleepPolicy(BaseModel):
    minutes: Optional[int] = None
    ok: Optional[bool] = None

class Snapshot(BaseModel):
    machine_id: str
    timestamp: str # ISO8601 string
    disk_encryption: str
    os_updates_pending: Optional[bool] = None
    antivirus: Antivirus
    sleep_policy: SleepPolicy

class IngestRequest(Snapshot):
    pass
