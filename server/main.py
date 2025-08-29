from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from typing import List, Optional
from dotenv import load_dotenv
import os
import sqlite3
import json
from datetime import datetime
import hashlib
import io
import csv

from database import get_db_connection, create_tables
from models import Machine, Snapshot, IngestRequest, Antivirus, SleepPolicy

load_dotenv()

app = FastAPI()

# Security
security = HTTPBearer()
API_TOKEN = os.getenv("API_TOKEN")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials

@app.on_event("startup")
def on_startup():
    create_tables()

@app.get("/")
def read_root():
    return {"message": "Welcome to the FastAPI backend for machine and snapshot management!"}

# Machine Endpoints
@app.post("/machines/", response_model=Machine)
def create_machine(machine: Machine, token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO machines (machine_id, hostname, os_name, os_version, last_seen, latest_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (machine.machine_id, machine.hostname, machine.os_name, machine.os_version, machine.last_seen.isoformat() if machine.last_seen else None, machine.latest_hash)
        )
        conn.commit()
        return machine
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Machine with this ID already exists")
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/machines/", response_model=List[Machine])
def read_machines(token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT machine_id, hostname, os_name, os_version, last_seen, latest_hash FROM machines")
    machines = []
    for row in cursor.fetchall():
        machines.append(Machine(
            machine_id=row[0],
            hostname=row[1],
            os_name=row[2],
            os_version=row[3],
            last_seen=datetime.fromisoformat(row[4]) if row[4] else None,
            latest_hash=row[5]
        ))
    conn.close()
    return machines

@app.get("/machines/{machine_id}", response_model=Machine)
def read_machine(machine_id: str, token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT machine_id, hostname, os_name, os_version, last_seen, latest_hash FROM machines WHERE machine_id = ?", (machine_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return Machine(
            machine_id=row[0],
            hostname=row[1],
            os_name=row[2],
            os_version=row[3],
            last_seen=datetime.fromisoformat(row[4]) if row[4] else None,
            latest_hash=row[5]
        )
    raise HTTPException(status_code=404, detail="Machine not found")

@app.put("/machines/{machine_id}", response_model=Machine)
def update_machine(machine_id: str, machine: Machine, token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE machines SET hostname = ?, os_name = ?, os_version = ?, last_seen = ?, latest_hash = ? WHERE machine_id = ?",
            (machine.hostname, machine.os_name, machine.os_version, machine.last_seen.isoformat() if machine.last_seen else None, machine.latest_hash, machine_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Machine not found")
        return machine
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.delete("/machines/{machine_id}")
def delete_machine(machine_id: str, token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM machines WHERE machine_id = ?", (machine_id,))
    conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Machine not found")
    conn.close()
    return {"message": "Machine deleted successfully"}

# Snapshot Endpoints
@app.post("/snapshots/", response_model=Snapshot)
def create_snapshot(snapshot: IngestRequest, token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if machine_id exists
        cursor.execute("SELECT machine_id FROM machines WHERE machine_id = ?", (snapshot.machine_id,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail=f"Machine with ID {snapshot.machine_id} not found")

        # Insert snapshot data
        cursor.execute(
            "INSERT INTO snapshots (machine_id, timestamp, payload, hash) VALUES (?, ?, ?, ?)",
            (
                snapshot.machine_id,
                snapshot.timestamp,
                json.dumps({
                    "disk_encryption": snapshot.disk_encryption,
                    "os_updates_pending": snapshot.os_updates_pending,
                    "antivirus": snapshot.antivirus.model_dump(),
                    "sleep_policy": snapshot.sleep_policy.model_dump()
                }),
                snapshot.hash # Assuming hash is part of the IngestRequest for now, though not explicitly in the new Snapshot model
            )
        )
        conn.commit()
        snapshot_id = cursor.lastrowid
        # Return the full Snapshot model, including the generated ID
        return Snapshot(
            id=snapshot_id,
            machine_id=snapshot.machine_id,
            timestamp=snapshot.timestamp,
            disk_encryption=snapshot.disk_encryption,
            os_updates_pending=snapshot.os_updates_pending,
            antivirus=snapshot.antivirus,
            sleep_policy=snapshot.sleep_policy
        )
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/snapshots/{machine_id}", response_model=List[Snapshot])
def read_snapshots(machine_id: str, token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, machine_id, timestamp, payload, hash FROM snapshots WHERE machine_id = ?", (machine_id,))
    snapshots = []
    for row in cursor.fetchall():
        payload_data = json.loads(row[3])
        snapshots.append(Snapshot(
            id=row[0],
            machine_id=row[1],
            timestamp=row[2],
            disk_encryption=payload_data.get("disk_encryption"),
            os_updates_pending=payload_data.get("os_updates_pending"),
            antivirus=Antivirus(**payload_data.get("antivirus", {"present": False})),
            sleep_policy=SleepPolicy(**payload_data.get("sleep_policy", {}))
        ))
    conn.close()
    return snapshots

@app.post("/api/v1/ingest")
def ingest_snapshot(ingest_request: IngestRequest, token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    changed = False
    try:
        # Compute hash of snapshot JSON
        snapshot_data_for_hash = ingest_request.model_dump(exclude={'machine_id', 'timestamp'})
        snapshot_json = json.dumps(snapshot_data_for_hash, sort_keys=True)
        current_hash = hashlib.sha256(snapshot_json.encode('utf-8')).hexdigest()

        # Check if machine_id exists
        cursor.execute("SELECT hostname, os_name, os_version, last_seen, latest_hash FROM machines WHERE machine_id = ?", (ingest_request.machine_id,))
        machine_record = cursor.fetchone()

        if machine_record:
            # Machine exists, update last_seen and latest_hash
            existing_latest_hash = machine_record["latest_hash"]
            
            # Update last_seen and latest_hash
            cursor.execute(
                "UPDATE machines SET last_seen = ?, latest_hash = ? WHERE machine_id = ?",
                (datetime.now().isoformat(), current_hash, ingest_request.machine_id)
            )
            conn.commit()

            if existing_latest_hash != current_hash:
                # Hash changed, insert new snapshot
                cursor.execute(
                    "INSERT INTO snapshots (machine_id, timestamp, payload, hash) VALUES (?, ?, ?, ?)",
                    (
                        ingest_request.machine_id,
                        ingest_request.timestamp,
                        json.dumps({
                            "disk_encryption": ingest_request.disk_encryption,
                            "os_updates_pending": ingest_request.os_updates_pending,
                            "antivirus": ingest_request.antivirus.model_dump(),
                            "sleep_policy": ingest_request.sleep_policy.model_dump()
                        }),
                        current_hash
                    )
                )
                conn.commit()
                changed = True
        else:
            # New machine_id, insert machine record and snapshot
            cursor.execute(
                "INSERT INTO machines (machine_id, hostname, os_name, os_version, last_seen, latest_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (ingest_request.machine_id, None, None, None, datetime.now().isoformat(), current_hash)
            )
            conn.commit()

            cursor.execute(
                "INSERT INTO snapshots (machine_id, timestamp, payload, hash) VALUES (?, ?, ?, ?)",
                (
                    ingest_request.machine_id,
                    ingest_request.timestamp,
                    json.dumps({
                        "disk_encryption": ingest_request.disk_encryption,
                        "os_updates_pending": ingest_request.os_updates_pending,
                        "antivirus": ingest_request.antivirus.model_dump(),
                        "sleep_policy": ingest_request.sleep_policy.model_dump()
                    }),
                    current_hash
                )
            )
            conn.commit()
            changed = True
        
        return {"accepted": True, "changed": changed}

    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/api/v1/machines")
def get_machines_with_latest_snapshot(issue: Optional[bool] = Query(False), token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    machines_data = []
    
    cursor.execute("SELECT machine_id, hostname, os_name, os_version, last_seen, latest_hash FROM machines")
    machines = cursor.fetchall()

    for machine_row in machines:
        machine_id = machine_row["machine_id"]
        
        # Get the latest snapshot for the machine
        cursor.execute(
            "SELECT id, machine_id, timestamp, payload, hash FROM snapshots WHERE machine_id = ? ORDER BY timestamp DESC LIMIT 1",
            (machine_id,)
        )
        latest_snapshot_row = cursor.fetchone()
        
        latest_snapshot = None
        has_issue = False

        if latest_snapshot_row:
            payload_data = json.loads(latest_snapshot_row["payload"])
            
            latest_snapshot = Snapshot(
                id=latest_snapshot_row["id"],
                machine_id=latest_snapshot_row["machine_id"],
                timestamp=latest_snapshot_row["timestamp"],
                disk_encryption=payload_data.get("disk_encryption"),
                os_updates_pending=payload_data.get("os_updates_pending"),
                antivirus=Antivirus(**payload_data.get("antivirus", {"present": False})),
                sleep_policy=SleepPolicy(**payload_data.get("sleep_policy", {}))
            )

            # Check for issues
            if issue:
                if latest_snapshot.disk_encryption != "enabled":
                    has_issue = True
                if latest_snapshot.os_updates_pending is True:
                    has_issue = True
                if not latest_snapshot.antivirus.present or (latest_snapshot.antivirus.present and latest_snapshot.antivirus.healthy is False):
                    has_issue = True
                if latest_snapshot.sleep_policy.ok is False:
                    has_issue = True
        
        machine_output = {
            "machine_id": machine_row["machine_id"],
            "hostname": machine_row["hostname"],
            "os_name": machine_row["os_name"],
            "os_version": machine_row["os_version"],
            "last_seen": machine_row["last_seen"],
            "latest_snapshot": latest_snapshot.model_dump() if latest_snapshot else None
        }

        if issue and not has_issue:
            continue # Skip machines without issues if issue=true

        machines_data.append(machine_output)
            
    conn.close()
    return machines_data

@app.get("/api/v1/export.csv")
async def get_export_csv(token: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    output = io.StringIO()
    writer = csv.writer(output)

    headers = [
        "machine_id", "hostname", "os_name", "os_version", "last_seen",
        "disk_encryption", "os_updates_pending", "antivirus_present",
        "antivirus_healthy", "sleep_minutes", "sleep_ok"
    ]
    writer.writerow(headers)

    cursor.execute("SELECT machine_id, hostname, os_name, os_version, last_seen FROM machines")
    machines = cursor.fetchall()

    for machine_row in machines:
        machine_id = machine_row["machine_id"]
        
        cursor.execute(
            "SELECT payload FROM snapshots WHERE machine_id = ? ORDER BY timestamp DESC LIMIT 1",
            (machine_id,)
        )
        latest_snapshot_row = cursor.fetchone()
        
        disk_encryption = None
        os_updates_pending = None
        antivirus_present = None
        antivirus_healthy = None
        sleep_minutes = None
        sleep_ok = None

        if latest_snapshot_row:
            payload_data = json.loads(latest_snapshot_row["payload"])
            disk_encryption = payload_data.get("disk_encryption")
            os_updates_pending = payload_data.get("os_updates_pending")
            
            antivirus_data = payload_data.get("antivirus", {})
            antivirus_present = antivirus_data.get("present")
            antivirus_healthy = antivirus_data.get("healthy")
            
            sleep_policy_data = payload_data.get("sleep_policy", {})
            sleep_minutes = sleep_policy_data.get("minutes")
            sleep_ok = sleep_policy_data.get("ok")

        writer.writerow([
            machine_row["machine_id"],
            machine_row["hostname"],
            machine_row["os_name"],
            machine_row["os_version"],
            machine_row["last_seen"],
            disk_encryption,
            os_updates_pending,
            antivirus_present,
            antivirus_healthy,
            sleep_minutes,
            sleep_ok
        ])
            
    conn.close()
    
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=export.csv"})
