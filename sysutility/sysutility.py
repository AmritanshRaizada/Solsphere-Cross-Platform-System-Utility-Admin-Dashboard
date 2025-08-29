import platform
import subprocess
import hashlib
import os
import json
import requests
import time
import argparse
from datetime import datetime
from .config import API_URL, API_TOKEN, POLL_INTERVAL_MINUTES

# sysutility.py - Main script for system utility

def get_machine_id():
    """
    Retrieves the machine ID based on the operating system and returns its SHA-256 hash.
    """
    machine_id = None
    system = platform.system()

    if system == "Windows":
        try:
            # Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
            result = subprocess.run(
                ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"],
                capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            for line in result.stdout.splitlines():
                if "MachineGuid" in line:
                    machine_id = line.split("REG_SZ")[-1].strip()
                    break
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error getting MachineGuid on Windows: {e}")
    elif system == "Darwin":  # macOS
        try:
            # ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    machine_id = line.split("=")[-1].strip().strip('"')
                    break
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error getting IOPlatformUUID on macOS: {e}")
    elif system == "Linux":
        try:
            # Read /etc/machine-id
            with open("/etc/machine-id", "r") as f:
                machine_id = f.read().strip()
        except FileNotFoundError:
            print("Error: /etc/machine-id not found on Linux.")
        except Exception as e:
            print(f"Error reading /etc/machine-id on Linux: {e}")
    else:
        print(f"Unsupported operating system: {system}")

    if machine_id:
        return hashlib.sha256(machine_id.encode('utf-8')).hexdigest()
    return None


def disk_encryption_status() -> str:
    """
    Checks the disk encryption status based on the operating system.
    Returns "enabled", "disabled", or "unknown".
    """
    system = platform.system()
    status = "unknown"

    if system == "Windows":
        try:
            result = subprocess.run(
                ["manage-bde", "-status"],
                capture_output=True, text=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            if "Protection Status: Protection On" in result.stdout:
                status = "enabled"
            elif "Protection Status: Protection Off" in result.stdout:
                status = "disabled"
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking BitLocker status on Windows: {e}")
    elif system == "Darwin":  # macOS
        try:
            result = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True, text=True, check=False
            )
            if "FileVault is On." in result.stdout:
                status = "enabled"
            elif "FileVault is Off." in result.stdout:
                status = "disabled"
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking FileVault status on macOS: {e}")
    elif system == "Linux":
        try:
            # Check for LUKS encrypted root volume
            result = subprocess.run(
                ["lsblk", "-o", "NAME,TYPE,MOUNTPOINT"],
                capture_output=True, text=True, check=True
            )
            root_device = None
            for line in result.stdout.splitlines():
                if "/" in line and "part" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] == "/":
                        root_device = parts[0].replace("└─", "").replace("├─", "")
                        break

            if root_device:
                crypt_result = subprocess.run(
                    ["cryptsetup", "isLuks", f"/dev/{root_device}"],
                    capture_output=True, text=True, check=False
                )
                if crypt_result.returncode == 0:
                    status = "enabled"
                else:
                    status = "disabled"
            else:
                print("Could not determine root device for Linux encryption check.")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking LUKS encryption on Linux: {e}")
    
    return status


def os_update_status() -> bool | None:
    """
    Checks if OS updates are pending.
    Returns True if updates are pending, False if up-to-date, None if unknown.
    """
    system = platform.system()
    updates_pending = None

    if system == "Windows":
        try:
            powershell_command = """
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResults = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
            if ($searchResults.Updates.Count -gt 0) {
                Write-Host "UpdatesPending: True"
            } else {
                Write-Host "UpdatesPending: False"
            }
            """
            result = subprocess.run(
                ["powershell", "-Command", powershell_command],
                capture_output=True, text=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if "UpdatesPending: True" in result.stdout:
                updates_pending = True
            elif "UpdatesPending: False" in result.stdout:
                updates_pending = False
            else:
                print(f"Could not determine Windows update status. Output: {result.stdout}")
                updates_pending = None
        except Exception as e:
            print(f"Error checking Windows update status: {e}")
    elif system == "Darwin":  # macOS
        try:
            result = subprocess.run(
                ["softwareupdate", "-l"],
                capture_output=True, text=True, check=False
            )
            if "No new software available." in result.stdout:
                updates_pending = False
            elif "Software Update found the following new or updated software:" in result.stdout:
                updates_pending = True
            else:
                updates_pending = None # Could not determine
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking macOS update status: {e}")
    elif system == "Linux":
        try:
            # Check for apt-get (Debian/Ubuntu) or dnf (Fedora/RHEL)
            if os.path.exists("/usr/bin/apt-get"):
                result = subprocess.run(
                    ["apt-get", "-s", "upgrade"],
                    capture_output=True, text=True, check=False
                )
                if "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded." in result.stdout:
                    updates_pending = False
                elif "Inst" in result.stdout or "Upgr" in result.stdout: # Indicates packages to install/upgrade
                    updates_pending = True
                else:
                    updates_pending = None
            elif os.path.exists("/usr/bin/dnf"):
                result = subprocess.run(
                    ["dnf", "check-update"],
                    capture_output=True, text=True, check=False
                )
                if "Last metadata expiration check" in result.stdout and "No packages marked for update" in result.stdout:
                    updates_pending = False
                elif "updates available" in result.stdout.lower() or "packages available for update" in result.stdout.lower():
                    updates_pending = True
                else:
                    updates_pending = None
            else:
                print("No supported package manager (apt-get or dnf) found for Linux update check.")
                updates_pending = None
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking Linux update status: {e}")
    
    return updates_pending


def antivirus_status() -> dict:
    """
    Checks for the presence and health of common antivirus software.
    Returns a dictionary { present: True/False, healthy: True/False/None }.
    Returns None if cannot detect.
    """
    system = platform.system()
    status = {"present": False, "healthy": None}

    if system == "Windows":
        try:
            powershell_command = """
            try {
                $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState
                if ($avProducts.Count -gt 0) {
                    Write-Host "Present: True"
                    $healthyCount = ($avProducts | Where-Object { ($_.productState -band 0x1000) -and ($_.productState -band 0x10000) }).Count
                    if ($healthyCount -gt 0) {
                        Write-Host "Healthy: True"
                    } else {
                        Write-Host "Healthy: False"
                    }
                } else {
                    Write-Host "Present: False"
                }
            } catch {
                Write-Host "Error: $($_.Exception.Message)"
            }
            """
            result = subprocess.run(
                ["powershell", "-Command", powershell_command],
                capture_output=True, text=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if "Present: True" in result.stdout:
                status["present"] = True
                if "Healthy: True" in result.stdout:
                    status["healthy"] = True
                elif "Healthy: False" in result.stdout:
                    status["healthy"] = False
            elif "Present: False" in result.stdout:
                status["present"] = False
            else:
                print(f"Could not determine Windows antivirus status. Output: {result.stdout}")
                status["present"] = False
                status["healthy"] = None
        except Exception as e:
            print(f"Error checking Windows antivirus status: {e}")
    elif system == "Darwin":  # macOS
        common_av_apps = ["/Applications/Sophos Home.app", "/Applications/Malwarebytes.app"]
        common_av_processes = ["SophosScanD", "MBAMService"]
        
        for app in common_av_apps:
            if os.path.exists(app):
                status["present"] = True
                break
        
        if not status["present"]:
            try:
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, check=True
                )
                for proc in common_av_processes:
                    if proc in result.stdout:
                        status["present"] = True
                        break
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"Error checking macOS processes for AV: {e}")

        if status["present"]:
            status["healthy"] = True # Assume healthy if present
    elif system == "Linux":
        common_av_processes = ["clamd", "freshclam"]
        clamav_installed = False
        try:
            result = subprocess.run(
                ["dpkg", "-l", "clamav"],
                capture_output=True, text=True, check=False
            )
            if "clamav" in result.stdout:
                clamav_installed = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        if not clamav_installed:
            try:
                result = subprocess.run(
                    ["rpm", "-q", "clamav"],
                    capture_output=True, text=True, check=False
                )
                if "clamav" in result.stdout:
                    clamav_installed = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        if clamav_installed:
            status["present"] = True
            try:
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, check=True
                )
                for proc in common_av_processes:
                    if proc in result.stdout:
                        status["healthy"] = True
                        break
                if status["healthy"] is None:
                    status["healthy"] = False
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"Error checking Linux processes for AV: {e}")
        
    return status


def sleep_policy() -> dict:
    """
    Checks the system's sleep policy.
    Returns a dictionary { minutes: int, ok: True/False, None if unknown }.
    'ok' is True if sleep delay is <= 10 minutes, False otherwise.
    """
    system = platform.system()
    policy = {"minutes": None, "ok": None}

    if system == "Windows":
        try:
            result = subprocess.run(
                ["powercfg", "/q"],
                capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            output_lines = result.stdout.splitlines()
            current_subgroup = ""
            for line in output_lines:
                if "Subgroup" in line:
                    current_subgroup = line.split(":")[-1].strip()
                elif "Current AC Power Setting Index:" in line:
                    try:
                        seconds = int(line.split(":")[-1].strip(), 16)
                        minutes = seconds // 60
                        policy["minutes"] = minutes
                        policy["ok"] = minutes <= 10
                        break
                    except ValueError:
                        pass
            if policy["minutes"] is None:
                print("Could not precisely parse Windows sleep policy from powercfg /q. Returning None.")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking Windows sleep policy: {e}")
    elif system == "Darwin":  # macOS
        try:
            result = subprocess.run(
                ["pmset", "-g", "live"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                if "sleep" in line and "displaysleep" not in line:
                    parts = line.strip().split()
                    if len(parts) > 1 and parts[0] == "sleep":
                        try:
                            minutes = int(parts[1])
                            policy["minutes"] = minutes
                            policy["ok"] = minutes <= 10
                            break
                        except ValueError:
                            pass
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking macOS sleep policy: {e}")
    elif system == "Linux":
        try:
            result = subprocess.run(
                ["gsettings", "get", "org.gnome.desktop.session", "idle-delay"],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0:
                delay_seconds = int(result.stdout.strip())
                if delay_seconds > 0:
                    minutes = delay_seconds // 60
                    policy["minutes"] = minutes
                    policy["ok"] = minutes <= 10
                else:
                    policy["minutes"] = 0
                    policy["ok"] = False
            else:
                print("gsettings not found or idle-delay not set. Trying xset for Xorg.")
                result = subprocess.run(
                    ["xset", "-q"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if "timeout:" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    timeout_seconds = int(parts[1])
                                    minutes = timeout_seconds // 60
                                    policy["minutes"] = minutes
                                    policy["ok"] = minutes <= 10
                                    break
                                except ValueError:
                                    pass
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error checking Linux sleep policy: {e}")
    
    return policy


def collect_snapshot() -> dict:
    """
    Collects a snapshot of system utility information.
    Returns a dictionary with machine ID, timestamp, disk encryption status,
    OS update status, antivirus status, and sleep policy.
    """
    snapshot = {
        "machine_id": get_machine_id(),
        "timestamp": datetime.now().isoformat(),
        "disk_encryption": disk_encryption_status(),
        "os_updates_pending": os_update_status(),
        "antivirus": antivirus_status(),
        "sleep_policy": sleep_policy()
    }
    return snapshot

def send_if_changed(snapshot: dict):
    """
    Compares the current snapshot hash with the last saved hash.
    If different, sends the snapshot to the API and updates state.json.
    """
    state_file_path = os.path.join(os.path.dirname(__file__), "state.json")
    last_snapshot_hash = None

    # Load last snapshot hash
    if os.path.exists(state_file_path):
        try:
            with open(state_file_path, "r") as f:
                state = json.load(f)
                last_snapshot_hash = state.get("last_snapshot_hash")
        except json.JSONDecodeError:
            print("Warning: state.json is corrupted or empty. Starting fresh.")
            pass

    # Compute hash of current snapshot
    current_snapshot_str = json.dumps(snapshot, sort_keys=True, indent=2)
    current_snapshot_hash = hashlib.sha256(current_snapshot_str.encode('utf-8')).hexdigest()

    if current_snapshot_hash != last_snapshot_hash:
        print("Snapshot changed. Sending to API...")
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(API_URL, headers=headers, json=snapshot)
            response.raise_for_status()  # Raise an exception for HTTP errors
            print(f"Snapshot successfully sent to API. Status Code: {response.status_code}")

            # On success, update state.json with new hash
            with open(state_file_path, "w") as f:
                json.dump({"last_snapshot_hash": current_snapshot_hash}, f, indent=2)
            print("state.json updated with new snapshot hash.")
        except requests.exceptions.RequestException as e:
            print(f"Error sending snapshot to API: {e}")
    else:
        print("Snapshot unchanged. Not sending to API.")


def main():
    parser = argparse.ArgumentParser(description="SysUtility - System monitoring and reporting daemon.")
    parser.add_argument("--once", action="store_true", help="Collect and print snapshot once without sending to API.")
    args = parser.parse_args()

    if args.once:
        print("--- Collecting Snapshot (Once Mode) ---")
        snapshot = collect_snapshot()
        print(json.dumps(snapshot, indent=2))
        return

    print(f"SysUtility daemon started. Polling every {POLL_INTERVAL_MINUTES} minutes.")
    try:
        while True:
            snapshot = collect_snapshot()
            send_if_changed(snapshot)
            print(f"Next poll in {POLL_INTERVAL_MINUTES} minutes...")
            time.sleep(POLL_INTERVAL_MINUTES * 60)
    except KeyboardInterrupt:
        print("\nSysUtility daemon stopped by user (KeyboardInterrupt). Exiting gracefully.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
