# SysUtility

A minimal Python project for system monitoring and reporting.

## Project Structure

- `sysutility.py`: Main script for collecting system information and sending it to an API.
- `state.json`: Optional cache for storing the hash of the last sent snapshot.
- `config.py`: Configuration file for API URL, token, and polling interval.
- `README.md`: This file.

## Requirements

- Python 3.10+
- `requests`
- `psutil`
- `platform`

## Setup

1. **Clone the repository:**
   ```bash
   git clone <repository_url>
   cd sysutility
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install requests psutil
   ```

4. **Configure `config.py`:**
   Open `config.py` and update `API_URL` and `API_TOKEN` with your actual values.
   Adjust `POLL_INTERVAL_MINUTES` if needed (must be between 15 and 60 minutes).

## Usage

The `sysutility.py` script can be run in two modes:

1.  **Run Once (collect and print snapshot without sending):**
    ```bash
    python sysutility.py --once
    ```

2.  **Run as Daemon (collect and send snapshots at intervals):**
    ```bash
    python sysutility.py
    ```
    The script will collect system information and send it to the configured API at regular intervals.

## Configuration

Open `config.py` to set the following:

-   `API_URL`: The endpoint where system snapshots will be sent (e.g., `https://example.com/api/v1/ingest`).
-   `API_TOKEN`: The authorization token for API requests.
-   `POLL_INTERVAL_MINUTES`: The interval (in minutes) between snapshot collections and send attempts. Must be between 15 and 60.

## Checks Performed

The utility collects the following system information:

-   **Disk Encryption Status:** Checks if the primary disk is encrypted (e.g., BitLocker on Windows, FileVault on macOS, LUKS on Linux).
-   **OS Update Status:** Determines if there are pending operating system updates.
-   **Antivirus Status:** Detects the presence and health of common antivirus software.
-   **Sleep Policy:** Reports the system's idle-delay/sleep timeout settings.
