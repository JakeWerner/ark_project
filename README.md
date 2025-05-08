# AutomatedReconKit (ARK)

ARK (`autork`) is a Python library designed to simplify and automate common network reconnaissance tasks for penetration testers and security professionals. It provides a unified, Pythonic interface to Nmap, parsing its output into structured Python objects for easy programmatic use.

## Features

* **Host Discovery:** Identifies live hosts within specified targets (CIDR, hostname, IP) using Nmap's ping scan (`-sn`).
* **TCP Port Scanning:** Scans for open TCP ports using various specifications (Top N ports, all ports).
* **Service & Version Detection:** Identifies services and their versions running on open ports (`-sV`).
* **Operating System (OS) Detection:** Attempts to identify the target OS (`-O`). **(Requires root/administrator privileges)**.
* **Host Details:** Retrieves MAC Address, Vendor (from MAC), estimated Uptime, and network Distance when available from Nmap scans.
* **Structured Output:** Returns results as easy-to-use Python dataclasses (`Host`, `Port`, `Service`, `OSMatch`).
* **Flexible Nmap Path:** Automatically finds Nmap in PATH, or uses `ARK_NMAP_PATH` environment variable, or accepts an explicit path during initialization.

## Requirements

* Python 3.8+
* **Nmap:** Must be installed on your system. ARK needs to be able to execute the `nmap` command. Download and install from [https://nmap.org](https://nmap.org). Ensure it's added to your system's PATH or configure ARK to find it (see Configuration section below).

## Installation

Currently, `autork` is not packaged on PyPI. To install it:

1.  **Install Nmap:** If you haven't already, download and install Nmap from [https://nmap.org](https://nmap.org). Make sure the `nmap` command is accessible from your terminal (added to PATH).

2.  **Clone the ARK repository:**
    ```bash
    # !!! Replace with your actual repository URL !!!
    git clone https://github.com/yourusername/autork.git
    cd autork
    ```

3.  **(Recommended) Create and activate a virtual environment:**
    ```bash
    # Create a virtual environment named 'venv'
    python -m venv venv

    # Activate it:
    # Windows PowerShell: .\venv\Scripts\Activate.ps1
    # Windows CMD: .\venv\Scripts\activate.bat
    # Linux/macOS: source venv/bin/activate
    ```

4.  **Install Dependencies:** `autork` currently only relies on the Python standard library. If dependencies are added later, they would be installed here (e.g., `pip install -r requirements.txt`).

## Basic Usage

Here's a simple example of how to use ARK to scan a target:

```python
import logging
from autork.engine import ARKEngine
# from autork.datamodels import Host, Port, Service, OSMatch # Import if needed for type checking

# --- Basic Logging Configuration ---
# Configure logging to see messages from ARK
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG for more verbosity
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# ------------------------------------

def run_scan():
    logging.info("--- Starting ARKEngine Scan ---")

    # Instantiate the engine
    # If Nmap isn't in PATH, provide the path:
    # engine = ARKEngine(nmap_path="/path/to/nmap")
    # Or set the ARK_NMAP_PATH environment variable
    try:
        engine = ARKEngine()
    except FileNotFoundError as e:
        logging.error(f"Failed to initialize ARKEngine: {e}")
        return

    target = "scanme.nmap.org" # Nmap's safe test target
    # target = "192.168.1.0/24" # Example local network (use targets you own!)

    logging.info(f"Starting basic recon on {target}...")

    # --- Run Reconnaissance ---
    # Set include_os_detection=True to attempt OS detection (requires privileges)
    attempt_os_scan = True # Set to False if you don't have/want root/admin rights

    if attempt_os_scan:
         logging.warning("OS Detection is ENABLED - this requires root/admin privileges!")

    results = engine.perform_basic_recon(
        target,
        top_ports=100, # Scan top 100 ports
        include_os_detection=attempt_os_scan
    )

    # --- Process Results ---
    if results:
        print("\n\n--- ARKEngine Reconnaissance Summary ---") # Using print for final user output
        for host in results:
            print(f"\nHost: {host.ip} (Hostname: {host.hostname or 'N/A'}, Status: {host.status})")
            if host.mac_address:
                print(f"  MAC Address: {host.mac_address} (Vendor: {host.vendor or 'N/A'})")
            if host.uptime_seconds is not None:
                 uptime_h = host.uptime_seconds // 3600
                 uptime_m = (host.uptime_seconds % 3600) // 60
                 print(f"  Uptime: ~{uptime_h}h {uptime_m}m ({host.uptime_seconds}s) (Last boot: {host.last_boot or 'N/A'})")
            if host.distance is not None:
                print(f"  Distance: {host.distance} hop(s)")

            if host.os_matches:
                print("  OS Detection:")
                for os_match in host.os_matches:
                    print(f"    - {os_match.name} (Accuracy: {os_match.accuracy}%)")
            elif attempt_os_scan: # Only mention if OS detection was attempted
                print("  OS Detection: No specific OS match found or scan ineffective.")

            print("  Open Ports:")
            open_ports = [p for p in host.ports if p.status == 'open']
            if open_ports:
                for port in open_ports:
                    service_info = "N/A"
                    if port.service:
                        s = port.service
                        service_info = (
                            f"Name: {s.name or 'N/A'}, "
                            f"Product: {s.product or 'N/A'}, "
                            f"Version: {s.version or 'N/A'} "
                            f"({s.extrainfo or ''})"
                        )
                    print(f"    [+] Open Port: {port.number}/{port.protocol} - {service_info}")
            else:
                print("    No open ports found (or reported by this scan).")
    else:
        print(f"\n[-] No hosts with details were returned by ARKEngine for {target}.")

if __name__ == '__main__':
    run_scan() # Assuming this example code is saved as a runnable script
```

## Privileges

Note that certain Nmap scan functionalities invoked by ARK require elevated privileges to run correctly:
OS Detection (include_os_detection=True): Nmap's -O flag needs to send raw packets and requires root (on Linux/macOS) or Administrator (on Windows) privileges. If you enable this feature, ensure you run your Python script with the necessary elevation (e.g., using sudo python your_script.py on Linux/macOS or running from an Administrator terminal on Windows).
Other scan types you might add later (like SYN scans -sS) also require these privileges.
ARK will log warnings when features requiring elevation are requested, but execution might fail if sufficient privileges are not available.


## Running Tests

ARK uses pytest for unit testing. The tests mock Nmap's execution, so Nmap doesn't need to be installed to run the tests themselves (though it is required for the library to function).

Install test dependencies:
```bash
pip install pytest pytest-mock
```

Navigate to the project root directory (the one containing the autork folder and the tests folder).
Run pytest:

```bash
python -m pytest
```

Or for more detailed output:
```bash
python -m pytest -v
```

All tests should pass if the setup is correct.


## Configuration

Nmap Path
ARK needs to know where your Nmap executable is. It searches in this order:

1) An explicit path passed to the ARKEngine(nmap_path="/path/to/nmap") constructor.
2) The path specified in the ARK_NMAP_PATH environment variable.
3) The default command nmap (assuming it's in your system's PATH).

If Nmap cannot be found, ARKEngine will raise a FileNotFoundError during initialization.