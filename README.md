# AutomatedReconKit (ARK) - `autork`

**AutomatedReconKit (ARK)** is a Python library designed to streamline and automate common network reconnaissance tasks. It provides a powerful yet easy-to-use Pythonic interface to the Nmap network scanner, parsing its XML output into structured Python objects for straightforward programmatic access and further analysis.

ARK allows for flexible control over various Nmap scan parameters, including host discovery, TCP and UDP port scanning, service and version detection, OS detection, Nmap Scripting Engine (NSE) execution with custom scripts and arguments, timing templates, selectable TCP scan types, IPv6 scanning, and detailed reason reporting for port states. Results can be easily exported to JSON/CSV or saved and loaded for session persistence.

## Core Features

* **Versatile Target Specification:**
    * Scan single IPs, hostnames, or CIDR ranges.
    * Read targets from a file (`-iL` equivalent).
    * Exclude specified targets or targets from a file (`--exclude`, `--excludefile` for discovery).
* **Comprehensive Host Discovery:**
    * Ping scans (`-sn`) with configurable Nmap timing templates.
    * (Future: Support for specific Nmap ping types like TCP SYN/ACK, UDP, ICMP pings).
* **Detailed Port Scanning:**
    * **TCP Scans:** Service & version detection (`-sV`), selectable scan techniques (`-sS` SYN, `-sT` Connect, `-sF` FIN, `-sX` Xmas, `-sN` Null, `-sA` ACK).
    * **UDP Scans:** Service & version detection (`-sU -sV`).
    * Flexible port specification (top N ports, full range, specific ports via Nmap syntax).
* **Operating System (OS) Detection:** Uses Nmap's `-O` flag.
* **Nmap Scripting Engine (NSE) Integration:**
    * Run custom scripts, categories (e.g., "default", "vuln"), or all scripts.
    * Pass arguments to NSE scripts (`--script-args`).
* **Rich Data Extraction:**
    * Host status, IP addresses (IPv4 & IPv6), hostnames.
    * Port details: number, protocol, state, service name, product, version, extrainfo.
    * Detailed reasons for port states (if Nmap's `--reason` flag is enabled).
    * OS match details (name, accuracy).
    * MAC address and vendor (for local network scans).
    * Host uptime, last boot time, and network distance (when available).
    * Raw output from host-level and port-level NSE scripts.
* **Scan Control:**
    * Nmap timing templates (`-T0` to `-T5`).
    * IPv6 scanning support (`-6`).
* **Structured Output:** Results are parsed into clean Python dataclasses (`Host`, `Port`, `Service`, `OSMatch`).
* **Data Handling:**
    * Export scan results to JSON and CSV formats.
    * Save and load complete scan sessions (list of `Host` objects) to/from JSON files.
* **Usability:**
    * Informative logging using Python's `logging` module.
    * Flexible Nmap executable path configuration (explicit, environment variable `ARK_NMAP_PATH`, or system PATH).

## Requirements

* Python 3.8+
* **Nmap:** Must be installed on your system and accessible via the system's PATH, or the path to the Nmap executable must be configured (see Configuration section). Download Nmap from [https://nmap.org](https://nmap.org).

## Installation

Currently, `autork` is best installed directly from the source for development or local use.

1.  **Install Nmap:**
    If you haven't already, download and install Nmap from [https://nmap.org/download.html](https://nmap.org/download.html). Ensure the `nmap` command is executable and in your system's PATH.

2.  **Use pip to install autork:**
    ```bash
    pip install autork
    ```

3.  **(Recommended) Create and activate a Python virtual environment:**
    ```bash
    python -m venv venv
    # On Windows PowerShell:
    # .\venv\Scripts\Activate.ps1
    # On Windows CMD:
    # .\venv\Scripts\activate.bat
    # On Linux/macOS:
    # source venv/bin/activate
    ```

4.  **Install `autork` in editable mode (for development):**
    This command also installs dependencies needed for testing.
    ```bash
    pip install -e .[test] 
    ```
    If you only want to install `autork` without test dependencies (once it's more formally packaged for use as a library and has runtime dependencies listed in `pyproject.toml`):
    ```bash
    # pip install . 
    ```
    (Currently, `autork` has no external runtime dependencies beyond Python's standard library).

## Basic Usage Example

Here's an example demonstrating several features of `autork`:

```python
import logging
import os
from typing import List, Optional

# Assuming 'autork' is installed (e.g., pip install -e .)
from autork.engine import ARKEngine
from autork.datamodels import Host # For type hinting if you inspect results deeply

# --- Basic Logging Configuration ---
# Configure logging to see messages from ARK and this script
logging.basicConfig(
    level=logging.INFO,  # Change to logging.DEBUG for more verbosity from ARK
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# ------------------------------------

# Helper to create dummy files for example
def create_dummy_file(filename="dummy_file.txt", content="scanme.nmap.org\n"):
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write(content)
        logging.info(f"Created dummy file: {filename}")
        return filename
    except IOError as e:
        logging.error(f"Could not create dummy file {filename}: {e}")
        return None

def cleanup_files(filenames: List[Optional[str]]):
    for filename in filenames:
        if filename and os.path.exists(filename):
            try:
                os.remove(filename)
                logging.info(f"Cleaned up: {filename}")
            except OSError as e:
                logging.error(f"Error removing {filename}: {e}")

def main():
    logging.info("--- ARKEngine Comprehensive Demo ---")
    
    # --- Configuration ---
    # If Nmap isn't in PATH, provide the path:
    # engine = ARKEngine(nmap_path="/path/to/nmap_executable")
    # Or set the ARK_NMAP_PATH environment variable.
    try:
        engine = ARKEngine()
    except FileNotFoundError as e:
        logging.error(f"CRITICAL - Nmap not found: {e}")
        return
    
    # --- Target Setup ---
    # Option 1: Direct target scope
    # target_scope_val: Optional[str] = "scanme.nmap.org"
    # input_file_val: Optional[str] = None

    # Option 2: From file (Nmap's -iL equivalent)
    target_scope_val = None 
    input_file_val = create_dummy_file(
        "ark_example_targets.txt", 
        "scanme.nmap.org\n45.33.49.119\n# example.com # Nmap will try to resolve this"
    )
    if not input_file_val: # Fallback if file creation fails
        target_scope_val = "scanme.nmap.org"
        logging.warning("Target file creation failed, using direct target scope.")

    # Exclusions
    exclude_targets_val: Optional[str] = None # "192.168.1.100" 
    exclude_file_val: Optional[str] = None # create_dummy_file("ark_example_excludes.txt", "192.168.1.254")

    # --- Scan Options ---
    use_ipv6_val: bool = False # Set to True to scan IPv6 address of scanme.nmap.org
    if use_ipv6_val:
        target_scope_val = "2600:3c01::f03c:91ff:fe18:bb2f" # scanme.nmap.org's IPv6
        input_file_val = None # For simplicity in this IPv6 example, use direct scope
        logging.info("IPv6 mode enabled. Target set to scanme.nmap.org's IPv6 address.")

    tcp_scan_type_val: Optional[str] = "S"  # SYN Scan (requires root/admin usually)
    timing_template_val: Optional[int] = 4   # T4 (Aggressive)
    include_os_val: bool = True
    include_reason_val: bool = True
    nse_scripts_val: Optional[str] = "default,vulners" # Run default scripts and vulners
    nse_script_args_val: Optional[str] = "vulners.mincvss=7.0" # Argument for vulners script
    include_udp_val: bool = False # Set to True to include UDP scan (can be slow)
    top_tcp_ports_val: int = 50
    top_udp_ports_val: int = 20

    # --- Log selected options ---
    if tcp_scan_type_val and tcp_scan_type_val.upper() not in ["T", ""]:
        logging.warning(f"TCP Scan Type -s{tcp_scan_type_val.upper()} selected, may require root/admin.")
    if include_os_val or include_udp_val or (tcp_scan_type_val and tcp_scan_type_val.upper() != "T"):
        logging.warning("Selected options may require root/administrator privileges to run correctly.")

    # --- Perform Reconnaissance ---
    logging.info(f"Starting reconnaissance...")
    try:
        results: List[Host] = engine.perform_basic_recon(
            target_scope=target_scope_val,
            input_target_file=input_file_val,
            exclude_targets=exclude_targets_val,
            exclude_file=exclude_file_val,
            top_ports=top_tcp_ports_val,
            include_os_detection=include_os_val,
            nse_scripts=nse_scripts_val,
            nse_script_args=nse_script_args_val,
            include_udp_scan=include_udp_val,
            top_udp_ports=top_udp_ports_val,
            timing_template=timing_template_val,
            tcp_scan_type=tcp_scan_type_val,
            ipv6=use_ipv6_val,
            include_reason=include_reason_val
        )
    except Exception as e:
        logging.error(f"An error occurred during perform_basic_recon: {e}", exc_info=True)
        cleanup_files([input_file_val, exclude_file_val])
        return

    # --- Process and Display Results ---
    if results:
        print("\n\n" + "="*30 + " ARK Reconnaissance Summary " + "="*30)
        for host_obj in results:
            print(f"\nHost: {host_obj.ip} (Hostname: {host_obj.hostname or 'N/A'}, Status: {host_obj.status})")
            if host_obj.mac_address: print(f"  MAC Address: {host_obj.mac_address} (Vendor: {host_obj.vendor or 'N/A'})")
            if host_obj.distance is not None: print(f"  Distance: {host_obj.distance} hop(s)")
            if host_obj.uptime_seconds is not None:
                 uptime_h = host_obj.uptime_seconds // 3600; uptime_m = (host_obj.uptime_seconds % 3600) // 60
                 print(f"  Uptime: ~{uptime_h}h {uptime_m}m ({host_obj.uptime_seconds}s) (Last boot: {host_obj.last_boot or 'N/A'})")

            if host_obj.os_matches:
                print("  OS Detection:")
                for os_match in host_obj.os_matches: print(f"    - {os_match.name} (Accuracy: {os_match.accuracy}%)")
            elif include_os_val: print("  OS Detection: No specific OS match found or scan ineffective.")

            if host_obj.host_scripts:
                 print("  Host Scripts:")
                 for script_id, output in host_obj.host_scripts.items():
                      print(f"    - {script_id}: {output.strip()[:150]}{'...' if len(output.strip()) > 150 else ''}")

            print("  Ports (TCP & UDP):")
            if host_obj.ports:
                ports_found_for_display = False
                sorted_ports = sorted(host_obj.ports, key=lambda p: (p.protocol, p.number))
                for port_obj in sorted_ports:
                    if 'open' in port_obj.status or 'filtered' in port_obj.status:
                        ports_found_for_display = True
                        service_info = "N/A"
                        if port_obj.service:
                            s = port_obj.service
                            service_info = (f"Name: {s.name or 'N/A'}, Prod: {s.product or 'N/A'}, "
                                            f"Ver: {s.version or 'N/A'} ({s.extrainfo or ''})")
                        reason_info = f" (Reason: {port_obj.reason})" if port_obj.reason and include_reason_val else ""
                        print(f"    [+] {port_obj.protocol.upper()} Port: {port_obj.number:<5} ({port_obj.status:<15}){reason_info} - {service_info}")
                        
                        if port_obj.scripts:
                             print(f"        Scripts:")
                             for script_id, output in port_obj.scripts.items():
                                 print(f"          - {script_id}: {output.strip()[:100]}{'...' if len(output.strip()) > 100 else ''}")
                if not ports_found_for_display:
                    print("    No open or open|filtered ports found for this host.")
            else:
                print("  No port information scanned/retrieved for this host.")
        print("="*70)

        # --- Export, Save, and Load ---
        if results: # Only if we have results
            json_export_file = "ark_scan_export.json"
            csv_export_file = "ark_scan_export.csv"
            session_save_file = "ark_scan_session.json"

            logging.info(f"Exporting results to {json_export_file} and {csv_export_file}...")
            engine.export_to_json(results, json_export_file)
            engine.export_to_csv(results, csv_export_file)
            
            logging.info(f"Saving scan session to {session_save_file}...")
            engine.save_scan_results(results, session_save_file)

            logging.info(f"Attempting to load scan session from {session_save_file}...")
            loaded_results = engine.load_scan_results(session_save_file)
            if loaded_results:
                logging.info(f"Successfully loaded {len(loaded_results)} hosts from session file.")
                # Basic check
                if len(loaded_results) == len(results) and loaded_results[0].ip == results[0].ip:
                    logging.info("Loaded data basic check passed.")
                else:
                    logging.warning("Loaded data differs from original or failed basic consistency check.")
            else:
                logging.error("Failed to load scan session or session file was empty.")
            
            # Consider cleaning up export/session files after demonstration if desired
            # cleanup_files([json_export_file, csv_export_file, session_save_file])
    else:
        logging.info(f"\n[-] No hosts with details were returned by ARKEngine for the specified targets.")

    # Clean up dummy target/exclude files created by this script
    cleanup_files([input_file_val, current_exclude_file])
    logging.info("--- ARKEngine Scan Example Complete ---")

if __name__ == '__main__':
    run_scan_example()
```


## Key Features Showcased in this test_ark.py:

* Configuration: Demonstrates how ARKEngine is initialized (with a note on nmap_path).
* Logging: Includes basic logging setup to see output from both autork and the script itself.
* Target Management: Shows how to use target_scope OR input_target_file, and placeholders for exclude_targets/exclude_file. Includes helper functions to create dummy files for these.
* IPv6 Scanning: Has a use_ipv6 flag and changes the target to an IPv6 address if enabled.
* Comprehensive Scan Options: Sets parameters for TCP scan type, timing, OS detection, NSE scripts and arguments, and UDP scanning.
* Privilege Warnings: Logs warnings based on selected options.
* Error Handling: Basic try-except around ARKEngine instantiation and perform_basic_recon.
* Detailed Results Processing: Loops through hosts and ports, printing many of the details autork can extract, including script outputs and port reasons.
* Export & Save/Load: Demonstrates calling export_to_json, export_to_csv, save_scan_results, and load_scan_results, with a basic verification of the loaded data.
* Cleanup: Removes dummy files created by the script.

This script should give a very good demonstration of autork's full capabilities. Remember to adjust the scan parameters at the top of run_scan_example() to test different scenarios quickly.