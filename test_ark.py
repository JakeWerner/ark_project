# ark_project/test_ark.py
import logging
from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch # For type context if needed
from typing import List, Optional
import os # For creating dummy files

# --- Basic Logging Configuration ---
logging.basicConfig(
    level=logging.INFO, # DEBUG for more details
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# ------------------------------------

def create_dummy_target_file(filename="targets.txt", content="scanme.nmap.org\nnmap.org\n"):
    try:
        with open(filename, "w") as f:
            f.write(content)
        logging.info(f"Created dummy target file: {filename}")
        return filename
    except IOError as e:
        logging.error(f"Could not create dummy target file {filename}: {e}")
        return None

def create_dummy_exclude_file(filename="excludes.txt", content="nmap.org\n"): # Exclude one of the targets
    try:
        with open(filename, "w") as f:
            f.write(content)
        logging.info(f"Created dummy exclude file: {filename}")
        return filename
    except IOError as e:
        logging.error(f"Could not create dummy exclude file {filename}: {e}")
        return None

def run_scan():
    logging.info("--- Starting ARKEngine Scan ---")
    try:
        engine = ARKEngine() # Assumes Nmap in PATH or ARK_NMAP_PATH is set
    except FileNotFoundError as e:
        logging.error(f"Failed to initialize ARKEngine: {e}. Ensure Nmap is installed and accessible.")
        return

    # --- Configure Target Options ---
    # Option 1: Direct target scope (set target_file_to_scan to None)
    # target_to_scan: Optional[str] = "scanme.nmap.org"
    # target_file_to_scan: Optional[str] = None

    # Option 2: Target file
    target_to_scan = None # Ignored if target_file_to_scan is used by engine logic
    target_file_to_scan = create_dummy_target_file()
    if not target_file_to_scan:
        logging.error("Proceeding without target file due to creation error.")
        target_to_scan = "scanme.nmap.org" # Fallback
        target_file_to_scan = None


    # Exclusion options
    exclusions_str: Optional[str] = None # "1.1.1.1,192.168.0.0/24"
    exclusions_file_path: Optional[str] = create_dummy_exclude_file()
    # if not exclusions_file_path:
    #    logging.warning("Could not create dummy exclude file.")
    # -----------------------------

    # --- Other Scan Options ---
    should_include_os = True
    should_include_udp = False # Keep UDP off for quicker demo, enable for full test
    scripts_to_run = "default" 
    script_arguments = None
    scan_timing = 4 
    desired_tcp_scan_type: Optional[str] = "S"
    # ---------------------------

    log_target_source = f"file '{target_file_to_scan}'" if target_file_to_scan else f"scope '{target_to_scan}'"
    logging.info(f"Starting reconnaissance with ARKEngine on targets from {log_target_source}")
    if exclusions_str: logging.info(f"Excluding targets string: {exclusions_str}")
    if exclusions_file_path: logging.info(f"Excluding targets from file: {exclusions_file_path}")
    # ... (log other options) ...


    recon_results: List[Host] = engine.perform_basic_recon(
        target_scope=target_to_scan, 
        input_target_file=target_file_to_scan,
        exclude_targets=exclusions_str,
        exclude_file=exclusions_file_path,
        # --- other scan options ---
        top_ports=20,
        include_os_detection=should_include_os,
        nse_scripts=scripts_to_run,
        nse_script_args=script_arguments,
        include_udp_scan=should_include_udp,
        top_udp_ports=10,
        timing_template=scan_timing,
        tcp_scan_type=desired_tcp_scan_type
    )

    # --- Process Results (remains the same) ---
    if recon_results:
        print("\n\n--- ARKEngine Reconnaissance Summary ---")
        for host_obj in recon_results:
            print(f"\nHost: {host_obj.ip} (Hostname: {host_obj.hostname or 'N/A'}, Status: {host_obj.status})")
            if host_obj.mac_address: print(f"  MAC Address: {host_obj.mac_address} (Vendor: {host_obj.vendor or 'N/A'})")
            if host_obj.uptime_seconds is not None:
                 uptime_h = host_obj.uptime_seconds // 3600; uptime_m = (host_obj.uptime_seconds % 3600) // 60
                 print(f"  Uptime: ~{uptime_h}h {uptime_m}m ({host_obj.uptime_seconds}s) (Last boot: {host_obj.last_boot or 'N/A'})")
            if host_obj.distance is not None: print(f"  Distance: {host_obj.distance} hop(s)")
            if host_obj.os_matches:
                print("  OS Detection:"); [print(f"    - {om.name} ({om.accuracy}%)") for om in host_obj.os_matches]
            elif should_include_os: print("  OS Detection: No specific OS match found or scan ineffective.")
            if host_obj.host_scripts:
                 print("  Host Scripts:"); [print(f"    - {sid}: {out.strip()[:100]}{'...' if len(out.strip()) > 100 else ''}") for sid, out in host_obj.host_scripts.items()]
            print("  Ports (TCP & UDP):")
            if host_obj.ports:
                ports_found_for_display = False
                sorted_ports = sorted(host_obj.ports, key=lambda p: (p.protocol, p.number))
                for port_obj in sorted_ports:
                    if 'open' in port_obj.status or 'filtered' in port_obj.status:
                        ports_found_for_display = True; service_info = "N/A"
                        if port_obj.service:
                            s = port_obj.service
                            service_info = (f"Name: {s.name or 'N/A'}, Prod: {s.product or 'N/A'}, "
                                            f"Ver: {s.version or 'N/A'} ({s.extrainfo or ''})")
                        print(f"    [+] {port_obj.protocol.upper()} Port: {port_obj.number:<5} ({port_obj.status:<15}) - {service_info}")
                        if port_obj.scripts:
                             print(f"        Scripts:"); [print(f"          - {sid}: {out.strip()[:100]}{'...' if len(out.strip()) > 100 else ''}") for sid, out in port_obj.scripts.items()]
                if not ports_found_for_display:
                    print("    No open or open|filtered ports found (or reported by this scan).")
            else: print("  No port information scanned/retrieved for this host.")
        if recon_results:
            json_filename = "ark_scan_results.json"; csv_filename = "ark_scan_results.csv"
            print(f"\nExporting results to {json_filename} and {csv_filename}...")
            engine.export_to_json(recon_results, json_filename)
            engine.export_to_csv(recon_results, csv_filename)
            print("Exports complete.")
    else:
        print(f"\n[-] No hosts with details were returned by ARKEngine for targets from {log_target_source}.")

    # Clean up dummy files
    if target_file_to_scan and os.path.exists(target_file_to_scan):
        os.remove(target_file_to_scan)
        logging.info(f"Removed dummy target file: {target_file_to_scan}")
    if exclusions_file_path and os.path.exists(exclusions_file_path):
        os.remove(exclusions_file_path)
        logging.info(f"Removed dummy exclude file: {exclusions_file_path}")

if __name__ == '__main__':
    run_scan()