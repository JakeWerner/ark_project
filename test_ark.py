# ark_project/test_ark.py
import logging
import os
import json # For checking loaded JSON content (optional)
from typing import List, Optional

# Assuming 'autork' is installed (e.g., pip install -e .)
# or autork directory is in PYTHONPATH or sibling to this script's location
from autork.engine import ARKEngine
from autork.datamodels import Host # For type hinting, not strictly needed for basic run

# --- Basic Logging Configuration ---
# Configure logging to see messages from ARK and this script
logging.basicConfig(
    level=logging.INFO,  # Change to logging.DEBUG for maximum verbosity from ARK
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# ------------------------------------

# --- Helper functions for creating dummy files for testing ---
def create_dummy_file(filename="dummy_targets.txt", content="scanme.nmap.org\n"):
    """Creates a dummy file with specified content."""
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write(content)
        logging.info(f"Created dummy file: {filename} with content: '{content.strip()}'")
        return filename
    except IOError as e:
        logging.error(f"Could not create dummy file {filename}: {e}")
        return None

def cleanup_dummy_files(filenames: List[Optional[str]]):
    """Removes a list of dummy files if they exist."""
    for filename in filenames:
        if filename and os.path.exists(filename):
            try:
                os.remove(filename)
                logging.info(f"Cleaned up dummy file: {filename}")
            except OSError as e:
                logging.error(f"Error removing dummy file {filename}: {e}")
# --- End Helper Functions ---

def run_ark_scan_example():
    """
    Demonstrates the capabilities of the ARKEngine.
    """
    logging.info("--- Initializing ARKEngine for Comprehensive Scan Example ---")
    try:
        # If Nmap is not in PATH, or you want to specify a version:
        # engine = ARKEngine(nmap_path="/usr/local/bin/nmap") # Example path
        # Or set ARK_NMAP_PATH environment variable
        engine = ARKEngine()
    except FileNotFoundError as e:
        logging.error(f"CRITICAL: Failed to initialize ARKEngine: {e}. Ensure Nmap is installed and accessible.")
        return
    except Exception as e:
        logging.error(f"CRITICAL: An unexpected error occurred during ARKEngine initialization: {e}", exc_info=True)
        return

    # --- User-configurable Scan Parameters ---
    # 1. Target Specification (Choose one method)
    use_target_file = True # Set to False to use target_scope_direct
    target_scope_direct: Optional[str] = "scanme.nmap.org" # Used if use_target_file is False
    target_file_content = "scanme.nmap.org\n45.33.49.119\n# Example of a comment\n# [2001:db8::dead:beef] # Example IPv6 target"
    
    use_ipv6 = False # <<< Set to True for IPv6 scanning
    if use_ipv6:
        # Override targets for a known IPv6 host if testing IPv6 specifically
        target_scope_direct = "ipv6.google.com" # Or scanme.nmap.org's IPv6: "2600:3c01::f03c:91ff:fe18:bb2f"
        target_file_content = "ipv6.google.com\n[2001:db8::cafe]\n" # Ensure file has IPv6 targets
        logging.info("IPv6 scanning mode enabled for targets.")

    # 2. Exclusion Options
    exclude_targets_str: Optional[str] = None # Example: "192.168.1.5, 192.168.1.100-120"
    exclude_file_content: Optional[str] = None # Example: "unscannable.example.com\n10.0.0.0/24"

    # 3. Scan Types and Options
    tcp_scan_type_flag: Optional[str] = "S"  # "S" (SYN), "T" (Connect), "A" (ACK), "F" (FIN), "X" (Xmas), "N" (Null), or None for Nmap default with -sV
    include_os_detection_flag: bool = True
    include_udp_scan_flag: bool = False # UDP scans are slow; enable cautiously for demos
    run_nse_scripts: Optional[str] = "default,vulners" # e.g., "default", "vuln", "http-title,smb-enum-*", None
    nse_script_arguments: Optional[str] = "vulners.mincvss=7.0" # e.g., "http.useragent='MyARKScanner/1.0'", None

    # 4. Performance and Timing
    timing_template_val: Optional[int] = 4 # T0 (slowest) to T5 (fastest); None for handler default (T4)
    tcp_top_ports_val: int = 20         # Number of top TCP ports to scan (0 for all 65535)
    udp_top_ports_val: int = 10         # Number of top UDP ports (if UDP scan enabled)
    # --- End User-configurable Parameters ---

    # Prepare target files if needed
    current_target_file: Optional[str] = None
    current_exclude_file: Optional[str] = None

    if use_target_file:
        current_target_file = create_dummy_file("ark_targets.txt", target_file_content)
        effective_target_scope = None
    else:
        effective_target_scope = target_scope_direct
    
    if exclude_file_content:
        current_exclude_file = create_dummy_file("ark_excludes.txt", exclude_file_content)

    # Log chosen options
    logging.info(f"--- Scan Configuration ---")
    logging.info(f"Target Source: {'File (' + str(current_target_file) + ')' if current_target_file else 'Direct (' + str(effective_target_scope) + ')'}")
    logging.info(f"IPv6 Mode: {use_ipv6}")
    if exclude_targets_str: logging.info(f"Exclude String: {exclude_targets_str}")
    if current_exclude_file: logging.info(f"Exclude File: {current_exclude_file}")
    logging.info(f"TCP Scan Type: -s{tcp_scan_type_flag.upper() if tcp_scan_type_flag else 'Default'}")
    logging.info(f"OS Detection: {include_os_detection_flag}")
    logging.info(f"UDP Scan: {include_udp_scan_flag} (Top {udp_top_ports_val} ports)")
    logging.info(f"NSE Scripts: '{run_nse_scripts or 'None'}'")
    if nse_script_arguments: logging.info(f"NSE Script Args: '{nse_script_arguments}'")
    logging.info(f"Timing Template: T{timing_template_val if timing_template_val is not None else 'Default'}")
    logging.info(f"TCP Top Ports: {tcp_top_ports_val if tcp_top_ports_val > 0 else 'All (1-65535)'}")
    logging.info("--------------------------")

    # Privilege warnings
    if include_os_detection_flag: logging.warning("OS Detection ENABLED - may require root/admin privileges!")
    if include_udp_scan_flag: logging.warning("UDP Scan ENABLED - requires root/admin and can be very slow!")
    if tcp_scan_type_flag and tcp_scan_type_flag.upper() not in ["T", ""]: logging.warning(f"TCP Scan Type -s{tcp_scan_type_flag.upper()} ENABLED - likely requires root/admin!")
    if run_nse_scripts and "vuln" in run_nse_scripts: logging.warning("NSE 'vuln' scripts can be intrusive.")


    # Perform the reconnaissance
    try:
        scan_results: List[Host] = engine.perform_basic_recon(
            target_scope=effective_target_scope,
            input_target_file=current_target_file,
            exclude_targets=exclude_targets_str,
            exclude_file=current_exclude_file,
            top_ports=tcp_top_ports_val,
            include_os_detection=include_os_detection_flag,
            nse_scripts=run_nse_scripts,
            nse_script_args=nse_script_arguments,
            include_udp_scan=include_udp_scan_flag,
            top_udp_ports=udp_top_ports_val,
            timing_template=timing_template_val,
            tcp_scan_type=tcp_scan_type_flag,
            ipv6=use_ipv6
        )
    except Exception as e:
        logging.error(f"An error occurred during perform_basic_recon: {e}", exc_info=True)
        cleanup_dummy_files([current_target_file, current_exclude_file])
        return

    # --- Process and Print Results ---
    if scan_results:
        print("\n\n" + "="*20 + " ARKEngine Reconnaissance Summary " + "="*20)
        for host_obj in scan_results:
            print(f"\nHost: {host_obj.ip} (Hostname: {host_obj.hostname or 'N/A'}, Status: {host_obj.status})")
            if host_obj.mac_address: print(f"  MAC Address: {host_obj.mac_address} (Vendor: {host_obj.vendor or 'N/A'})")
            if host_obj.distance is not None: print(f"  Distance: {host_obj.distance} hop(s)")
            if host_obj.uptime_seconds is not None:
                 uptime_h = host_obj.uptime_seconds // 3600; uptime_m = (host_obj.uptime_seconds % 3600) // 60
                 print(f"  Uptime: ~{uptime_h}h {uptime_m}m ({host_obj.uptime_seconds}s) (Last boot: {host_obj.last_boot or 'N/A'})")

            if host_obj.os_matches:
                print("  OS Detection:")
                for os_match in host_obj.os_matches: print(f"    - {os_match.name} (Accuracy: {os_match.accuracy}%)")
            elif include_os_detection_flag: print("  OS Detection: No specific OS match found or scan ineffective.")

            if host_obj.host_scripts:
                 print("  Host Scripts:")
                 for script_id, output in host_obj.host_scripts.items():
                      print(f"    - {script_id}: {output.strip()[:150]}{'...' if len(output.strip()) > 150 else ''}")

            print("  Ports (TCP & UDP):")
            if host_obj.ports:
                ports_found_for_display = False
                sorted_ports = sorted(host_obj.ports, key=lambda p: (p.protocol, p.number))
                for port_obj in sorted_ports:
                    if 'open' in port_obj.status or 'filtered' in port_obj.status: # Show open or potentially open
                        ports_found_for_display = True
                        service_info = "N/A"
                        if port_obj.service:
                            s = port_obj.service
                            service_info = (f"Name: {s.name or 'N/A'}, Prod: {s.product or 'N/A'}, "
                                            f"Ver: {s.version or 'N/A'} ({s.extrainfo or ''})")
                        print(f"    [+] {port_obj.protocol.upper()} Port: {port_obj.number:<5} ({port_obj.status:<15}) - {service_info}")
                        
                        if port_obj.scripts:
                             print(f"        Scripts:")
                             for script_id, output in port_obj.scripts.items():
                                 print(f"          - {script_id}: {output.strip()[:100]}{'...' if len(output.strip()) > 100 else ''}")
                if not ports_found_for_display:
                    print("    No open or open|filtered ports found for this host.")
            else:
                print("  No port information scanned/retrieved for this host.")
        print("="*60)

        # --- Export, Save, and Load Results ---
        if scan_results:
            json_export_file = "ark_scan_export.json"
            csv_export_file = "ark_scan_export.csv"
            session_save_file = "ark_scan_session.json"

            logging.info(f"Exporting results to {json_export_file} and {csv_export_file}...")
            engine.export_to_json(scan_results, json_export_file)
            engine.export_to_csv(scan_results, csv_export_file)
            
            logging.info(f"Saving scan session to {session_save_file}...")
            engine.save_scan_results(scan_results, session_save_file)

            logging.info(f"Attempting to load scan session from {session_save_file}...")
            loaded_results = engine.load_scan_results(session_save_file)
            if loaded_results:
                logging.info(f"Successfully loaded {len(loaded_results)} hosts from session file.")
                # Basic check: compare number of hosts and IP of the first host
                if len(loaded_results) == len(scan_results) and loaded_results[0].ip == scan_results[0].ip:
                    logging.info("Loaded data appears consistent with original (basic check).")
                else:
                    logging.warning("Loaded data differs from original or failed basic consistency check.")
            else:
                logging.error("Failed to load scan session or session file was empty.")
            
            # Optional: cleanup export/session files after demonstration
            # cleanup_dummy_files([json_export_file, csv_export_file, session_save_file]) 
    else:
        logging.info(f"\n[-] No hosts with details were returned by ARKEngine for the specified targets.")

    # Clean up dummy target/exclude files created by this script
    cleanup_dummy_files([current_target_file, current_exclude_file])
    logging.info("--- ARKEngine Scan Example Complete ---")

if __name__ == '__main__':
    run_ark_scan_example()