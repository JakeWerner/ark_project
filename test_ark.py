# ark_project/test_ark.py
import logging
from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch # For context
from typing import List

# --- Basic Logging Configuration ---
logging.basicConfig(
    level=logging.INFO, # DEBUG for more details
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# ------------------------------------

def run_scan():
    logging.info("--- Starting ARKEngine Scan ---")
    try:
        engine = ARKEngine()
    except FileNotFoundError as e:
        logging.error(f"Failed to initialize ARKEngine: {e}")
        return

    test_target_scope = "scanme.nmap.org"

    # --- Configure Scan Options ---
    should_include_os = True
    should_include_udp = True # Set to False for quicker testing if needed
    scripts_to_run = "default" # Example: "default", "vuln", "http-title,ssh-hostkey", None
    script_arguments = None # Example: "http.useragent='MyARKScanner/1.0'"

    logging.info(f"Starting reconnaissance with ARKEngine on: {test_target_scope}")
    if should_include_os: logging.warning("OS Detection is ENABLED - requires root/admin!")
    if should_include_udp: logging.warning("UDP Scan is ENABLED - requires root/admin & can be slow!")
    if scripts_to_run: logging.info(f"NSE Script Scan ('{scripts_to_run}') is ENABLED.")
    if script_arguments: logging.info(f"NSE Script Arguments: {script_arguments}")

    recon_results: List[Host] = engine.perform_basic_recon(
        test_target_scope,
        top_ports=20, # Keep low for testing speed
        include_os_detection=should_include_os,
        nse_scripts=scripts_to_run,
        nse_script_args=script_arguments,
        include_udp_scan=should_include_udp,
        top_udp_ports=10 # Scan fewer UDP ports for faster test
    )

    # --- Process and Print Results ---
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
                ports_found = False
                sorted_ports = sorted(host_obj.ports, key=lambda p: (p.protocol, p.number)) # Sort by proto then num
                for port_obj in sorted_ports:
                    if 'open' in port_obj.status:
                        ports_found = True; service_info = "N/A"
                        if port_obj.service:
                            s = port_obj.service
                            service_info = (f"Name: {s.name or 'N/A'}, Prod: {s.product or 'N/A'}, "
                                            f"Ver: {s.version or 'N/A'} ({s.extrainfo or ''})")
                        print(f"    [+] {port_obj.protocol.upper()} Port: {port_obj.number:<5} ({port_obj.status:<15}) - {service_info}")
                        if port_obj.scripts:
                             print(f"        Scripts:"); [print(f"          - {sid}: {out.strip()[:100]}{'...' if len(out.strip()) > 100 else ''}") for sid, out in port_obj.scripts.items()]
                if not ports_found: print("    No open or open|filtered ports found (or reported by this scan).")
            else: print("  No port information scanned/retrieved for this host.")

        # --- NEW: Export results ---
        if recon_results: # Only export if we have something
            json_filename = "ark_scan_results.json"
            csv_filename = "ark_scan_results.csv"
            print(f"\nExporting results to {json_filename} and {csv_filename}...")
            engine.export_to_json(recon_results, json_filename)
            engine.export_to_csv(recon_results, csv_filename)
            print("Exports complete.")
        # --- End Export ---
    else:
        print(f"\n[-] No hosts with details were returned by ARKEngine for {test_target_scope}.")

if __name__ == '__main__':
    run_scan()