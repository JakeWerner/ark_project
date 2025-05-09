# ark_project/test_ark.py
import logging
from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch # For type context if needed
from typing import List

# --- Basic Logging Configuration ---
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG for more detailed messages from ARK
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# ------------------------------------

def run_scan():
    logging.info("--- Starting ARKEngine Scan ---")
    try:
        engine = ARKEngine() # Assumes Nmap in PATH or ARK_NMAP_PATH is set
    except FileNotFoundError as e:
        logging.error(f"Failed to initialize ARKEngine: {e}. Ensure Nmap is installed and accessible.")
        return

    test_target_scope = "scanme.nmap.org" # Nmap's safe test target

    # --- Configure Scan Options ---
    should_include_os = True
    should_include_udp = True # Set to False for quicker testing if preferred
    scripts_to_run = "default" # e.g., "default", "vuln", "http-title,ssh-hostkey", or None
    script_arguments = None    # e.g., "http.useragent='MyCustomARKScanner/1.0'"
    scan_timing = 4 # Nmap timing template T0-T5, None for handler default (T4)
    
    tcp_ports_to_scan = 20 # Scan fewer ports for a quicker example run
    udp_ports_to_scan = 10 # Scan even fewer UDP ports

    logging.info(f"Starting reconnaissance with ARKEngine on: {test_target_scope}")
    if should_include_os: logging.warning("OS Detection is ENABLED - this requires root/admin privileges!")
    if should_include_udp: logging.warning("UDP Scan is ENABLED - this requires root/admin privileges and can be slow!")
    if scripts_to_run: logging.info(f"NSE Script Scan ('{scripts_to_run}') is ENABLED.")
    if script_arguments: logging.info(f"NSE Script Arguments: {script_arguments}")
    logging.info(f"Nmap Timing Template: T{scan_timing if scan_timing is not None else 'Default (Handler T4)'}")


    recon_results: List[Host] = engine.perform_basic_recon(
        test_target_scope,
        top_ports=tcp_ports_to_scan,
        include_os_detection=should_include_os,
        nse_scripts=scripts_to_run,
        nse_script_args=script_arguments,
        include_udp_scan=should_include_udp,
        top_udp_ports=udp_ports_to_scan,
        timing_template=scan_timing
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
                print("  OS Detection:")
                for os_match in host_obj.os_matches: print(f"    - {os_match.name} (Accuracy: {os_match.accuracy}%)")
            elif should_include_os: print("  OS Detection: No specific OS match found or scan ineffective.")

            if host_obj.host_scripts:
                 print("  Host Scripts:")
                 for script_id, output in host_obj.host_scripts.items():
                      print(f"    - {script_id}: {output.strip()[:100]}{'...' if len(output.strip()) > 100 else ''}")

            print("  Ports (TCP & UDP):")
            if host_obj.ports:
                ports_found_for_display = False
                # Sort ports for consistent display
                sorted_ports = sorted(host_obj.ports, key=lambda p: (p.protocol, p.number))
                for port_obj in sorted_ports:
                    # Display open or open|filtered ports
                    if 'open' in port_obj.status or 'filtered' in port_obj.status:
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
                    print("    No open or open|filtered ports found (or reported by this scan).")
            else:
                print("  No port information scanned/retrieved for this host.")

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