# ark_project/test_ark.py
import logging
from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
from typing import List

# --- Basic Logging Configuration ---
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG for more verbosity
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# ------------------------------------

def run_scan():
    logging.info("--- Starting ARKEngine Scan ---")

    try:
        engine = ARKEngine() # Assumes Nmap in PATH or env var set
    except FileNotFoundError as e:
        logging.error(f"Failed to initialize ARKEngine: {e}")
        return

    test_target_scope = "scanme.nmap.org" # Nmap's safe test target

    # --- Configure Scan Options ---
    should_include_os = True
    should_include_udp = True
    should_run_scripts = True # <<< Enable script scanning
    tcp_ports_to_scan = 20 # Keep low for testing speed
    udp_ports_to_scan = 20 # Keep low for testing speed
    # -----------------------------

    logging.info(f"Starting reconnaissance with ARKEngine on: {test_target_scope}")
    if should_include_os: logging.warning("OS Detection is ENABLED - requires root/admin!")
    if should_include_udp: logging.warning("UDP Scan is ENABLED - requires root/admin & can be slow!")
    if should_run_scripts: logging.info("Default NSE Script Scan (-sC) is ENABLED.")

    recon_results: List[Host] = engine.perform_basic_recon(
        test_target_scope,
        top_ports=tcp_ports_to_scan,
        include_os_detection=should_include_os,
        run_default_scripts=should_run_scripts, # <<< Pass flag
        include_udp_scan=should_include_udp,
        top_udp_ports=udp_ports_to_scan
    )

    # --- Process Results ---
    if recon_results:
        print("\n\n--- ARKEngine Reconnaissance Summary ---")
        for host_obj in recon_results:
            print(f"\nHost: {host_obj.ip} (Hostname: {host_obj.hostname or 'N/A'}, Status: {host_obj.status})")
            if host_obj.mac_address: print(f"  MAC Address: {host_obj.mac_address} (Vendor: {host_obj.vendor or 'N/A'})")
            if host_obj.uptime_seconds is not None:
                 uptime_h = host_obj.uptime_seconds // 3600
                 uptime_m = (host_obj.uptime_seconds % 3600) // 60
                 print(f"  Uptime: ~{uptime_h}h {uptime_m}m ({host_obj.uptime_seconds}s) (Last boot: {host_obj.last_boot or 'N/A'})")
            if host_obj.distance is not None: print(f"  Distance: {host_obj.distance} hop(s)")

            if host_obj.os_matches:
                print("  OS Detection:")
                for os_match in host_obj.os_matches: print(f"    - {os_match.name} (Accuracy: {os_match.accuracy}%)")
            elif should_include_os: print("  OS Detection: No specific OS match found or scan ineffective.")

            # --- Print Host Script Results ---
            if host_obj.host_scripts:
                 print("  Host Scripts:")
                 for script_id, output in host_obj.host_scripts.items():
                      # Simple print; can get long. Limit output length if needed.
                      print(f"    - {script_id}: {output.strip()[:200]}{'...' if len(output.strip()) > 200 else ''}")

            print("  Ports (TCP & UDP):")
            if host_obj.ports:
                ports_found = False
                sorted_ports = sorted(host_obj.ports, key=lambda p: (p.number, p.protocol))
                for port_obj in sorted_ports:
                    if 'open' in port_obj.status: # Show open or open|filtered
                        ports_found = True
                        service_info = "N/A"
                        if port_obj.service:
                            s = port_obj.service
                            service_info = (f"Name: {s.name or 'N/A'}, Prod: {s.product or 'N/A'}, "
                                            f"Ver: {s.version or 'N/A'} ({s.extrainfo or ''})")
                        print(f"    [+] {port_obj.protocol.upper()} Port: {port_obj.number:<5} ({port_obj.status:<15}) - {service_info}")

                        # --- Print Port Script Results ---
                        if port_obj.scripts:
                             print(f"        Scripts:")
                             for script_id, output in port_obj.scripts.items():
                                 # Simple print; limit length if output is very long
                                 print(f"          - {script_id}: {output.strip()[:150]}{'...' if len(output.strip()) > 150 else ''}")
                if not ports_found:
                    print("    No open or open|filtered ports found (or reported by this scan).")
            else:
                print("  No port information scanned/retrieved for this host.")
    else:
        print(f"\n[-] No hosts with details were returned by ARKEngine for {test_target_scope}.")

if __name__ == '__main__':
    run_scan()