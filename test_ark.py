# ark_project/test_ark.py
import logging
from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
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

    engine = ARKEngine() # Assumes Nmap in PATH or env var set
    test_target_scope = "scanme.nmap.org"

    # --- Configure Scan Options ---
    # Set to True to attempt OS detection (requires root/admin)
    should_include_os = True
    # Set to True to attempt UDP scan (requires root/admin, can be slow)
    should_include_udp = True
    # Number of TCP ports / UDP ports for the test scan
    tcp_ports_to_scan = 20
    udp_ports_to_scan = 20
    # -----------------------------

    logging.info(f"Starting reconnaissance with ARKEngine on: {test_target_scope}")
    if should_include_os:
        logging.warning("OS Detection is ENABLED - requires root/admin privileges!")
    if should_include_udp:
        logging.warning("UDP Scan is ENABLED - requires root/admin privileges and can be slow!")

    recon_results: List[Host] = engine.perform_basic_recon(
        test_target_scope,
        top_ports=tcp_ports_to_scan,
        include_os_detection=should_include_os,
        include_udp_scan=should_include_udp, # Pass flag
        top_udp_ports=udp_ports_to_scan      # Pass UDP ports
    )

    # --- Process Results ---
    if recon_results:
        print("\n\n--- ARKEngine Reconnaissance Summary (Including UDP) ---")
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

            print("  Ports (TCP & UDP):")
            if host_obj.ports:
                ports_found = False
                sorted_ports = sorted(host_obj.ports, key=lambda p: (p.number, p.protocol))
                for port_obj in sorted_ports:
                    # Show open or potentially open (open|filtered) ports
                    if 'open' in port_obj.status:
                        ports_found = True
                        service_info = "N/A"
                        if port_obj.service:
                            s = port_obj.service
                            service_info = (
                                f"Name: {s.name or 'N/A'}, "
                                f"Product: {s.product or 'N/A'}, "
                                f"Version: {s.version or 'N/A'} "
                                f"({s.extrainfo or ''})"
                            )
                        # Clearly label protocol
                        print(f"    [+] {port_obj.protocol.upper()} Port: {port_obj.number} ({port_obj.status}) - {service_info}")
                if not ports_found:
                    print("    No open or open|filtered ports found (or reported by this scan).")
            else:
                print("  No port information scanned/retrieved for this host.")
    else:
        print(f"\n[-] No hosts with details were returned by ARKEngine for {test_target_scope}.")

if __name__ == '__main__':
    run_scan()