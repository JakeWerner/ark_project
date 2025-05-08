# autork/engine.py
import logging
from .datamodels import Host, Port, Service, OSMatch
from .nmap_handler import NmapHandler
from typing import List, Optional

# Get a logger for this module
logger = logging.getLogger(__name__)

class ARKEngine:
    def __init__(self, nmap_path: Optional[str] = None):
        """
        Initializes the AutomatedReconKit Engine.
        :param nmap_path: Optional explicit path to Nmap executable.
                          If None, NmapHandler will search environment variables
                          and system PATH.
        """
        try:
            self.nmap_handler = NmapHandler(nmap_path=nmap_path)
            logger.info(f"ARKEngine initialized. Nmap handler configured to use: {self.nmap_handler.nmap_path}")
        except FileNotFoundError as e:
            logger.error(f"ARKEngine Initialization Error: {e}", exc_info=True)
            raise e # Re-raise after logging

    def discover_live_hosts(self, target_scope: str) -> List[Host]:
        """
        Discovers live hosts within the given target scope (e.g., CIDR).
        Returns a list of Host objects.
        """
        logger.info(f"ARKEngine: Discovering live hosts in {target_scope}...")
        discovered_hosts: List[Host] = self.nmap_handler.run_ping_scan(target_scope)
        if discovered_hosts:
            logger.info(f"ARKEngine: Found {len(discovered_hosts)} live host(s).")
        else:
            logger.info(f"ARKEngine: No live hosts found up in {target_scope} by ping scan.")
        return discovered_hosts

    def scan_host_deep(self, host_obj: Host, top_ports: int = 100, include_os_detection: bool = False) -> Host:
        """
        Performs a TCP port scan, service detection, and optionally OS detection
        on a given Host object, updating it with the results.
        """
        logger.info(f"ARKEngine: Performing TCP deep scan on {host_obj.ip} (top {top_ports} ports, OS Detect: {include_os_detection})...")

        scan_data = self.nmap_handler.run_port_scan_with_services(
            host_obj.ip,
            top_ports=top_ports,
            include_os_detection=include_os_detection
        )

        # Update host object with TCP scan results
        # Ensure we don't overwrite ports from other scan types (like UDP)
        # A simple approach is to filter existing ports list first
        existing_tcp_ports = {(p.number, p.protocol) for p in host_obj.ports if p.protocol == 'tcp'}
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'tcp'] # Remove old TCP results

        new_tcp_ports = scan_data.get("ports", [])
        host_obj.ports.extend(new_tcp_ports) # Add new TCP results

        # Update other host details (OS, MAC, etc. are generally host-wide)
        host_obj.os_matches = scan_data.get("os_matches", [])
        host_obj.mac_address = scan_data.get("mac_address") # Might be overwritten by UDP scan if run later? Nmap usually gets MAC once.
        host_obj.vendor = scan_data.get("vendor")
        host_obj.uptime_seconds = scan_data.get("uptime_seconds")
        host_obj.last_boot = scan_data.get("last_boot")
        host_obj.distance = scan_data.get("distance")

        open_ports_count = sum(1 for p in new_tcp_ports if p.status == 'open')
        logger.info(f"ARKEngine: TCP deep scan for {host_obj.ip} complete. Found {open_ports_count} open TCP port(s).")
        if host_obj.os_matches:
            logger.info(f"ARKEngine: OS detection for {host_obj.ip} found {len(host_obj.os_matches)} match(es).")
        elif include_os_detection:
            logger.info(f"ARKEngine: No OS matches found for {host_obj.ip} or OS scan not effective.")

        return host_obj # Return the updated object

    # --- NEW METHOD for UDP ---
    def scan_host_udp(self, host_obj: Host, top_ports: int = 100, include_version: bool = True):
        """
        Performs a UDP scan on the given Host object and updates its port list.

        Note: This typically requires root/administrator privileges and can be slow.
        Results for UDP often include 'open|filtered' states. Appends results
        to the host_obj.ports list.

        :param host_obj: The Host object to scan (must have IP).
        :type host_obj: Host
        :param top_ports: Scan the top N most common UDP ports. Defaults to 100.
        :type top_ports: int
        :param include_version: Attempt service/version detection on UDP ports (`-sV`). Defaults to True.
        :type include_version: bool
        """
        logger.info(f"ARKEngine: Performing UDP scan on {host_obj.ip} (top {top_ports} ports, version={include_version})...")

        udp_ports: List[Port] = self.nmap_handler.run_udp_scan(
            host_obj.ip,
            top_ports=top_ports,
            include_version=include_version
        )

        # Append or merge UDP ports with existing port list
        # Remove previous UDP results for this host first to avoid duplicates if re-scanned
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'udp']
        host_obj.ports.extend(udp_ports) # Add new UDP results

        newly_found_count = len(udp_ports)
        open_or_filtered_count = sum(1 for p in udp_ports if 'open' in p.status) # Count open or open|filtered

        logger.info(f"ARKEngine: UDP scan for {host_obj.ip} complete. Found {newly_found_count} UDP ports in result ({open_or_filtered_count} open or open|filtered).")
        # This method modifies host_obj directly.


    def perform_basic_recon(self, target_scope: str, top_ports: int = 100, include_os_detection: bool = False, include_udp_scan: bool = False, top_udp_ports: int = 50) -> List[Host]: # Added UDP flags
        """
        Performs a configurable reconnaissance workflow.

        :param target_scope: Target specification string.
        :param top_ports: Number of top TCP ports to scan.
        :param include_os_detection: Attempt OS detection (requires root/admin).
        :param include_udp_scan: Perform a UDP scan after TCP scan (requires root/admin, can be slow).
        :param top_udp_ports: Number of top UDP ports to scan if include_udp_scan is True.
        :return: List of Host objects with gathered details.
        """
        logger.info(f"ARKEngine: Starting full reconnaissance for target: {target_scope} (TCP ports={top_ports}, OS={include_os_detection}, UDP={include_udp_scan}, UDP ports={top_udp_ports if include_udp_scan else 'N/A'})")
        live_hosts: List[Host] = self.discover_live_hosts(target_scope)

        if not live_hosts:
            logger.info(f"ARKEngine: No live hosts to perform scans on for {target_scope}.")
            return []

        for host_obj in live_hosts:
            logger.info(f"\n--- Processing host: {host_obj.ip} ({host_obj.hostname or 'N/A'}) ---")
            # Perform TCP and optional OS scan
            self.scan_host_deep(host_obj, top_ports=top_ports, include_os_detection=include_os_detection)

            # Perform optional UDP scan
            if include_udp_scan:
                self.scan_host_udp(host_obj, top_ports=top_udp_ports, include_version=True) # Assuming version detect for UDP

        logger.info(f"\n[*] ARKEngine: Full reconnaissance complete for {target_scope}.")
        return live_hosts # Returns the list of updated Host objects