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
            raise e

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

    def scan_host_deep(self, host_obj: Host, top_ports: int = 100, include_os_detection: bool = False, run_default_scripts: bool = False) -> Host:
        """
        Performs TCP scan: ports, services, optionally OS and default NSE scripts.
        Updates the Host object with results.
        """
        logger.info(f"ARKEngine: Performing TCP deep scan on {host_obj.ip} (top {top_ports} ports, OS={include_os_detection}, Scripts={run_default_scripts})...")

        scan_data = self.nmap_handler.run_port_scan_with_services(
            host_obj.ip,
            top_ports=top_ports,
            include_os_detection=include_os_detection,
            run_default_scripts=run_default_scripts # Pass flag
        )

        # Update host object
        # Remove old TCP results before adding new ones
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'tcp']
        host_obj.ports.extend(scan_data.get("ports", [])) # Add new TCP+Script results

        # Update host-level details (these might overwrite if multiple scans provide them)
        host_obj.os_matches = scan_data.get("os_matches", [])
        host_obj.mac_address = scan_data.get("mac_address", host_obj.mac_address) # Keep old if new is None
        host_obj.vendor = scan_data.get("vendor", host_obj.vendor)
        host_obj.uptime_seconds = scan_data.get("uptime_seconds", host_obj.uptime_seconds)
        host_obj.last_boot = scan_data.get("last_boot", host_obj.last_boot)
        host_obj.distance = scan_data.get("distance", host_obj.distance)
        host_obj.host_scripts = scan_data.get("host_scripts", {}) # Get host scripts

        open_ports_count = sum(1 for p in scan_data.get("ports", []) if p.status == 'open')
        logger.info(f"ARKEngine: TCP deep scan for {host_obj.ip} complete. Found {open_ports_count} open TCP port(s).")
        if host_obj.os_matches: logger.info(f"ARKEngine: OS detection found {len(host_obj.os_matches)} match(es).")
        elif include_os_detection: logger.info(f"ARKEngine: No OS matches found or scan ineffective.")
        if host_obj.host_scripts: logger.info(f"ARKEngine: Found {len(host_obj.host_scripts)} host script results.")

        return host_obj # Return the updated object


    def scan_host_udp(self, host_obj: Host, top_ports: int = 100, include_version: bool = True):
        """
        Performs a UDP scan on the given Host object and updates its port list.
        """
        logger.info(f"ARKEngine: Performing UDP scan on {host_obj.ip} (top {top_ports} ports, version={include_version})...")

        udp_ports: List[Port] = self.nmap_handler.run_udp_scan(
            host_obj.ip,
            top_ports=top_ports,
            include_version=include_version
        )

        # Remove previous UDP results before adding new ones
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'udp']
        host_obj.ports.extend(udp_ports)

        newly_found_count = len(udp_ports)
        open_or_filtered_count = sum(1 for p in udp_ports if 'open' in p.status)

        logger.info(f"ARKEngine: UDP scan for {host_obj.ip} complete. Found {newly_found_count} UDP ports in result ({open_or_filtered_count} open or open|filtered).")


    def perform_basic_recon(
        self, target_scope: str, top_ports: int = 100,
        include_os_detection: bool = False,
        run_default_scripts: bool = False, # Added flag
        include_udp_scan: bool = False, top_udp_ports: int = 50
        ) -> List[Host]:
        """
        Performs a configurable reconnaissance workflow including optional NSE scripts.
        """
        logger.info(f"ARKEngine: Starting full reconnaissance for target: {target_scope} "
                    f"(TCP ports={top_ports}, OS={include_os_detection}, Scripts={run_default_scripts}, "
                    f"UDP={include_udp_scan}, UDP ports={top_udp_ports if include_udp_scan else 'N/A'})")

        live_hosts: List[Host] = self.discover_live_hosts(target_scope)

        if not live_hosts:
            logger.info(f"ARKEngine: No live hosts to perform scans on for {target_scope}.")
            return []

        # Process each host found up
        for host_obj in live_hosts:
            logger.info(f"\n--- Processing host: {host_obj.ip} ({host_obj.hostname or 'N/A'}) ---")
            # Perform TCP, optional OS, and optional Script scan
            self.scan_host_deep(
                host_obj, # Pass the object to be updated
                top_ports=top_ports,
                include_os_detection=include_os_detection,
                run_default_scripts=run_default_scripts # Pass flag
            )
            # Perform optional UDP scan
            if include_udp_scan:
                self.scan_host_udp(
                    host_obj, # Pass the object to be updated
                    top_ports=top_udp_ports,
                    include_version=True # Assuming version detect for UDP
                )

        logger.info(f"\n[*] ARKEngine: Full reconnaissance complete for {target_scope}.")
        return live_hosts # Returns the list of updated Host objects