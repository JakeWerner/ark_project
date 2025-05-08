# autork/engine.py
import logging # Import logging
from .datamodels import Host, Port, Service, OSMatch
from .nmap_handler import NmapHandler
from typing import List, Optional

# Get a logger for this module
logger = logging.getLogger(__name__)

class ARKEngine:
    def __init__(self, nmap_path: Optional[str] = None):
        try:
            self.nmap_handler = NmapHandler(nmap_path=nmap_path)
            logger.info(f"ARKEngine initialized. Nmap handler configured to use: {self.nmap_handler.nmap_path}")
        except FileNotFoundError as e:
            logger.error(f"ARKEngine Initialization Error: {e}", exc_info=True)
            raise e # Re-raise after logging

    def discover_live_hosts(self, target_scope: str) -> List[Host]:
        logger.info(f"ARKEngine: Discovering live hosts in {target_scope}...")
        discovered_hosts: List[Host] = self.nmap_handler.run_ping_scan(target_scope)
        if discovered_hosts:
            logger.info(f"ARKEngine: Found {len(discovered_hosts)} live host(s).")
        else:
            # This is not necessarily an error, just no hosts found up
            logger.info(f"ARKEngine: No live hosts found up in {target_scope} by ping scan.")
        return discovered_hosts

    def scan_host_deep(self, host_obj: Host, top_ports: int = 100, include_os_detection: bool = False) -> Host:
        logger.info(f"ARKEngine: Performing deep scan on {host_obj.ip} (top {top_ports} ports, OS Detect: {include_os_detection})...")
        scan_data = self.nmap_handler.run_port_scan_with_services(
            host_obj.ip, top_ports=top_ports, include_os_detection=include_os_detection
        )
        # ... (populate host_obj attributes from scan_data) ...
        host_obj.ports = scan_data.get("ports", [])
        host_obj.os_matches = scan_data.get("os_matches", [])
        host_obj.mac_address = scan_data.get("mac_address")
        host_obj.vendor = scan_data.get("vendor")
        host_obj.uptime_seconds = scan_data.get("uptime_seconds")
        host_obj.last_boot = scan_data.get("last_boot")
        host_obj.distance = scan_data.get("distance")

        open_ports_count = sum(1 for p in host_obj.ports if p.status == 'open')
        logger.info(f"ARKEngine: Deep scan for {host_obj.ip} complete. Found {open_ports_count} open port(s).")
        if host_obj.os_matches:
            logger.info(f"ARKEngine: OS detection for {host_obj.ip} found {len(host_obj.os_matches)} match(es).")
        elif include_os_detection:
            logger.info(f"ARKEngine: No OS matches found for {host_obj.ip} or OS scan not effective.")
        return host_obj

    def perform_basic_recon(self, target_scope: str, top_ports: int = 100, include_os_detection: bool = False) -> List[Host]:
        logger.info(f"ARKEngine: Starting full basic reconnaissance for target: {target_scope} (top_ports={top_ports}, os_detect={include_os_detection})")
        live_hosts: List[Host] = self.discover_live_hosts(target_scope)
        if not live_hosts:
            logger.info(f"ARKEngine: No live hosts to perform deep scans on for {target_scope}.")
            return []
        for host_obj in live_hosts:
            logger.debug(f"--- Scanning host: {host_obj.ip} ({host_obj.hostname or 'N/A'}) ---")
            self.scan_host_deep(host_obj, top_ports=top_ports, include_os_detection=include_os_detection)
        logger.info(f"ARKEngine: Full basic reconnaissance complete for {target_scope}.")
        return live_hosts