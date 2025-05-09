# autork/engine.py
import logging
from .datamodels import Host, Port, Service, OSMatch # Ensure all are imported
from .nmap_handler import NmapHandler
from typing import List, Optional, Any, Dict # Added Any, Dict
import json
from dataclasses import asdict, is_dataclass
import csv

logger = logging.getLogger(__name__)

class ARKEngine:
    def __init__(self, nmap_path: Optional[str] = None):
        try:
            self.nmap_handler = NmapHandler(nmap_path=nmap_path)
            logger.info(f"ARKEngine initialized. Nmap handler configured to use: {self.nmap_handler.nmap_path}")
        except FileNotFoundError as e:
            logger.error(f"ARKEngine Initialization Error: {e}", exc_info=True)
            raise e

    def discover_live_hosts(self, target_scope: str) -> List[Host]:
        logger.info(f"ARKEngine: Discovering live hosts in {target_scope}...")
        discovered_hosts: List[Host] = self.nmap_handler.run_ping_scan(target_scope)
        if discovered_hosts:
            logger.info(f"ARKEngine: Found {len(discovered_hosts)} live host(s).")
        else:
            logger.info(f"ARKEngine: No live hosts found up in {target_scope} by ping scan.")
        return discovered_hosts

    def scan_host_deep(
        self, host_obj: Host, top_ports: int = 100,
        include_os_detection: bool = False,
        nse_scripts: Optional[str] = None,
        nse_script_args: Optional[str] = None
        ) -> Host:
        logger.info(f"ARKEngine: Performing TCP deep scan on {host_obj.ip} "
                    f"(top {top_ports} ports, OS={include_os_detection}, "
                    f"Scripts='{nse_scripts or 'None'}', ScriptArgs='{nse_script_args or 'None'}')...")
        scan_data = self.nmap_handler.run_port_scan_with_services(
            host_obj.ip, top_ports=top_ports, include_os_detection=include_os_detection,
            nse_scripts=nse_scripts, nse_script_args=nse_script_args
        )
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'tcp']
        host_obj.ports.extend(scan_data.get("ports", []))
        host_obj.os_matches = scan_data.get("os_matches", [])
        host_obj.mac_address = scan_data.get("mac_address", host_obj.mac_address)
        host_obj.vendor = scan_data.get("vendor", host_obj.vendor)
        host_obj.uptime_seconds = scan_data.get("uptime_seconds", host_obj.uptime_seconds)
        host_obj.last_boot = scan_data.get("last_boot", host_obj.last_boot)
        host_obj.distance = scan_data.get("distance", host_obj.distance)
        host_obj.host_scripts = scan_data.get("host_scripts", {})
        open_ports_count = sum(1 for p in scan_data.get("ports", []) if p.status == 'open')
        logger.info(f"ARKEngine: TCP deep scan for {host_obj.ip} complete. Found {open_ports_count} open TCP port(s).")
        if host_obj.os_matches: logger.info(f"ARKEngine: OS detection found {len(host_obj.os_matches)} match(es).")
        elif include_os_detection: logger.info(f"ARKEngine: No OS matches found or scan ineffective.")
        if host_obj.host_scripts: logger.info(f"ARKEngine: Found {len(host_obj.host_scripts)} host script results.")
        return host_obj

    def scan_host_udp(self, host_obj: Host, top_ports: int = 100, include_version: bool = True):
        logger.info(f"ARKEngine: Performing UDP scan on {host_obj.ip} (top {top_ports} ports, version={include_version})...")
        udp_ports: List[Port] = self.nmap_handler.run_udp_scan(
            host_obj.ip, top_ports=top_ports, include_version=include_version
        )
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'udp']
        host_obj.ports.extend(udp_ports)
        newly_found_count = len(udp_ports)
        open_or_filtered_count = sum(1 for p in udp_ports if 'open' in p.status)
        logger.info(f"ARKEngine: UDP scan for {host_obj.ip} complete. Found {newly_found_count} UDP ports in result ({open_or_filtered_count} open or open|filtered).")

    def perform_basic_recon(
        self, target_scope: str, top_ports: int = 100,
        include_os_detection: bool = False,
        nse_scripts: Optional[str] = None,
        nse_script_args: Optional[str] = None,
        include_udp_scan: bool = False, top_udp_ports: int = 50
        ) -> List[Host]:
        logger.info(f"ARKEngine: Starting full reconnaissance for target: {target_scope} "
                    f"(TCP ports={top_ports}, OS={include_os_detection}, "
                    f"Scripts='{nse_scripts or 'None'}', ScriptArgs='{nse_script_args or 'None'}', "
                    f"UDP={include_udp_scan}, UDP ports={top_udp_ports if include_udp_scan else 'N/A'})")
        live_hosts: List[Host] = self.discover_live_hosts(target_scope)
        if not live_hosts:
            logger.info(f"ARKEngine: No live hosts to perform scans on for {target_scope}.")
            return []
        for host_obj in live_hosts:
            logger.info(f"\n--- Processing host: {host_obj.ip} ({host_obj.hostname or 'N/A'}) ---")
            self.scan_host_deep(
                host_obj, top_ports=top_ports, include_os_detection=include_os_detection,
                nse_scripts=nse_scripts, nse_script_args=nse_script_args
            )
            if include_udp_scan:
                self.scan_host_udp(host_obj, top_ports=top_udp_ports, include_version=True)
        logger.info(f"\n[*] ARKEngine: Full reconnaissance complete for {target_scope}.")
        return live_hosts

    # --- NEW EXPORT METHODS ---
    def _dataclass_to_dict_converter(self, obj: Any) -> Any:
        """
        Helper function to recursively convert dataclasses to dictionaries.
        """
        if isinstance(obj, list):
            return [self._dataclass_to_dict_converter(item) for item in obj]
        elif is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        elif isinstance(obj, dict):
             return {k: self._dataclass_to_dict_converter(v) for k, v in obj.items()}
        return obj

    def export_to_json(self, scan_results: List[Host], filename: str):
        """ Exports the list of Host scan results to a JSON file. """
        logger.info(f"Exporting {len(scan_results)} host(s) to JSON file: {filename}")
        try:
            results_as_dicts = [self._dataclass_to_dict_converter(host) for host in scan_results]
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results_as_dicts, f, indent=4)
            logger.info(f"Successfully exported results to {filename}")
        except IOError as e:
            logger.error(f"IOError exporting results to JSON file {filename}: {e}", exc_info=True)
        except TypeError as e:
            logger.error(f"TypeError during JSON serialization for {filename}: {e}. Check data structures.", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred during JSON export to {filename}: {e}", exc_info=True)

    def export_to_csv(self, scan_results: List[Host], filename: str):
        """ Exports key information from scan results to a CSV file. """
        logger.info(f"Exporting results to CSV file: {filename}")
        headers = [
            "Host IP", "Hostname", "Host Status",
            "Port Number", "Port Protocol", "Port Status",
            "Service Name", "Service Product", "Service Version", "Service ExtraInfo",
            "Port Scripts", "OS Guesses", "MAC Address", "MAC Vendor", "Host Scripts"
        ]
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
                for host in scan_results:
                    host_info = {
                        "Host IP": host.ip, "Hostname": host.hostname or "", "Host Status": host.status,
                        "OS Guesses": "; ".join([f"{om.name} ({om.accuracy}%)" for om in host.os_matches]) if host.os_matches else "",
                        "MAC Address": host.mac_address or "", "MAC Vendor": host.vendor or "",
                        "Host Scripts": "; ".join([f"{sid}: {out[:50]}{'...' if len(out)>50 else ''}" for sid, out in (host.host_scripts or {}).items()])
                    }
                    if host.ports:
                        open_or_filtered_ports = [p for p in host.ports if 'open' in p.status]
                        if open_or_filtered_ports:
                            for port in open_or_filtered_ports:
                                port_info = {
                                    "Port Number": port.number, "Port Protocol": port.protocol, "Port Status": port.status,
                                    "Service Name": port.service.name if port.service else "",
                                    "Service Product": port.service.product if port.service else "",
                                    "Service Version": port.service.version if port.service else "",
                                    "Service ExtraInfo": port.service.extrainfo if port.service else "",
                                    "Port Scripts": "; ".join([f"{sid}: {out[:50]}{'...' if len(out)>50 else ''}" for sid, out in (port.scripts or {}).items()])
                                }
                                writer.writerow({**host_info, **port_info})
                        else: # Host up, but no open/open|filtered ports
                            empty_port_info = {h: "" for h in headers if h.startswith("Port ") or h.startswith("Service ")}
                            writer.writerow({**host_info, **empty_port_info})
                    else: # Host up, no port info at all
                        empty_port_info = {h: "" for h in headers if h.startswith("Port ") or h.startswith("Service ")}
                        writer.writerow({**host_info, **empty_port_info})
            logger.info(f"Successfully exported results to {filename}")
        except IOError as e:
            logger.error(f"IOError exporting results to CSV file {filename}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred during CSV export to {filename}: {e}", exc_info=True)