# autork/engine.py
import logging
from .datamodels import Host, Port, Service, OSMatch
from .nmap_handler import NmapHandler
from typing import List, Optional, Any, Dict, Type
import json
from dataclasses import asdict, is_dataclass, fields
import csv

logger = logging.getLogger(__name__)

class ARKEngine:
    def __init__(self, nmap_path: Optional[str] = None):
        try:
            self.nmap_handler = NmapHandler(nmap_path=nmap_path)
            logger.info(f"ARKEngine initialized. Nmap handler configured to use: {self.nmap_handler.nmap_path}")
        except FileNotFoundError as e:
            logger.error(f"ARKEngine Initialization Error: {e}", exc_info=True)
            raise e # Or handle more gracefully depending on library design

    def discover_live_hosts(
        self,
        target_scope: Optional[str] = None,
        timing_template: Optional[int] = None,
        input_target_file: Optional[str] = None,
        exclude_targets: Optional[str] = None,
        exclude_file: Optional[str] = None,
        ipv6: bool = False
    ) -> List[Host]:
        if not target_scope and not input_target_file:
            logger.error("ARKEngine: Host discovery called without target_scope or input_target_file.")
            return []
        
        default_timing_for_log = self.nmap_handler._get_validated_timing_template_value(None)
        log_target_spec = f"file '{input_target_file}'" if input_target_file else f"scope '{target_scope}'"
        logger.info(f"ARKEngine: Discovering live hosts for targets {log_target_spec} "
                    f"(Timing: T{timing_template if timing_template is not None else default_timing_for_log}"
                    f"{', IPv6' if ipv6 else ''})...")
        if exclude_targets: logger.info(f"ARKEngine: Excluding targets string: {exclude_targets}")
        if exclude_file: logger.info(f"ARKEngine: Excluding targets from file: {exclude_file}")

        discovered_hosts: List[Host] = self.nmap_handler.run_ping_scan(
            target_scope=target_scope,
            timing_template=timing_template,
            input_target_file=input_target_file,
            exclude_targets=exclude_targets,
            exclude_file=exclude_file,
            ipv6=ipv6
        )
        if discovered_hosts:
            logger.info(f"ARKEngine: Found {len(discovered_hosts)} live host(s).")
        else:
            logger.info(f"ARKEngine: No live hosts found up for the specified targets/exclusions by ping scan.")
        return discovered_hosts

    def scan_host_deep(
        self,
        host_obj: Host,
        top_ports: int = 100,
        include_os_detection: bool = False,
        nse_scripts: Optional[str] = None,
        nse_script_args: Optional[str] = None,
        timing_template: Optional[int] = None,
        tcp_scan_type: Optional[str] = None, # Parameter for "S", "T", "A", "F", "X", "N"
        include_reason: bool = False
    ) -> Host:
        """
        Performs a detailed TCP scan on the given Host object, including service detection,
        optional OS detection, NSE scripts (with arguments), selectable TCP scan type,
        timing template, and reason for port states. Updates the Host object with results.

        :param host_obj: The Host object to scan (must have an IP address).
        :type host_obj: Host
        :param top_ports: Scan the top N most common TCP ports. Defaults to 100. Use 0 for all.
        :type top_ports: int
        :param include_os_detection: If True, attempts OS detection (-O). Defaults to False.
        :type include_os_detection: bool
        :param nse_scripts: NSE scripts to run (e.g., "default", "vuln"). Defaults to None.
        :type nse_scripts: Optional[str]
        :param nse_script_args: Arguments for NSE scripts. Defaults to None.
        :type nse_script_args: Optional[str]
        :param timing_template: Nmap timing template (0-5). Defaults to None (handler uses T4).
        :type timing_template: Optional[int]
        :param tcp_scan_type: Specific Nmap TCP scan type (e.g., "S" for SYN, "T" for Connect).
                              Defaults to None (Nmap's default with -sV).
        :type tcp_scan_type: Optional[str]
        :param include_reason: If True, requests Nmap to provide reasons for port states (--reason).
                               Defaults to False.
        :type include_reason: bool
        :return: The updated Host object with scan details.
        :rtype: Host
        """
        is_ipv6_target = ":" in host_obj.ip  # Simple check for IPv6 format
        default_timing_for_log = self.nmap_handler._get_validated_timing_template_value(None)
        
        scan_type_log_msg = "Nmap Default with -sV"
        if tcp_scan_type and isinstance(tcp_scan_type, str):
            type_char_log = tcp_scan_type.strip().upper()
            valid_scan_type_chars_log = ["S", "T", "A", "F", "X", "N"]
            if type_char_log in valid_scan_type_chars_log:
                scan_type_log_msg = f"TCP Scan Type: -s{type_char_log}"
        
        logger.info(
            f"ARKEngine: Performing TCP deep scan on {host_obj.ip}{' (IPv6)' if is_ipv6_target else ''} "
            f"(top {top_ports} ports, OS={include_os_detection}, "
            f"Scripts='{nse_scripts or 'None'}', ScriptArgs='{nse_script_args or 'None'}', "
            f"Timing=T{timing_template if timing_template is not None else default_timing_for_log}, "
            f"{scan_type_log_msg}, Reason={include_reason})..."
        )

        scan_data = self.nmap_handler.run_port_scan_with_services(
            host_ip=host_obj.ip,
            top_ports=top_ports,
            include_os_detection=include_os_detection,
            nse_scripts=nse_scripts,
            nse_script_args=nse_script_args,
            timing_template=timing_template,
            tcp_scan_type=tcp_scan_type,
            ipv6=is_ipv6_target, # Pass determined IPv6 status to handler
            include_reason=include_reason
        )

        # Update host object with new TCP scan results
        # Remove previous TCP port data for this host to avoid duplicates if re-scanned
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'tcp']
        # Add new TCP port results (which include service and script data from the handler)
        host_obj.ports.extend(scan_data.get("ports", []))

        # Update host-level details (these might overwrite if multiple scans provide them,
        # or preserve existing if new scan_data doesn't have the key)
        host_obj.os_matches = scan_data.get("os_matches", host_obj.os_matches or [])
        host_obj.mac_address = scan_data.get("mac_address", host_obj.mac_address)
        host_obj.vendor = scan_data.get("vendor", host_obj.vendor)
        host_obj.uptime_seconds = scan_data.get("uptime_seconds", host_obj.uptime_seconds)
        host_obj.last_boot = scan_data.get("last_boot", host_obj.last_boot)
        host_obj.distance = scan_data.get("distance", host_obj.distance)
        host_obj.host_scripts = scan_data.get("host_scripts", host_obj.host_scripts or {})

        # Log summary of findings for this deep scan
        open_ports_count = sum(1 for p in scan_data.get("ports", []) if p.status == 'open')
        logger.info(
            f"ARKEngine: TCP deep scan for {host_obj.ip} complete. "
            f"Found {open_ports_count} open TCP port(s)."
        )
        if host_obj.os_matches:
            logger.info(f"ARKEngine: OS detection for {host_obj.ip} found {len(host_obj.os_matches)} match(es).")
        elif include_os_detection: # Only log if OS detection was attempted
            logger.info(f"ARKEngine: No OS matches found for {host_obj.ip} or OS scan not effective.")
        
        if host_obj.host_scripts:
            logger.info(f"ARKEngine: Found {len(host_obj.host_scripts)} host script results for {host_obj.ip}.")
        elif nse_scripts: # Only log if scripts were attempted
             logger.info(f"ARKEngine: No host script results found for {host_obj.ip} with specified scripts.")

        return host_obj

    def scan_host_udp(
        self,
        host_obj: Host,
        top_ports: int = 100,
        include_version: bool = True,
        timing_template: Optional[int] = None,
        include_reason: bool = False
    ):
        """
        Performs a UDP scan on the given Host object and updates its port list.

        Note: This typically requires root/administrator privileges and can be very slow.
        Results for UDP often include 'open|filtered' states. Appends results
        to the host_obj.ports list, replacing any previous UDP scan results for this host.

        :param host_obj: The Host object to scan (must have an IP address).
        :type host_obj: Host
        :param top_ports: Scan the top N most common UDP ports. Defaults to 100.
                          Use 0 for Nmap's default UDP port list for -sU -sV (which is often the top 1000).
        :type top_ports: int
        :param include_version: Attempt service/version detection on UDP ports (`-sV`). Defaults to True.
        :type include_version: bool
        :param timing_template: Nmap timing template (0-5). Defaults to None (handler uses T4).
        :type timing_template: Optional[int]
        :param include_reason: If True, requests Nmap to provide reasons for port states. Defaults to False.
        :type include_reason: bool
        """
        is_ipv6_target = ":" in host_obj.ip  # Simple check for IPv6 format
        default_timing_for_log = self.nmap_handler._get_validated_timing_template_value(None) # For logging consistency

        logger.info(
            f"ARKEngine: Performing UDP scan on {host_obj.ip}{' (IPv6)' if is_ipv6_target else ''} "
            f"(top {top_ports} ports, version={include_version}, "
            f"Timing=T{timing_template if timing_template is not None else default_timing_for_log}, "
            f"Reason={include_reason})..."
        )

        udp_ports: List[Port] = self.nmap_handler.run_udp_scan(
            host_ip=host_obj.ip,
            top_ports=top_ports,
            include_version=include_version,
            timing_template=timing_template,
            ipv6=is_ipv6_target, # Pass determined IPv6 status to handler
            include_reason=include_reason
        )

        # Remove previous UDP results for this host first to avoid duplicates if re-scanned
        host_obj.ports = [p for p in host_obj.ports if p.protocol != 'udp']
        # Add new UDP results
        host_obj.ports.extend(udp_ports)

        newly_found_count = len(udp_ports)
        open_or_filtered_count = sum(1 for p in udp_ports if 'open' in p.status or 'filtered' in p.status) # Check for 'open' or 'open|filtered'

        logger.info(
            f"ARKEngine: UDP scan for {host_obj.ip} complete. "
            f"Found {newly_found_count} UDP ports in result "
            f"({open_or_filtered_count} open or open|filtered)."
        )
        # This method modifies host_obj directly; no explicit return is strictly necessary
        # unless a fluent interface or the modified object itself is desired by the caller.

    def perform_basic_recon(
        self,
        target_scope: Optional[str] = None,
        top_ports: int = 100,
        include_os_detection: bool = False,
        nse_scripts: Optional[str] = None,
        nse_script_args: Optional[str] = None,
        include_udp_scan: bool = False,
        top_udp_ports: int = 50,
        timing_template: Optional[int] = None,
        tcp_scan_type: Optional[str] = None,
        input_target_file: Optional[str] = None,
        exclude_targets: Optional[str] = None,
        exclude_file: Optional[str] = None,
        ipv6: bool = False,
        include_reason: bool = False # <<< Includes the latest addition
    ) -> List[Host]:
        """
        Performs a configurable reconnaissance workflow.

        Steps include:
        1. Host discovery (ping scan) with target file/exclusion support.
        2. For each live host:
           a. Detailed TCP scan (ports, services, versions, optional OS, NSE scripts/args, reasons).
           b. Optional UDP scan (ports, services, versions, reasons).

        All scan phases respect the provided timing template and IPv6 mode where applicable.

        :param target_scope: Direct target string (e.g., "192.168.1.0/24", "host.com").
                             Used if input_target_file is None.
        :param top_ports: Number of top TCP ports to scan. Defaults to 100.
        :param include_os_detection: If True, attempts OS detection. Defaults to False.
        :param nse_scripts: NSE scripts to run (e.g., "default", "vuln", "http-title"). Defaults to None.
        :param nse_script_args: Arguments for NSE scripts. Defaults to None.
        :param include_udp_scan: If True, performs a UDP scan. Defaults to False.
        :param top_udp_ports: Number of top UDP ports if UDP scan is enabled. Defaults to 50.
        :param timing_template: Nmap timing template (0-5). Defaults to None (handler uses T4).
        :param tcp_scan_type: Specific Nmap TCP scan type (e.g., "S", "T", "F"). Defaults to None.
        :param input_target_file: Path to a file containing targets. Takes precedence over target_scope if provided.
        :param exclude_targets: Comma-separated string of hosts/networks to exclude.
        :param exclude_file: Path to a file containing hosts/networks to exclude.
        :param ipv6: If True, enables IPv6 scanning mode for discovery and subsequent scans. Defaults to False.
        :param include_reason: If True, requests Nmap to provide reasons for port/host states. Defaults to False.
        :return: A list of Host objects, updated with discovered information.
        """
        if not target_scope and not input_target_file:
            logger.error("ARKEngine: perform_basic_recon called without target_scope or input_target_file.")
            return []

        # For logging, determine the effective timing and TCP scan type if None is passed
        # (as the handler will apply defaults)
        effective_timing_log = f"T{timing_template if timing_template is not None else self.nmap_handler._get_validated_timing_template_value(None)}"
        
        effective_tcp_scan_type_log = "Nmap Default with -sV"
        if tcp_scan_type and isinstance(tcp_scan_type, str):
            type_char_log = tcp_scan_type.strip().upper()
            valid_scan_type_chars_log = ["S", "T", "A", "F", "X", "N"]
            if type_char_log in valid_scan_type_chars_log:
                effective_tcp_scan_type_log = f"TCP Scan Type: -s{type_char_log}"

        log_target_spec = f"file '{input_target_file}'" if input_target_file else f"scope '{target_scope}'"

        logger.info(
            f"ARKEngine: Starting full reconnaissance for targets {log_target_spec} ("
            f"TCP ports={top_ports}, OS={include_os_detection}, "
            f"Scripts='{nse_scripts or 'None'}', ScriptArgs='{nse_script_args or 'None'}', "
            f"UDP={include_udp_scan}, UDP ports={top_udp_ports if include_udp_scan else 'N/A'}, "
            f"Timing={effective_timing_log}, {effective_tcp_scan_type_log}"
            f"{', IPv6 Mode' if ipv6 else ''}, Reason={include_reason})"
        )
        if exclude_targets: logger.info(f"ARKEngine: Recon excluding targets string: {exclude_targets}")
        if exclude_file: logger.info(f"ARKEngine: Recon excluding targets from file: {exclude_file}")

        live_hosts: List[Host] = self.discover_live_hosts(
            target_scope=target_scope,
            timing_template=timing_template,
            input_target_file=input_target_file,
            exclude_targets=exclude_targets,
            exclude_file=exclude_file,
            ipv6=ipv6
        )

        if not live_hosts:
            logger.info(f"ARKEngine: No live hosts to perform detailed scans on for targets {log_target_spec}.")
            return []

        for host_obj in live_hosts: # live_hosts already contains Host objects from discover_live_hosts
            logger.info(f"\n--- Processing host: {host_obj.ip} ({host_obj.hostname or 'N/A'}) ---")
            
            # Perform TCP, optional OS, NSE scripts, and reason
            self.scan_host_deep(
                host_obj=host_obj, # Pass the Host object to be updated
                top_ports=top_ports,
                include_os_detection=include_os_detection,
                nse_scripts=nse_scripts,
                nse_script_args=nse_script_args,
                timing_template=timing_template,
                tcp_scan_type=tcp_scan_type,
                include_reason=include_reason
            )
            
            # Perform optional UDP scan
            if include_udp_scan:
                self.scan_host_udp(
                    host_obj=host_obj, # Pass the Host object to be updated
                    top_ports=top_udp_ports,
                    include_version=True, # Assuming version detection is desired for UDP if scanned
                    timing_template=timing_template,
                    include_reason=include_reason
                )
                
        logger.info(f"\n[*] ARKEngine: Full reconnaissance complete for targets {log_target_spec}.")
        return live_hosts # This list contains the updated Host objects
    
    # --- EXPORT and SAVE/LOAD METHODS (remain the same as the last full file version) ---
    def _dataclass_to_dict_converter(self, obj: Any) -> Any:
        if isinstance(obj, list): return [self._dataclass_to_dict_converter(item) for item in obj]
        elif is_dataclass(obj) and not isinstance(obj, type): return {k: self._dataclass_to_dict_converter(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, dict): return {k: self._dataclass_to_dict_converter(v) for k, v in obj.items()}
        return obj

    def export_to_json(self, scan_results: List[Host], filename: str):
        logger.info(f"Exporting {len(scan_results)} host(s) to JSON file: {filename}")
        try:
            results_as_dicts = [asdict(host) for host in scan_results] # Simplified for export
            with open(filename, 'w', encoding='utf-8') as f: json.dump(results_as_dicts, f, indent=4)
            logger.info(f"Successfully exported results to {filename}")
        except IOError as e: logger.error(f"IOError exporting results to JSON file {filename}: {e}", exc_info=True)
        except TypeError as e: logger.error(f"TypeError during JSON serialization for {filename}: {e}", exc_info=True)
        except Exception as e: logger.error(f"An unexpected error occurred during JSON export to {filename}: {e}", exc_info=True)

    def export_to_csv(self, scan_results: List[Host], filename: str):
        logger.info(f"Exporting results to CSV file: {filename}")
        headers = [
            "Host IP", "Hostname", "Host Status", "MAC Address", "MAC Vendor",
            "OS Guesses", "Host Scripts (Summary)", "Port Number", "Port Protocol", "Port Status", "Port Reason",
            "Service Name", "Service Product", "Service Version", "Service ExtraInfo", "Port Scripts (Summary)"
        ]
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore')
                writer.writeheader()
                for host in scan_results:
                    host_base_info = {
                        "Host IP": host.ip, "Hostname": host.hostname or "", "Host Status": host.status,
                        "MAC Address": host.mac_address or "", "MAC Vendor": host.vendor or "",
                        "OS Guesses": "; ".join([f"{om.name} ({om.accuracy}%)" for om in host.os_matches]) if host.os_matches else "",
                        "Host Scripts (Summary)": "; ".join([f"{sid}:{out[:30]}{'...' if len(out)>30 else ''}" for sid, out in (host.host_scripts or {}).items()])
                    }
                    if host.ports:
                        relevant_ports = [p for p in host.ports if 'open' in p.status or 'filtered' in p.status]
                        if relevant_ports:
                            for port in relevant_ports:
                                port_info_row = {
                                    "Port Number": port.number, "Port Protocol": port.protocol, "Port Status": port.status,
                                    "Port Reason": port.reason or "",
                                    "Service Name": port.service.name if port.service else "",
                                    "Service Product": port.service.product if port.service else "",
                                    "Service Version": port.service.version if port.service else "",
                                    "Service ExtraInfo": port.service.extrainfo if port.service else "",
                                    "Port Scripts (Summary)": "; ".join([f"{sid}:{out[:30]}{'...' if len(out)>30 else ''}" for sid, out in (port.scripts or {}).items()])
                                }
                                writer.writerow({**host_base_info, **port_info_row})
                        else: writer.writerow(host_base_info)
                    else: writer.writerow(host_base_info)
            logger.info(f"Successfully exported results to {filename}")
        except IOError as e: logger.error(f"IOError exporting results to CSV file {filename}: {e}", exc_info=True)
        except Exception as e: logger.error(f"An unexpected error occurred during CSV export to {filename}: {e}", exc_info=True)

    def save_scan_results(self, scan_results: List[Host], filename: str):
        logger.info(f"Saving {len(scan_results)} host(s) scan results to: {filename}")
        try:
            self.export_to_json(scan_results, filename) 
        except Exception as e:
            logger.error(f"Failed to save scan results to {filename} (error during export_to_json): {e}", exc_info=True)

    def _dict_to_dataclass_converter(self, data: Any, target_cls: Type) -> Any: # Corrected name
        if data is None: return None
        actual_cls_for_list_item = None
        if hasattr(target_cls, '__origin__') and target_cls.__origin__ is list:
            if not isinstance(data, list):
                logger.warning(f"Data for list type {target_cls} is not a list: {type(data)}. Returning as is.")
                return data
            actual_cls_for_list_item = target_cls.__args__[0]
            return [self._dict_to_dataclass_converter(item, actual_cls_for_list_item) for item in data]
        actual_cls = target_cls
        if hasattr(target_cls, '__origin__') and target_cls.__origin__ is Optional:
            actual_cls = next(t for t in target_cls.__args__ if t is not type(None))
        if not is_dataclass(actual_cls) or not isinstance(data, dict):
            return data
        field_types = {f.name: f.type for f in fields(actual_cls)}
        constructor_args = {}
        for name, field_type_hint in field_types.items():
            value = data.get(name)
            is_field_optional = hasattr(field_type_hint, '__origin__') and field_type_hint.__origin__ is Optional or \
                                hasattr(field_type_hint, '__args__') and type(None) in field_type_hint.__args__
            current_field_actual_type = field_type_hint
            if is_field_optional:
                current_field_actual_type = next(t for t in field_type_hint.__args__ if t is not type(None))
            if value is not None:
                if hasattr(current_field_actual_type, '__origin__') and current_field_actual_type.__origin__ is list:
                    list_element_type = current_field_actual_type.__args__[0]
                    constructor_args[name] = [self._dict_to_dataclass_converter(item, list_element_type) for item in value]
                elif hasattr(current_field_actual_type, '__origin__') and current_field_actual_type.__origin__ is dict:
                    constructor_args[name] = value 
                elif is_dataclass(current_field_actual_type):
                    constructor_args[name] = self._dict_to_dataclass_converter(value, current_field_actual_type)
                else: constructor_args[name] = value
            elif is_field_optional: constructor_args[name] = None
        try: return actual_cls(**constructor_args)
        except TypeError as e: logger.error(f"TypeError creating {actual_cls.__name__} with args {constructor_args} from data {data}: {e}", exc_info=True); return None

    def load_scan_results(self, filename: str) -> List[Host]:
        logger.info(f"Loading scan results from: {filename}")
        loaded_hosts: List[Host] = []
        try:
            with open(filename, 'r', encoding='utf-8') as f: data_from_json = json.load(f)
            if not isinstance(data_from_json, list): logger.error(f"Invalid format in {filename}: Expected list."); return []
            for host_data_dict in data_from_json:
                if isinstance(host_data_dict, dict):
                    host_obj = self._dict_to_dataclass_converter(host_data_dict, Host)
                    if host_obj: loaded_hosts.append(host_obj)
                else: logger.warning(f"Skipping non-dict item in JSON: {type(host_data_dict)}")
            logger.info(f"Successfully loaded {len(loaded_hosts)} host(s) from {filename}")
            return loaded_hosts
        except FileNotFoundError: logger.error(f"File not found: {filename}"); return []
        except json.JSONDecodeError as e: logger.error(f"Error decoding JSON from {filename}: {e}"); return []
        except Exception as e: logger.error(f"Unexpected error loading from {filename}: {e}", exc_info=True); return []