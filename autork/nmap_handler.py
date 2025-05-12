# autork/nmap_handler.py
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any
import os
import shutil
import logging

from .datamodels import Host, Port, Service, OSMatch

logger = logging.getLogger(__name__)

class NmapHandler:
    def __init__(self, nmap_path: Optional[str] = None):
        """
        Initializes the NmapHandler, determining the path to the Nmap executable.
        Search Order: explicit path -> ARK_NMAP_PATH env var -> "nmap" in PATH.
        """
        found_path: Optional[str] = None
        if nmap_path:
            if shutil.which(nmap_path):
                found_path = nmap_path
                logger.info(f"Using explicitly provided Nmap path: {found_path}")
            else:
                logger.warning(f"Explicitly provided nmap_path '{nmap_path}' not found or not executable. Checking environment/PATH.")
        if not found_path:
            env_path = os.environ.get('ARK_NMAP_PATH')
            if env_path:
                if shutil.which(env_path):
                    found_path = env_path
                    logger.info(f"Using Nmap path from ARK_NMAP_PATH environment variable: {found_path}")
                else:
                     logger.warning(f"Nmap path specified in ARK_NMAP_PATH ('{env_path}') not found or not executable. Checking default PATH.")
        if not found_path:
            if shutil.which("nmap"):
                found_path = "nmap"
                logger.info("Using 'nmap' found in system PATH.")
            else:
                err_msg = ("Nmap executable not found. Please ensure Nmap is installed and in your PATH, "
                           "provide the path explicitly, or set the ARK_NMAP_PATH environment variable.")
                logger.error(err_msg)
                raise FileNotFoundError(err_msg)
        self.nmap_path = found_path

    def _run_command(self, command: List[str]) -> Optional[ET.ElementTree]:
        """
        Runs an Nmap command and returns the parsed XML output ElementTree.
        """
        try:
            logger.debug(f"Executing Nmap command: {' '.join(command)}")
            # Increased timeout to handle potentially long scans
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=1800) # 30 min timeout
            if result.stdout:
                try:
                    return ET.ElementTree(ET.fromstring(result.stdout))
                except ET.ParseError as e:
                    logger.error(f"Error parsing Nmap XML output: {e}", exc_info=False) # Set exc_info=True for full traceback
                    logger.debug(f"--- Nmap Raw Output (first 1000 chars) ---:\n{result.stdout[:1000]}\n--- End Raw Output ---")
                    return None
            else:
                logger.warning("Nmap command completed successfully but produced no stdout.")
                return None
        except FileNotFoundError:
            logger.error(f"Nmap executable not found at '{self.nmap_path}'.")
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running Nmap (return code {e.returncode}): {e}")
            if e.stderr: logger.error(f"Nmap stderr:\n{e.stderr}")
            if e.stdout: logger.debug(f"Nmap stdout (on error):\n{e.stdout[:500]}")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap command timed out after specified duration: {' '.join(command)}")
            return None

    def _get_validated_timing_template_value(self, timing_template_input: Optional[int]) -> int:
        """Validates user timing template input, defaults to 4 if invalid or None."""
        default_timing = 4
        if timing_template_input is None:
            logger.debug(f"Timing template not specified, defaulting to T{default_timing}.")
            return default_timing
        if isinstance(timing_template_input, int) and 0 <= timing_template_input <= 5:
            return timing_template_input
        else:
            logger.warning(
                f"Invalid timing_template value '{timing_template_input}'. "
                f"Must be an integer between 0 and 5. Defaulting to -T{default_timing}."
            )
            return default_timing

    def _get_ip_from_host_node(self, host_node: ET.Element, prefer_ipv6: bool) -> Optional[str]:
        """Helper to extract IP, preferring IPv6 if requested and available from scanned target."""
        ip_address: Optional[str] = None
        preferred_type = "ipv6" if prefer_ipv6 else "ipv4"
        fallback_type = "ipv4" if prefer_ipv6 else "ipv6"

        addr_node = host_node.find(f'address[@addrtype="{preferred_type}"]')
        if addr_node is not None:
            ip_address = addr_node.get('addr')
        
        if not ip_address: # If preferred not found, try fallback
            addr_node = host_node.find(f'address[@addrtype="{fallback_type}"]')
            if addr_node is not None:
                ip_address = addr_node.get('addr')
        
        if not ip_address: # Still no IP, grab the first one that isn't MAC
            for an_addr_node in host_node.findall('address'):
                addr_type = an_addr_node.get('addrtype')
                if addr_type == 'ipv4' or addr_type == 'ipv6':
                    ip_address = an_addr_node.get('addr')
                    logger.debug(f"Found IP {ip_address} of type {addr_type} as a last resort.")
                    break
        return ip_address

    def run_ping_scan(
        self,
        target_scope: Optional[str] = None,
        timing_template: Optional[int] = None,
        input_target_file: Optional[str] = None,
        exclude_targets: Optional[str] = None,
        exclude_file: Optional[str] = None,
        ipv6: bool = False
    ) -> List[Host]:
        final_timing_value = self._get_validated_timing_template_value(timing_template)
        log_target_spec = f"from file '{input_target_file}'" if input_target_file else f"scope '{target_scope}'" if target_scope else "No Target Specified"
        if not (target_scope or input_target_file):
            logger.error("Ping scan initiated without a target_scope or input_target_file.")
            return []
        
        logger.debug(f"Initiating ping scan for targets {log_target_spec} with timing -T{final_timing_value}{' (IPv6)' if ipv6 else ''}")

        command = [self.nmap_path]
        if ipv6: command.append("-6")
        command.extend(['-sn', f'-T{final_timing_value}'])

        if input_target_file and isinstance(input_target_file, str) and input_target_file.strip():
            command.extend(['-iL', input_target_file.strip()])
        if exclude_targets and isinstance(exclude_targets, str) and exclude_targets.strip():
            command.extend(['--exclude', exclude_targets.strip()])
        if exclude_file and isinstance(exclude_file, str) and exclude_file.strip():
            command.extend(['--excludefile', exclude_file.strip()])
        
        command.extend(['-oX', '-']) # XML output to stdout
        
        # Append target_scope only if input_target_file was not used
        if not (input_target_file and isinstance(input_target_file, str) and input_target_file.strip()):
            if target_scope and isinstance(target_scope, str) and target_scope.strip():
                command.append(target_scope.strip())
            else: # This state should have been caught by the initial check
                logger.error("Ping scan target_scope is missing and no input_target_file was provided to Nmap command.")
                return []

        xml_root_element_tree = self._run_command(command)
        discovered_hosts: List[Host] = []
        if xml_root_element_tree:
            root = xml_root_element_tree.getroot()
            for host_node in root.findall('host'):
                status_node = host_node.find('status')
                ip_address = self._get_ip_from_host_node(host_node, ipv6) # Use helper for IP

                if status_node is not None and ip_address:
                    state = status_node.get('state')
                    if state == 'up':
                        current_hostname: Optional[str] = None
                        hostnames_node = host_node.find('hostnames')
                        if hostnames_node is not None:
                            hostname_element = hostnames_node.find('hostname')
                            if hostname_element is not None:
                                current_hostname = hostname_element.get('name')
                        discovered_hosts.append(Host(ip=ip_address, status='up', hostname=current_hostname))
        
        if not discovered_hosts and xml_root_element_tree is not None:
             root = xml_root_element_tree.getroot()
             runstats_node = root.find('runstats/hosts')
             if runstats_node is not None and runstats_node.get('up') == "0" and runstats_node.get('total') != "0":
                 logger.info(f"Nmap ping scan completed. No hosts found up in {log_target_spec}")
             elif runstats_node is None or runstats_node.get('total') == "0" and (target_scope or input_target_file):
                 logger.warning(f"Nmap ping scan completed but reported 0 total hosts for {log_target_spec}. Check target specification and network connectivity.")
        
        logger.debug(f"Ping scan for {log_target_spec} finished. Returning {len(discovered_hosts)} hosts.")
        return discovered_hosts

    def run_port_scan_with_services(
        self,
        host_ip: str,
        top_ports: int = 100,
        include_os_detection: bool = False,
        nse_scripts: Optional[str] = None,
        nse_script_args: Optional[str] = None,
        timing_template: Optional[int] = None,
        tcp_scan_type: Optional[str] = None,
        ipv6: bool = False,
        include_reason: bool = False
    ) -> Dict[str, Any]:
        final_timing_value = self._get_validated_timing_template_value(timing_template)
        nmap_scan_type_flag_to_add: Optional[str] = None
        log_scan_type = "Nmap Default for -sV"
        
        if tcp_scan_type and isinstance(tcp_scan_type, str):
            type_char = tcp_scan_type.strip().upper()
            valid_scan_type_chars = ["S", "T", "A", "F", "X", "N"]
            if type_char in valid_scan_type_chars:
                nmap_scan_type_flag_to_add = f"-s{type_char}"
                log_scan_type = f"TCP Scan Type: {nmap_scan_type_flag_to_add}"
                if type_char != "T" and not (ipv6 and type_char == "S"):
                    logger.warning(f"TCP scan type {nmap_scan_type_flag_to_add} often requires root/admin privileges.")
            else:
                logger.warning(f"Invalid tcp_scan_type character '{tcp_scan_type}'. Using Nmap's default with -sV.")
        
        logger.debug(f"Initiating TCP port/service/script scan for host: {host_ip} "
                     f"(top_ports={top_ports}, os_detect={include_os_detection}, "
                     f"scripts='{nse_scripts or 'None'}', script_args='{nse_script_args or 'None'}', "
                     f"timing_template='T{final_timing_value}', {log_scan_type}"
                     f"{', IPv6' if ipv6 else ''}{', Reason: ' + str(include_reason) if include_reason else ''})")

        command = [self.nmap_path]
        if ipv6: command.append("-6")
        if nmap_scan_type_flag_to_add: command.append(nmap_scan_type_flag_to_add)
        
        command.extend(['-sV', f'-T{final_timing_value}'])
        
        if include_reason:
            command.append("--reason")

        if top_ports is not None and top_ports > 0: command.extend(['--top-ports', str(top_ports)])
        elif top_ports == 0: command.extend(['-p', '1-65535'])
        if include_os_detection: command.append('-O')
        
        has_scripts_to_run = False
        if nse_scripts and isinstance(nse_scripts, str) and nse_scripts.strip():
            safe_script_value = nse_scripts.strip(); command.extend(['--script', safe_script_value]); has_scripts_to_run = True
        
        if has_scripts_to_run and nse_script_args and isinstance(nse_script_args, str) and nse_script_args.strip():
            command.extend(['--script-args', nse_script_args.strip()])
        elif nse_script_args and not has_scripts_to_run:
            logger.warning("NSE script arguments provided, but no scripts were specified to run. Args will be ignored by Nmap.")
            
        command.extend(['-oX', '-', host_ip])

        xml_root_element_tree = self._run_command(command)
        scan_results: Dict[str, Any] = {
            "ports": [], "os_matches": [], "mac_address": None, "vendor": None,
            "uptime_seconds": None, "last_boot": None, "distance": None, "host_scripts": {}
        }

        if xml_root_element_tree:
            root = xml_root_element_tree.getroot()
            host_node = root.find('host')
            if host_node is None:
                logger.warning(f"No 'host' node found in Nmap XML output for {host_ip}. Scan may have been blocked or target is down.")
                return scan_results

            should_parse_scripts = has_scripts_to_run
            
            # XML Parsing for ports, OS, scripts, MAC, etc. remains the same.
            # The 'reason' attribute is already being parsed from the <state> tag if present.
            # Using --reason in Nmap command makes Nmap populate this attribute more reliably/detailed.
            ports_parent_node = host_node.find('ports')
            if ports_parent_node is not None:
                for port_element in ports_parent_node.findall('port'):
                    try:
                        port_num = int(port_element.get('portid')); protocol = port_element.get('protocol')
                        if protocol != 'tcp': continue 
                        state_node = port_element.find('state');
                        if state_node is None: continue
                        status = state_node.get('state'); reason = state_node.get('reason', '')
                        port_service_obj: Optional[Service] = None; port_scripts_data: Optional[Dict[str, str]] = None
                        if status == 'open':
                            service_node = port_element.find('service')
                            if service_node is not None:
                                port_service_obj = Service(
                                    name=service_node.get('name', ""), product=service_node.get('product', ""),
                                    version=service_node.get('version', ""), extrainfo=service_node.get('extrainfo', ""),
                                    ostype=service_node.get('ostype', ""), method=service_node.get('method', ""),
                                    conf=int(service_node.get('conf', "0")))
                        if should_parse_scripts:
                            temp_scripts_data = {s.get('id'): s.get('output', '') for s in port_element.findall('script') if s.get('id')}
                            if temp_scripts_data: port_scripts_data = temp_scripts_data
                        scan_results["ports"].append(Port(number=port_num, protocol=protocol, status=status, service=port_service_obj, reason=reason, scripts=port_scripts_data))
                    except Exception as e: logger.error(f"Error parsing a TCP port element for {host_ip}: {e}", exc_info=True)
            
            if include_os_detection: # OS parsing
                 os_node = host_node.find('os')
                 if os_node is not None:
                     for osmatch_node in os_node.findall('osmatch'):
                          scan_results["os_matches"].append(OSMatch(name=osmatch_node.get('name', 'Unknown OS'), accuracy=int(osmatch_node.get('accuracy', 0)),line=int(osmatch_node.get('line', 0))))
            
            if should_parse_scripts: # Host scripts parsing
                hostscript_node = host_node.find('hostscript')
                if hostscript_node is not None:
                    temp_host_scripts = {s.get('id'): s.get('output', '') for s in hostscript_node.findall('script') if s.get('id')}
                    if temp_host_scripts: scan_results["host_scripts"] = temp_host_scripts
            
            # MAC, Uptime, Distance parsing
            for addr_el in host_node.findall('address'):
                if addr_el.get('addrtype') == 'mac':
                    scan_results['mac_address'] = addr_el.get('addr')
                    scan_results['vendor'] = addr_el.get('vendor'); break 
            uptime_node = host_node.find('uptime')
            if uptime_node is not None: scan_results['uptime_seconds'] = int(uptime_node.get('seconds', "0")); scan_results['last_boot'] = uptime_node.get('lastboot')
            distance_node = host_node.find('distance')
            if distance_node is not None: scan_results['distance'] = int(distance_node.get('value', "0"))
            
        return scan_results

    def run_udp_scan(self, host_ip: str, top_ports: int = 100, include_version: bool = True,
                     timing_template: Optional[int] = None, ipv6: bool = False,
                     include_reason: bool = False) -> List[Port]:
        final_timing_value = self._get_validated_timing_template_value(timing_template)
        logger.info(f"Initiating UDP scan for host: {host_ip} (top_ports={top_ports}, version_detect={include_version}, "
                    f"timing_template='T{final_timing_value}'{', IPv6' if ipv6 else ''}"
                    f"{', Reason: ' + str(include_reason) if include_reason else ''})")
        logger.warning("UDP scanning requires root/administrator privileges and can be very slow.")
        
        command = [self.nmap_path]
        if ipv6: command.append("-6")
        command.extend(['-sU', f'-T{final_timing_value}'])
        if include_version: command.append('-sV')
        
        if include_reason:
            command.append("--reason")
            
        if top_ports is not None and top_ports > 0: command.extend(['--top-ports', str(top_ports)])
        command.extend(['-oX', '-', host_ip])
        
        xml_root_element_tree = self._run_command(command)
        parsed_ports: List[Port] = []
        if xml_root_element_tree:
            root = xml_root_element_tree.getroot()
            host_node = root.find('host')
            if host_node is None: logger.warning(f"No 'host' node in UDP XML for {host_ip}."); return parsed_ports
            ports_parent_node = host_node.find('ports')
            if ports_parent_node is not None:
                for port_element in ports_parent_node.findall('port'):
                    try:
                        port_num = int(port_element.get('portid')); protocol = port_element.get('protocol')
                        if protocol != 'udp': continue
                        state_node = port_element.find('state');
                        if state_node is None: continue
                        status = state_node.get('state'); reason = state_node.get('reason', '') # Reason is parsed here
                        port_service_obj: Optional[Service] = None
                        if include_version and ('open' in status):
                            service_node = port_element.find('service')
                            if service_node is not None:
                                port_service_obj = Service(name=service_node.get('name', ""), product=service_node.get('product', ""), version=service_node.get('version', ""), extrainfo=service_node.get('extrainfo', ""), method=service_node.get('method', ""), conf=int(service_node.get('conf', "0")))
                        # For UDP, scripts are not typically run with just -sU -sV, so scripts=None
                        parsed_ports.append(Port(number=port_num, protocol=protocol, status=status, service=port_service_obj, reason=reason, scripts=None))
                    except Exception as e: logger.error(f"Error parsing a UDP port element for {host_ip}: {e}", exc_info=True)
        logger.debug(f"UDP scan for {host_ip} finished. Parsed {len(parsed_ports)} ports.")
        return parsed_ports

# ... (Main block for direct testing, if any)