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
        try:
            logger.debug(f"Executing Nmap command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=900)
            if result.stdout:
                try:
                    return ET.ElementTree(ET.fromstring(result.stdout))
                except ET.ParseError as e:
                    logger.error(f"Error parsing Nmap XML output: {e}", exc_info=False)
                    logger.debug(f"--- Nmap Raw Output (first 500 chars) ---:\n{result.stdout[:500]}\n--- End Raw Output ---")
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
        default_timing = 4 # Nmap's default is T3, but we've been using T4.
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

    def run_ping_scan(self, target_scope: str, timing_template: Optional[int] = None) -> List[Host]:
        final_timing_value = self._get_validated_timing_template_value(timing_template)
        logger.debug(f"Initiating ping scan for target: {target_scope} with timing -T{final_timing_value}")
        command = [self.nmap_path, '-sn', f'-T{final_timing_value}', '-oX', '-', target_scope]
        xml_root_element_tree = self._run_command(command)
        discovered_hosts: List[Host] = []
        if xml_root_element_tree:
            # ... (rest of parsing logic as before) ...
            root = xml_root_element_tree.getroot()
            for host_node in root.findall('host'):
                status_node = host_node.find('status')
                address_node = host_node.find('address[@addrtype="ipv4"]')
                if status_node is not None and address_node is not None:
                    state = status_node.get('state')
                    ip_address = address_node.get('addr')
                    if state == 'up' and ip_address:
                        current_hostname: Optional[str] = None
                        hostnames_node = host_node.find('hostnames')
                        if hostnames_node is not None:
                            hostname_element = hostnames_node.find('hostname')
                            if hostname_element is not None:
                                current_hostname = hostname_element.get('name')
                        discovered_hosts.append(Host(ip=ip_address, status='up', hostname=current_hostname))
        # ... (logging for no hosts up as before) ...
        return discovered_hosts

    def run_port_scan_with_services(
        self,
        host_ip: str,
        top_ports: int = 100,
        include_os_detection: bool = False,
        nse_scripts: Optional[str] = None,
        nse_script_args: Optional[str] = None,
        timing_template: Optional[int] = None # <<< ADDED
    ) -> Dict[str, Any]:
        final_timing_value = self._get_validated_timing_template_value(timing_template)
        logger.debug(f"Initiating TCP port/service/script scan for host: {host_ip} "
                     f"(top_ports={top_ports}, os_detect={include_os_detection}, "
                     f"scripts='{nse_scripts or 'None'}', script_args='{nse_script_args or 'None'}', "
                     f"timing_template='T{final_timing_value}')")

        command = [self.nmap_path, '-sV', f'-T{final_timing_value}'] # Use validated timing
        if top_ports is not None and top_ports > 0: command.extend(['--top-ports', str(top_ports)])
        elif top_ports == 0: command.extend(['-p', '1-65535'])
        if include_os_detection: command.append('-O'); logger.info("OS detection requested. Requires root/admin.")
        has_scripts_to_run = False
        if nse_scripts and isinstance(nse_scripts, str) and nse_scripts.strip():
            safe_script_value = nse_scripts.strip()
            command.extend(['--script', safe_script_value]); logger.info(f"NSE scripts requested: --script {safe_script_value}"); has_scripts_to_run = True
        if has_scripts_to_run and nse_script_args and isinstance(nse_script_args, str) and nse_script_args.strip():
            safe_script_args_value = nse_script_args.strip()
            command.extend(['--script-args', safe_script_args_value]); logger.info(f"NSE script arguments provided: --script-args \"{safe_script_args_value}\"")
        elif nse_script_args and not has_scripts_to_run: logger.warning("NSE script arguments provided, but no scripts were specified to run. Args will be ignored.")
        command.extend(['-oX', '-', host_ip])
        xml_root_element_tree = self._run_command(command)
        scan_results: Dict[str, Any] = {
            "ports": [], "os_matches": [], "mac_address": None, "vendor": None,
            "uptime_seconds": None, "last_boot": None, "distance": None, "host_scripts": {}
        }
        if xml_root_element_tree:
            # ... (rest of parsing logic for ports, OS, scripts, MAC etc. remains the same as the last full version) ...
            root = xml_root_element_tree.getroot()
            host_node = root.find('host')
            if host_node is None:
                logger.warning(f"No 'host' node found in Nmap XML output for {host_ip}.")
                return scan_results
            should_parse_scripts = has_scripts_to_run
            ports_parent_node = host_node.find('ports')
            if ports_parent_node is not None:
                for port_element in ports_parent_node.findall('port'):
                    try:
                        port_num = int(port_element.get('portid')); protocol = port_element.get('protocol')
                        if protocol != 'tcp': continue
                        state_node = port_element.find('state');
                        if state_node is None: continue
                        status = state_node.get('state'); reason = state_node.get('reason', '')
                        port_service_obj: Optional[Service] = None
                        if status == 'open':
                            service_node = port_element.find('service')
                            if service_node is not None:
                                port_service_obj = Service(
                                    name=service_node.get('name', ""), product=service_node.get('product', ""),
                                    version=service_node.get('version', ""), extrainfo=service_node.get('extrainfo', ""),
                                    ostype=service_node.get('ostype', ""), method=service_node.get('method', ""),
                                    conf=int(service_node.get('conf', "0")))
                        port_scripts_data: Optional[Dict[str, str]] = None
                        if should_parse_scripts:
                            temp_scripts_data = {}
                            for script_node in port_element.findall('script'):
                                script_id = script_node.get('id'); script_output = script_node.get('output')
                                if script_id and script_output is not None: temp_scripts_data[script_id] = script_output
                            if temp_scripts_data: port_scripts_data = temp_scripts_data
                        scan_results["ports"].append(Port(
                            number=port_num, protocol=protocol, status=status,
                            service=port_service_obj, reason=reason, scripts=port_scripts_data))
                    except Exception as e: logger.error(f"Error parsing a TCP port element for {host_ip}: {e}", exc_info=True)
            if include_os_detection:
                 os_node = host_node.find('os')
                 if os_node is not None:
                     for osmatch_node in os_node.findall('osmatch'):
                          scan_results["os_matches"].append(OSMatch(
                             name=osmatch_node.get('name', 'Unknown OS'), accuracy=int(osmatch_node.get('accuracy', 0)),
                             line=int(osmatch_node.get('line', 0))))
            if should_parse_scripts:
                hostscript_node = host_node.find('hostscript')
                if hostscript_node is not None:
                    host_scripts_data = {}
                    for script_node in hostscript_node.findall('script'):
                        script_id = script_node.get('id'); script_output = script_node.get('output')
                        if script_id and script_output is not None: host_scripts_data[script_id] = script_output
                    if host_scripts_data: scan_results["host_scripts"] = host_scripts_data
            for address_element in host_node.findall('address'):
                 if address_element.get('addrtype') == 'mac':
                     scan_results['mac_address'] = address_element.get('addr')
                     scan_results['vendor'] = address_element.get('vendor'); break
            uptime_node = host_node.find('uptime')
            if uptime_node is not None: scan_results['uptime_seconds'] = int(uptime_node.get('seconds', "0")); scan_results['last_boot'] = uptime_node.get('lastboot')
            distance_node = host_node.find('distance')
            if distance_node is not None: scan_results['distance'] = int(distance_node.get('value', "0"))
        logger.debug(f"TCP port/service/script scan for {host_ip} finished. Returning results.")
        return scan_results

    def run_udp_scan(self, host_ip: str, top_ports: int = 100, include_version: bool = True, timing_template: Optional[int] = None) -> List[Port]: # Added timing
        final_timing_value = self._get_validated_timing_template_value(timing_template)
        logger.info(f"Initiating UDP scan for host: {host_ip} (top_ports={top_ports}, version_detect={include_version}, timing_template='T{final_timing_value}')")
        logger.warning("UDP scanning requires root/administrator privileges and can be very slow.")
        command = [self.nmap_path, '-sU', f'-T{final_timing_value}']
        if include_version: command.append('-sV')
        if top_ports is not None and top_ports > 0: command.extend(['--top-ports', str(top_ports)])
        command.extend(['-oX', '-', host_ip])
        # ... (rest of UDP parsing logic remains the same as the last full version) ...
        xml_root_element_tree = self._run_command(command)
        parsed_ports: List[Port] = []
        if xml_root_element_tree:
            root = xml_root_element_tree.getroot()
            host_node = root.find('host')
            if host_node is None:
                logger.warning(f"No 'host' node found in Nmap UDP scan XML output for {host_ip}.")
                return parsed_ports
            ports_parent_node = host_node.find('ports')
            if ports_parent_node is not None:
                for port_element in ports_parent_node.findall('port'):
                    try:
                        port_num = int(port_element.get('portid')); protocol = port_element.get('protocol')
                        if protocol != 'udp': continue
                        state_node = port_element.find('state');
                        if state_node is None: continue
                        status = state_node.get('state'); reason = state_node.get('reason', '')
                        port_service_obj: Optional[Service] = None
                        if include_version and ('open' in status):
                            service_node = port_element.find('service')
                            if service_node is not None:
                                port_service_obj = Service(
                                    name=service_node.get('name', ""), product=service_node.get('product', ""),
                                    version=service_node.get('version', ""), extrainfo=service_node.get('extrainfo', ""),
                                    method=service_node.get('method', ""), conf=int(service_node.get('conf', "0")))
                        parsed_ports.append(Port(
                            number=port_num, protocol=protocol, status=status,
                            service=port_service_obj, reason=reason, scripts=None))
                    except Exception as e: logger.error(f"Error parsing a UDP port element for {host_ip}: {e}", exc_info=True)
        logger.debug(f"UDP scan for {host_ip} finished. Parsed {len(parsed_ports)} ports.")
        return parsed_ports

# ... (Main block for direct testing) ...