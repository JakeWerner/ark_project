# autork/nmap_handler.py
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any
import os
import shutil
import logging

from .datamodels import Host, Port, Service, OSMatch

# Get a logger for this module
logger = logging.getLogger(__name__)

class NmapHandler:
    def __init__(self, nmap_path: Optional[str] = None):
        """
        Initializes the NmapHandler, determining the path to the Nmap executable.
        Search Order: explicit path -> ARK_NMAP_PATH env var -> "nmap" in PATH.
        """
        found_path: Optional[str] = None
        # 1. Check explicit argument
        if nmap_path:
            if shutil.which(nmap_path):
                found_path = nmap_path
                logger.info(f"Using explicitly provided Nmap path: {found_path}")
            else:
                logger.warning(f"Explicitly provided nmap_path '{nmap_path}' not found or not executable. Checking environment/PATH.")
        # 2. Check environment variable
        if not found_path:
            env_path = os.environ.get('ARK_NMAP_PATH')
            if env_path:
                if shutil.which(env_path):
                    found_path = env_path
                    logger.info(f"Using Nmap path from ARK_NMAP_PATH environment variable: {found_path}")
                else:
                     logger.warning(f"Nmap path specified in ARK_NMAP_PATH ('{env_path}') not found or not executable. Checking default PATH.")
        # 3. Check default "nmap" in PATH
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
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=900) # 15 min timeout
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

    def run_ping_scan(self, target_scope: str) -> List[Host]:
        """
        Performs a ping scan (host discovery) on the given target scope.
        Returns a list of Host objects with IP, status, and hostname (if available).
        """
        logger.debug(f"Initiating ping scan for target: {target_scope}")
        command = [self.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
        xml_root_element_tree = self._run_command(command)
        discovered_hosts: List[Host] = []

        if xml_root_element_tree:
            root = xml_root_element_tree.getroot()
            logger.debug(f"Parsing ping scan XML. Root tag: {root.tag}")
            for host_node in root.findall('host'):
                ip_for_debug = host_node.findtext('address[@addrtype="ipv4"]')
                status_element = host_node.find('status')
                state_attr_for_debug = status_element.get('state') if status_element is not None else 'StatusElementNotFound'
                logger.debug(f"Processing host node: IP={ip_for_debug}, StatusAttr='{state_attr_for_debug}'")

                status_node = host_node.find('status')
                address_node = host_node.find('address[@addrtype="ipv4"]')

                if status_node is not None and address_node is not None:
                    state = status_node.get('state')
                    ip_address = address_node.get('addr')
                    logger.debug(f"  Parsed state='{state}', ip='{ip_address}'")

                    if state == 'up' and ip_address:
                        current_hostname: Optional[str] = None
                        hostnames_node = host_node.find('hostnames')
                        if hostnames_node is not None:
                            hostname_element = hostnames_node.find('hostname')
                            if hostname_element is not None:
                                current_hostname = hostname_element.get('name')
                        logger.debug(f"  >>> Found UP host! Appending Host(ip={ip_address}, hostname={current_hostname})")
                        discovered_hosts.append(
                            Host(ip=ip_address, status='up', hostname=current_hostname)
                        )

        if not discovered_hosts and xml_root_element_tree is not None:
             root = xml_root_element_tree.getroot()
             runstats_node = root.find('runstats/hosts')
             if runstats_node is not None and runstats_node.get('up') == "0" and runstats_node.get('total') != "0":
                 logger.info(f"Nmap ping scan completed. No hosts found up in scope: {target_scope}")
             elif runstats_node is None or runstats_node.get('total') == "0":
                 logger.warning(f"Nmap ping scan completed but reported 0 total hosts. Check target specification: {target_scope}")

        logger.debug(f"Ping scan for {target_scope} finished. Returning {len(discovered_hosts)} hosts.")
        return discovered_hosts

    def run_port_scan_with_services(
        self,
        host_ip: str,
        top_ports: int = 100,
        include_os_detection: bool = False,
        run_default_scripts: bool = False # NEW flag
    ) -> Dict[str, Any]:
        """
        Performs a TCP port scan, optionally OS detection and default NSE scripts.
        Returns dict including ports, os_matches, host_scripts, MAC, uptime etc.
        """
        logger.debug(f"Initiating TCP port/service/script scan for host: {host_ip} "
                     f"(top_ports={top_ports}, os_detect={include_os_detection}, scripts={run_default_scripts})")

        command = [self.nmap_path, '-sV', '-T4'] # Base TCP scan with service detection
        if top_ports is not None and top_ports > 0:
            command.extend(['--top-ports', str(top_ports)])
        elif top_ports == 0:
            command.extend(['-p', '1-65535'])

        if include_os_detection:
            command.append('-O')
            logger.info("OS detection requested. Requires root/admin.")

        if run_default_scripts:
            command.append('-sC') # Add default scripts flag
            logger.info("Default NSE scripts requested (-sC).")

        command.extend(['-oX', '-', host_ip]) # Output XML to stdout, specify target

        xml_root_element_tree = self._run_command(command)

        scan_results: Dict[str, Any] = { # Initialize with new keys
            "ports": [], "os_matches": [], "mac_address": None, "vendor": None,
            "uptime_seconds": None, "last_boot": None, "distance": None,
            "host_scripts": {} # Initialize host scripts dict
        }

        if xml_root_element_tree:
            root = xml_root_element_tree.getroot()
            host_node = root.find('host')

            if host_node is None:
                 # ... (error handling as before using logger) ...
                 hosthint_node = root.find('hosthint')
                 if hosthint_node:
                      status_node = hosthint_node.find('status')
                      if status_node is not None and status_node.get('state') == 'down':
                          logger.info(f"Host {host_ip} reported as down by Nmap during detailed scan.")
                          return scan_results
                 verbose_node = root.find('verbose')
                 if verbose_node is not None and "Failed to resolve" in verbose_node.get('level', ''):
                      logger.warning(f"Failed to resolve hostname {host_ip}")
                      return scan_results
                 logger.warning(f"No 'host' node found in Nmap XML output for {host_ip}. Scan might have failed or host is down.")
                 return scan_results

            # --- Parsing logic now guaranteed to have a valid host_node ---
            # Parse Ports and Port Scripts
            ports_parent_node = host_node.find('ports')
            if ports_parent_node is not None:
                for port_element in ports_parent_node.findall('port'):
                    try:
                        port_num = int(port_element.get('portid'))
                        protocol = port_element.get('protocol')
                        if protocol != 'tcp': continue # Focus on TCP ports here

                        state_node = port_element.find('state')
                        if state_node is None: continue
                        status = state_node.get('state')
                        reason = state_node.get('reason', '')

                        port_service_obj: Optional[Service] = None
                        if status == 'open':
                            service_node = port_element.find('service')
                            if service_node is not None:
                                port_service_obj = Service(
                                    name=service_node.get('name', ""), product=service_node.get('product', ""),
                                    version=service_node.get('version', ""), extrainfo=service_node.get('extrainfo', ""),
                                    ostype=service_node.get('ostype', ""), method=service_node.get('method', ""),
                                    conf=int(service_node.get('conf', "0"))
                                )

                        # Parse Port Script Output
                        port_scripts_data: Optional[Dict[str, str]] = None
                        if run_default_scripts: # Only parse if scripts were requested
                            temp_scripts_data = {}
                            for script_node in port_element.findall('script'):
                                script_id = script_node.get('id')
                                script_output = script_node.get('output')
                                if script_id and script_output is not None: # Check output is not None
                                    temp_scripts_data[script_id] = script_output
                            if temp_scripts_data: # Assign only if not empty
                                port_scripts_data = temp_scripts_data

                        scan_results["ports"].append(Port(
                            number=port_num, protocol=protocol, status=status,
                            service=port_service_obj, reason=reason,
                            scripts=port_scripts_data # Assign parsed scripts
                        ))
                    except Exception as e:
                        logger.error(f"Error parsing a TCP port element for {host_ip}: {e}", exc_info=True)
                        continue

            # Parse OS Detection Results
            if include_os_detection:
                 os_node = host_node.find('os')
                 if os_node is not None:
                     for osmatch_node in os_node.findall('osmatch'):
                          scan_results["os_matches"].append(OSMatch(
                             name=osmatch_node.get('name', 'Unknown OS'),
                             accuracy=int(osmatch_node.get('accuracy', 0)),
                             line=int(osmatch_node.get('line', 0))
                          ))

            # Parse Host Script Output
            if run_default_scripts:
                hostscript_node = host_node.find('hostscript')
                if hostscript_node is not None:
                    host_scripts_data = {}
                    for script_node in hostscript_node.findall('script'):
                        script_id = script_node.get('id')
                        script_output = script_node.get('output')
                        if script_id and script_output is not None: # Check output is not None
                            host_scripts_data[script_id] = script_output
                    if host_scripts_data:
                        scan_results["host_scripts"] = host_scripts_data

            # Parse MAC, Vendor, Uptime, Distance
            for address_element in host_node.findall('address'):
                 if address_element.get('addrtype') == 'mac':
                     scan_results['mac_address'] = address_element.get('addr')
                     scan_results['vendor'] = address_element.get('vendor')
                     break
            uptime_node = host_node.find('uptime')
            if uptime_node is not None:
                 scan_results['uptime_seconds'] = int(uptime_node.get('seconds', "0"))
                 scan_results['last_boot'] = uptime_node.get('lastboot')
            distance_node = host_node.find('distance')
            if distance_node is not None:
                 scan_results['distance'] = int(distance_node.get('value', "0"))

        logger.debug(f"TCP port/service/script scan for {host_ip} finished. Returning results.")
        return scan_results


    def run_udp_scan(self, host_ip: str, top_ports: int = 100, include_version: bool = True) -> List[Port]:
        """
        Performs a UDP scan on the specified host.
        Requires root/administrator privileges. Can be slow.
        """
        logger.info(f"Initiating UDP scan for host: {host_ip} (top_ports={top_ports}, version_detect={include_version})")
        logger.warning("UDP scanning requires root/administrator privileges and can be very slow.")

        command = [self.nmap_path, '-sU', '-T4']
        if include_version:
            command.append('-sV')

        if top_ports is not None and top_ports > 0:
            command.extend(['--top-ports', str(top_ports)])

        command.extend(['-oX', '-', host_ip])

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
                        port_num = int(port_element.get('portid'))
                        protocol = port_element.get('protocol')
                        if protocol != 'udp': continue

                        state_node = port_element.find('state')
                        if state_node is None: continue
                        status = state_node.get('state')
                        reason = state_node.get('reason', '')

                        port_service_obj: Optional[Service] = None
                        if include_version and ('open' in status):
                            service_node = port_element.find('service')
                            if service_node is not None:
                                port_service_obj = Service(
                                    name=service_node.get('name', ""), product=service_node.get('product', ""),
                                    version=service_node.get('version', ""), extrainfo=service_node.get('extrainfo', ""),
                                    method=service_node.get('method', ""), conf=int(service_node.get('conf', "0"))
                                )

                        # Could add UDP script parsing here later if needed (e.g. using -sU -sC)
                        parsed_ports.append(Port(
                            number=port_num, protocol=protocol, status=status,
                            service=port_service_obj, reason=reason, scripts=None # No scripts parsed here yet
                        ))
                    except Exception as e:
                        logger.error(f"Error parsing a UDP port element for {host_ip}: {e}", exc_info=True)
                        continue
        logger.debug(f"UDP scan for {host_ip} finished. Parsed {len(parsed_ports)} ports.")
        return parsed_ports

# --- Main block for direct testing (optional) ---
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("--- Manual Testing NmapHandler ---")
    try:
        # Example: Test ping scan
        handler = NmapHandler() # Assumes nmap in PATH or ARK_NMAP_PATH is set
        target = "scanme.nmap.org"
        logger.info(f"Running manual ping scan test on {target}")
        hosts = handler.run_ping_scan(target)
        logger.info(f"Manual Ping Scan Found Hosts: {hosts}")

        # Example: Test TCP scan with scripts (use an IP if ping scan found one)
        test_ip = hosts[0].ip if hosts else target # Use discovered IP or fallback
        logger.info(f"Running manual TCP deep scan test on {test_ip}")
        details = handler.run_port_scan_with_services(test_ip, top_ports=20, include_os_detection=False, run_default_scripts=True)
        logger.info(f"Manual TCP Scan Details:\n{details}")

    except FileNotFoundError as e:
         logger.error(f"Manual test failed: {e}")
    except Exception as e:
         logger.exception(f"An unexpected error occurred during manual test: {e}")