# autork/nmap_handler.py
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any
import os
import shutil
import logging # Import logging

from .datamodels import Host, Port, Service, OSMatch

# Get a logger for this module
logger = logging.getLogger(__name__)

class NmapHandler:
    def __init__(self, nmap_path: Optional[str] = None):
        """
        Initializes the NmapHandler, determining the path to the Nmap executable.

        Search Order for Nmap path:
        1. Explicit `nmap_path` argument provided.
        2. `ARK_NMAP_PATH` environment variable.
        3. Default "nmap" (checks if it exists in the system PATH).

        :param nmap_path: Explicit path to the Nmap executable (optional).
        :type nmap_path: Optional[str]
        :raises FileNotFoundError: If no valid Nmap executable path can be found.
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
        Runs an Nmap command and returns the parsed XML output.
        """
        try:
            logger.debug(f"Executing Nmap command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=600)
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
            logger.error(f"Nmap command timed out: {' '.join(command)}")
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
            logger.debug(f"Parsing ping scan XML. Root tag: {root.tag}") # Debug root
            for host_node in root.findall('host'):
                # --- Added Debug block ---
                ip_for_debug = host_node.findtext('address[@addrtype="ipv4"]')
                status_element = host_node.find('status') # Find element first
                state_attr_for_debug = status_element.get('state') if status_element is not None else 'StatusElementNotFound'
                logger.debug(f"Processing host node: IP={ip_for_debug}, StatusAttr='{state_attr_for_debug}'")
                # --- End Debug block ---

                status_node = host_node.find('status') # Re-find for logic
                address_node = host_node.find('address[@addrtype="ipv4"]')

                if status_node is not None and address_node is not None:
                    state = status_node.get('state')
                    ip_address = address_node.get('addr')
                    logger.debug(f"  Parsed state='{state}', ip='{ip_address}'") # Debug parsed values

                    if state == 'up' and ip_address:
                        current_hostname: Optional[str] = None
                        hostnames_node = host_node.find('hostnames')
                        if hostnames_node is not None:
                            hostname_element = hostnames_node.find('hostname')
                            if hostname_element is not None:
                                current_hostname = hostname_element.get('name')
                        # See if this critical debug message prints during the failing test
                        logger.debug(f"  >>> Found UP host! Appending Host(ip={ip_address}, hostname={current_hostname})")
                        discovered_hosts.append(
                            Host(ip=ip_address, status='up', hostname=current_hostname)
                        )
        # ... (logging for no hosts up) ...
        if not discovered_hosts and xml_root_element_tree is not None:
             root = xml_root_element_tree.getroot()
             runstats_node = root.find('runstats/hosts')
             if runstats_node is not None and runstats_node.get('up') == "0" and runstats_node.get('total') != "0":
                 logger.info(f"Nmap ping scan completed. No hosts found up in scope: {target_scope}")
             elif runstats_node is None or runstats_node.get('total') == "0":
                 logger.warning(f"Nmap ping scan completed but reported 0 total hosts. Check target specification: {target_scope}")

        logger.debug(f"Ping scan for {target_scope} finished. Returning {len(discovered_hosts)} hosts.")
        return discovered_hosts

    def run_port_scan_with_services(self, host_ip: str, top_ports: int = 100, include_os_detection: bool = False) -> Dict[str, Any]:
        """
        Performs a port scan and optionally OS detection on the specified host.
        Returns a dictionary containing 'ports' (List[Port]) and 'os_matches' (List[OSMatch]),
        plus other host details like MAC, uptime, etc.
        """
        logger.debug(f"Initiating port/service scan for host: {host_ip} (top_ports={top_ports}, os_detect={include_os_detection})")
        command = [self.nmap_path, '-sV', '-T4']
        if top_ports is not None and top_ports > 0:
            command.extend(['--top-ports', str(top_ports)])
        elif top_ports == 0:
             command.extend(['-p', '1-65535'])

        if include_os_detection:
            command.append('-O')
            logger.info("OS detection requested. This may require root/administrator privileges.")

        command.extend(['-oX', '-', host_ip])

        xml_root_element_tree = self._run_command(command)

        scan_results: Dict[str, Any] = { # Default empty structure
            "ports": [], "os_matches": [], "mac_address": None, "vendor": None,
            "uptime_seconds": None, "last_boot": None, "distance": None
        }

        if xml_root_element_tree:
            root = xml_root_element_tree.getroot()
            host_node = root.find('host')

            # Ensure host_node exists before proceeding with parsing for that host
            if host_node is None:
                hosthint_node = root.find('hosthint')
                if hosthint_node:
                     status_node = hosthint_node.find('status')
                     if status_node is not None and status_node.get('state') == 'down':
                         logger.info(f"Host {host_ip} reported as down by Nmap during port scan.")
                         return scan_results

                verbose_node = root.find('verbose')
                if verbose_node is not None and "Failed to resolve" in verbose_node.get('level', ''):
                     logger.warning(f"Failed to resolve hostname {host_ip}")
                     return scan_results

                logger.warning(f"No 'host' node found in Nmap XML output for {host_ip}. Scan might have failed or host is down.")
                return scan_results

            # --- Parsing logic now guaranteed to have a valid host_node ---

            # Parse Ports
            ports_parent_node = host_node.find('ports')
            if ports_parent_node is not None:
                for port_element in ports_parent_node.findall('port'):
                    try:
                        port_num = int(port_element.get('portid'))
                        protocol = port_element.get('protocol')
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
                        scan_results["ports"].append(Port(
                            number=port_num, protocol=protocol, status=status,
                            service=port_service_obj, reason=reason
                        ))
                    except Exception as e:
                        logger.error(f"Error parsing a port element for {host_ip}: {e}", exc_info=True)
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

        # End of 'if xml_root_element_tree:' block
        logger.debug(f"Port/service scan for {host_ip} finished. Returning results.")
        return scan_results

# --- For direct testing of this file ---
# The __main__ block remains the same as the previous version, it can be used
# for manual testing if needed, but pytest is preferred.
if __name__ == '__main__':
    # Basic logging setup for direct script testing
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    print("--- Testing NmapHandler (with OS Detection if privileges allow) ---")
    # ... (rest of the __main__ block as provided before) ...
    handler = NmapHandler()
    # ... etc ...