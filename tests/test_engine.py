import pytest
from unittest.mock import MagicMock, patch
import subprocess # Keep for potential future use

# Import the class we are testing
from autork.engine import ARKEngine
# Import the datamodels used in the return types and arguments
from autork.datamodels import Host, Port, Service, OSMatch
# We might need NmapHandler for type hinting or patching the class itself
from autork.nmap_handler import NmapHandler
from typing import List, Dict, Any, Optional

# --- Test ARKEngine Initialization ---
def test_arkengine_initialization(mocker):
    """Test that ARKEngine initializes NmapHandler correctly."""
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    custom_path = "/usr/bin/nmap"
    engine = ARKEngine(nmap_path=custom_path)
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path=custom_path)
    assert isinstance(engine.nmap_handler, MagicMock)

# --- Test ARKEngine.discover_live_hosts ---
def test_discover_live_hosts_success(mocker):
    """Test discover_live_hosts when NmapHandler finds hosts."""
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    mock_host2 = Host(ip="192.168.1.5", status="up", hostname=None)
    mock_return_value = [mock_host1, mock_host2]
    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=mock_return_value)
    target_scope = "192.168.1.0/24"
    result_hosts = engine.discover_live_hosts(target_scope)
    mock_run_ping_scan.assert_called_once_with(target_scope)
    assert result_hosts == mock_return_value

def test_discover_live_hosts_no_hosts_up(mocker):
    """Test discover_live_hosts when NmapHandler finds no hosts up."""
    mock_return_value = []
    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=mock_return_value)
    target_scope = "10.0.0.0/24"
    result_hosts = engine.discover_live_hosts(target_scope)
    mock_run_ping_scan.assert_called_once_with(target_scope)
    assert result_hosts == []

# --- Test ARKEngine.scan_host_deep ---
def test_scan_host_deep_success_with_scripts(mocker):
    """Test scan_host_deep processing successful results including scripts."""
    # Arrange
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.105", status="up")
    top_ports = 100
    include_os = False
    nse_scripts_arg = "default" # <<< Define the NSE script argument for the test

    mock_nmap_handler_result: Dict[str, Any] = {
        "ports": [Port(number=80, protocol='tcp', status='open', service=Service(name='http'), scripts={"http-title": "Test Title"})],
        "os_matches": [], "mac_address": None, "vendor": None, "uptime_seconds": None,
        "last_boot": None, "distance": None, "host_scripts": {"smb-os": "Win"}
    }
    mock_scan_method = mocker.patch.object(engine.nmap_handler,'run_port_scan_with_services', return_value=mock_nmap_handler_result)

    # Act
    result_host = engine.scan_host_deep(
        input_host,
        top_ports=top_ports,
        include_os_detection=include_os,
        nse_scripts=nse_scripts_arg # <<< CORRECTED: Use nse_scripts parameter
    )

    # Assert
    # Check handler was called correctly
    mock_scan_method.assert_called_once_with(
        input_host.ip,
        top_ports=top_ports,
        include_os_detection=include_os,
        nse_scripts=nse_scripts_arg # <<< CORRECTED: Expect nse_scripts parameter
    )

    # Check Host object population (assertions remain the same)
    assert len(result_host.ports) == 1
    assert result_host.ports[0].scripts and result_host.ports[0].scripts.get("http-title") == "Test Title"
    assert result_host.host_scripts and "Win" in result_host.host_scripts.get("smb-os","")


def test_scan_host_deep_nmap_handler_returns_empty(mocker):
    """Test scan_host_deep when NmapHandler returns empty data (e.g., scan failed)."""
    # Arrange
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.101", status="up")
    mock_nmap_handler_result: Dict[str, Any] = { "ports": [], "os_matches": [], "mac_address": None, "host_scripts": {} }
    mock_scan_method = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_nmap_handler_result)

    # Act
    result_host = engine.scan_host_deep(
        input_host,
        top_ports=100,
        include_os_detection=False,
        nse_scripts=None # <<< CORRECTED: Use nse_scripts parameter (passing None)
    )

    # Assert
    mock_scan_method.assert_called_once_with(
        input_host.ip,
        top_ports=100,
        include_os_detection=False,
        nse_scripts=None # <<< CORRECTED: Expect nse_scripts=None
    )
    assert result_host.ports == []
    assert result_host.os_matches == []
    assert result_host.host_scripts == {}

# --- Test ARKEngine.scan_host_udp ---
def test_scan_host_udp_success(mocker):
    """Test scan_host_udp correctly calls handler and updates host."""
    # Arrange
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.200", status="up", ports=[Port(number=80, protocol='tcp', status='open')])
    top_ports_udp = 50; include_ver_udp = True
    mock_udp_ports = [Port(number=53, protocol='udp', status='open', service=Service(name='domain'))]
    mock_handler_udp_scan = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=mock_udp_ports)

    # Act
    engine.scan_host_udp(input_host, top_ports=top_ports_udp, include_version=include_ver_udp)

    # Assert
    mock_handler_udp_scan.assert_called_once_with(input_host.ip, top_ports=top_ports_udp, include_version=include_ver_udp)
    assert len(input_host.ports) == 2
    assert any(p.number == 80 and p.protocol == 'tcp' for p in input_host.ports)
    assert any(p.number == 53 and p.protocol == 'udp' for p in input_host.ports)

# --- Test ARKEngine.perform_basic_recon ---
def test_perform_basic_recon_workflow_all_features(mocker):
    """ Test the main workflow including TCP, UDP, OS, and NSE scripts """
    # Arrange
    engine = ARKEngine(); target_scope = "192.168.1.0/24"
    top_tcp = 50; top_udp = 25; include_os = True; include_udp = True; nse_script_arg = "default" # Enable all

    # 1. Mock run_ping_scan
    mock_h1 = Host(ip="192.168.1.1"); mock_h2 = Host(ip="192.168.1.5")
    mock_ping = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_h1, mock_h2])

    # 2. Mock run_port_scan_with_services (TCP/OS/Scripts)
    mock_tcp1: Dict[str, Any] = {"ports": [Port(number=80, protocol='tcp', scripts={"http-title":"H1"})], "os_matches":[OSMatch(name="L")], "host_scripts": {"smb":"H1"}, "mac_address":"AA..."}
    mock_tcp2: Dict[str, Any] = {"ports": [Port(number=445, protocol='tcp', scripts={"smb-enum":"H2"})], "os_matches":[OSMatch(name="W")], "host_scripts": {"smb":"H2"}, "mac_address":"BB..."}
    mock_tcp = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', side_effect=[mock_tcp1, mock_tcp2])

    # 3. Mock run_udp_scan
    mock_udp1 = [Port(number=53, protocol='udp')]
    mock_udp2 = [Port(number=161, protocol='udp')]
    mock_udp = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', side_effect=[mock_udp1, mock_udp2])

    # Act
    final_results = engine.perform_basic_recon(
        target_scope,
        top_ports=top_tcp,
        include_os_detection=include_os,
        nse_scripts=nse_script_arg, # <<< CORRECTED: Use nse_scripts parameter
        include_udp_scan=include_udp,
        top_udp_ports=top_udp
    )

    # Assert calls
    mock_ping.assert_called_once_with(target_scope)
    assert mock_tcp.call_count == 2
    assert mock_udp.call_count == 2

    # Check TCP/OS/Script calls specifically - expecting nse_scripts="default"
    mock_tcp.assert_any_call(
        "192.168.1.1", top_ports=top_tcp,
        include_os_detection=include_os, nse_scripts=nse_script_arg # <<< CORRECTED: Expect nse_scripts
    )
    mock_tcp.assert_any_call(
        "192.168.1.5", top_ports=top_tcp,
        include_os_detection=include_os, nse_scripts=nse_script_arg # <<< CORRECTED: Expect nse_scripts
    )
    # Check UDP calls
    mock_udp.assert_any_call("192.168.1.1", top_ports=top_udp, include_version=True)
    mock_udp.assert_any_call("192.168.1.5", top_ports=top_udp, include_version=True)

    # Assert results (abbreviated checks)
    assert len(final_results) == 2
    host1_result = next(h for h in final_results if h.ip == "192.168.1.1")
    host2_result = next(h for h in final_results if h.ip == "192.168.1.5")
    assert any(p.number == 80 and p.protocol == 'tcp' for p in host1_result.ports)
    assert any(p.number == 53 and p.protocol == 'udp' for p in host1_result.ports)
    assert host1_result.host_scripts == {"smb":"H1"}
    assert any(p.number == 445 and p.protocol == 'tcp' for p in host2_result.ports)
    assert any(p.number == 161 and p.protocol == 'udp' for p in host2_result.ports)
    assert host2_result.host_scripts == {"smb":"H2"}

def test_perform_basic_recon_scripts_disabled(mocker):
    """ Test workflow ensures scripts aren't run or passed if nse_scripts is None """
    engine = ARKEngine(); target_scope = "192.168.1.0/2"
    mock_h1 = Host(ip="192.168.1.1")
    mock_ping = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_h1])
    mock_tcp1: Dict[str, Any] = {"ports": [Port(number=80, protocol='tcp')], "os_matches":[], "host_scripts": {}}
    mock_tcp = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_tcp1)
    mock_udp = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=[])

    # Act with nse_scripts=None (default)
    results = engine.perform_basic_recon(target_scope, top_ports=10, include_udp_scan=False, nse_scripts=None) # <<< Pass None

    # Assert TCP scan call did not include nse_scripts=None explicitly
    mock_tcp.assert_called_once_with(
        "192.168.1.1", top_ports=10, include_os_detection=False, nse_scripts=None # <<< Assert None
    )
    assert results[0].host_scripts == {}
    assert results[0].ports[0].scripts is None