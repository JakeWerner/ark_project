import pytest
from unittest.mock import MagicMock, patch # Added patch here if needed for class patch
import subprocess # Needed for CalledProcessError simulation if done here later

# Import the class we are testing
from autork.engine import ARKEngine
# Import the datamodels used in the return types and arguments
from autork.datamodels import Host, Port, Service, OSMatch
# We might need NmapHandler for type hinting or patching the class itself
from autork.nmap_handler import NmapHandler

# --- Test ARKEngine Initialization ---

# Use mocker fixture provided by pytest-mock
def test_arkengine_initialization(mocker):
    """Test that ARKEngine initializes NmapHandler correctly."""
    # Patch the NmapHandler class within the engine module where it's imported
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')

    # Instantiate ARKEngine, which should trigger the patched constructor
    custom_path = "/usr/bin/nmap"
    engine = ARKEngine(nmap_path=custom_path)

    # Assert that NmapHandler was called once with the correct path
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path=custom_path)
    # Assert that the engine's handler is the instance created by the mock
    assert isinstance(engine.nmap_handler, MagicMock) # The constructor now returns a mock

# --- Test ARKEngine.discover_live_hosts ---

def test_discover_live_hosts_success(mocker):
    """Test discover_live_hosts when NmapHandler finds hosts."""
    # Arrange
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    mock_host2 = Host(ip="192.168.1.5", status="up", hostname=None)
    mock_return_value = [mock_host1, mock_host2]

    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(
        engine.nmap_handler,
        'run_ping_scan',
        return_value=mock_return_value
    )

    target_scope = "192.168.1.0/24"

    # Act
    result_hosts = engine.discover_live_hosts(target_scope)

    # Assert
    mock_run_ping_scan.assert_called_once_with(target_scope)
    assert result_hosts == mock_return_value
    assert len(result_hosts) == 2
    assert result_hosts[0].ip == "192.168.1.1"

def test_discover_live_hosts_no_hosts_up(mocker):
    """Test discover_live_hosts when NmapHandler finds no hosts up."""
    # Arrange
    mock_return_value = []

    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(
        engine.nmap_handler,
        'run_ping_scan',
        return_value=mock_return_value
    )

    target_scope = "10.0.0.0/24"

    # Act
    result_hosts = engine.discover_live_hosts(target_scope)

    # Assert
    mock_run_ping_scan.assert_called_once_with(target_scope)
    assert result_hosts == []

# --- Test ARKEngine.scan_host_deep ---

def test_scan_host_deep_success(mocker): # Renamed back to match user traceback
    """Test scan_host_deep processing successful results including scripts."""
    # Arrange
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.101", hostname="host1.local", status="up")
    top_ports = 100
    # Note: The failing traceback showed include_os=True and run_default_scripts=False
    # being passed in the *actual* call, but the test *should* be setting run_scripts=True
    # based on the test name/intent. Let's assume run_scripts should be True here.
    include_os = True
    run_scripts = True # Set to True to test script handling

    mock_nmap_handler_result = {
        "ports": [
            Port(number=22, protocol='tcp', status='open', service=Service(name='ssh'), scripts={"ssh-info": "v2"}),
            Port(number=80, protocol='tcp', status='open', service=Service(name='http'), scripts={"http-title": "Title"})
        ],
        "os_matches": [ OSMatch(name='Linux 5.X', accuracy=95) ],
        "mac_address": "AA:BB:CC:DD:EE:FF", "vendor": "TestVendor",
        "uptime_seconds": 5000, "last_boot": "SomeTime", "distance": 1,
        "host_scripts": {"smb-os": "Win"}
    }

    mock_scan_method = mocker.patch.object(
        engine.nmap_handler,
        'run_port_scan_with_services',
        return_value=mock_nmap_handler_result
    )

    # Act
    result_host = engine.scan_host_deep(
        input_host, # Pass host object
        top_ports=top_ports,
        include_os_detection=include_os,
        run_default_scripts=run_scripts # Pass True
    )

    # Assert
    # Check that the NmapHandler method was called correctly
    # *** THIS IS THE CORRECTED ASSERTION ***
    mock_scan_method.assert_called_once_with(
        input_host.ip,
        top_ports=top_ports,
        include_os_detection=include_os,
        run_default_scripts=run_scripts # Now expecting run_default_scripts=True
    )

    # Check Host object population
    assert result_host.ip == "192.168.1.101"
    assert result_host.hostname == "host1.local" # Check it preserved existing info
    assert len(result_host.ports) == 2
    assert result_host.ports[0].number == 22
    assert result_host.ports[0].scripts is not None
    assert result_host.ports[0].scripts.get("ssh-info") == "v2"
    assert len(result_host.os_matches) == 1
    assert result_host.os_matches[0].name == "Linux 5.X"
    assert result_host.mac_address == "AA:BB:CC:DD:EE:FF"
    assert result_host.host_scripts == {"smb-os": "Win"}


def test_scan_host_deep_nmap_handler_returns_empty(mocker):
    """Test scan_host_deep when NmapHandler returns empty data (e.g., scan failed)."""
    # Arrange
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.101", status="up")

    mock_nmap_handler_result = { "ports": [], "os_matches": [], "mac_address": None, "host_scripts": {} } # Empty result

    mock_scan_method = mocker.patch.object(
        engine.nmap_handler,
        'run_port_scan_with_services',
        return_value=mock_nmap_handler_result
    )

    # Act
    result_host = engine.scan_host_deep(input_host, top_ports=100, include_os_detection=False, run_default_scripts=False)

    # Assert
    mock_scan_method.assert_called_once()
    assert result_host.ports == []
    assert result_host.os_matches == []
    assert result_host.mac_address is None
    assert result_host.host_scripts == {}

# --- Test ARKEngine.perform_basic_recon ---

def test_perform_basic_recon_workflow_with_udp(mocker): # Keeping original name from traceback
    """ Test the main workflow including checks for correct calls with flags. """
    # Arrange
    engine = ARKEngine()
    target_scope = "192.168.1.0/24"
    top_tcp_ports = 50
    top_udp_ports = 25
    include_os = True
    include_udp = True
    run_scripts = True # <<< Enable scripts in test setup

    # 1. Mock run_ping_scan
    mock_host1 = Host(ip="192.168.1.1", status="up")
    mock_host2 = Host(ip="192.168.1.5", status="up")
    mock_ping_scan_return = [mock_host1, mock_host2]
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=mock_ping_scan_return)

    # 2. Mock run_port_scan_with_services (TCP/OS/Scripts)
    mock_tcp_scan_result_host1 = {
        "ports": [Port(number=80, protocol='tcp', scripts={"http-title": "H1"})],
        "os_matches": [OSMatch(name="Linux")], "mac_address": "AA...",
        "host_scripts": {"smb-stuff": "H1 Info"}
    }
    mock_tcp_scan_result_host2 = {
        "ports": [Port(number=445, protocol='tcp', scripts={"smb-info": "Share data"})],
        "os_matches": [OSMatch(name="Windows")], "mac_address": "BB...",
        "host_scripts": {"smb-stuff": "H2 Info"}
    }
    mock_run_tcp_port_scan = mocker.patch.object(
        engine.nmap_handler,
        'run_port_scan_with_services',
        side_effect=[mock_tcp_scan_result_host1, mock_tcp_scan_result_host2]
    )

    # 3. Mock run_udp_scan
    mock_udp_scan_result_host1 = [Port(number=53, protocol='udp', status='open')]
    mock_udp_scan_result_host2 = [Port(number=161, protocol='udp', status='open|filtered')]
    mock_run_udp_scan = mocker.patch.object(
        engine.nmap_handler, 'run_udp_scan',
        side_effect=[mock_udp_scan_result_host1, mock_udp_scan_result_host2]
    )

    # Act
    final_results = engine.perform_basic_recon(
        target_scope,
        top_ports=top_tcp_ports,
        include_os_detection=include_os,
        run_default_scripts=run_scripts, # <<< Pass True here
        include_udp_scan=include_udp,
        top_udp_ports=top_udp_ports
    )

    # Assert
    mock_run_ping_scan.assert_called_once_with(target_scope)
    assert mock_run_tcp_port_scan.call_count == 2
    assert mock_run_udp_scan.call_count == 2

    # Check TCP/OS/Script calls specifically - expecting run_default_scripts=True
    # *** THIS IS THE CORRECTED ASSERTION for this test ***
    mock_run_tcp_port_scan.assert_any_call(
        "192.168.1.1", top_ports=top_tcp_ports,
        include_os_detection=include_os, run_default_scripts=run_scripts # Expect True
    )
    mock_run_tcp_port_scan.assert_any_call(
        "192.168.1.5", top_ports=top_tcp_ports,
        include_os_detection=include_os, run_default_scripts=run_scripts # Expect True
    )
    # Check UDP calls
    mock_run_udp_scan.assert_any_call("192.168.1.1", top_ports=top_udp_ports, include_version=True)
    mock_run_udp_scan.assert_any_call("192.168.1.5", top_ports=top_udp_ports, include_version=True)

    # Check final results (abbreviated checks for brevity)
    assert len(final_results) == 2
    host1_result = next(h for h in final_results if h.ip == "192.168.1.1")
    host2_result = next(h for h in final_results if h.ip == "192.168.1.5")
    assert any(p.number == 80 and p.protocol == 'tcp' for p in host1_result.ports)
    assert any(p.number == 53 and p.protocol == 'udp' for p in host1_result.ports)
    assert host1_result.host_scripts == {"smb-stuff": "H1 Info"}
    assert any(p.number == 445 and p.protocol == 'tcp' for p in host2_result.ports)
    assert any(p.number == 161 and p.protocol == 'udp' for p in host2_result.ports)
    assert host2_result.host_scripts == {"smb-stuff": "H2 Info"}