import pytest
from unittest.mock import MagicMock # Can still use MagicMock if needed

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
    # Create mock Host objects that run_ping_scan should return
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    mock_host2 = Host(ip="192.168.1.5", status="up", hostname=None)
    mock_return_value = [mock_host1, mock_host2]
    
    # Patch the run_ping_scan method on the NmapHandler *instance*
    # We need an ARKEngine instance first to patch its handler's method
    engine = ARKEngine() # Let it initialize normally first
    mock_run_ping_scan = mocker.patch.object(
        engine.nmap_handler, 
        'run_ping_scan', 
        return_value=mock_return_value
    )
    
    target_scope = "192.168.1.0/24"

    # Act
    result_hosts = engine.discover_live_hosts(target_scope)

    # Assert
    # Check that the mocked method was called correctly
    mock_run_ping_scan.assert_called_once_with(target_scope)
    # Check that the result is what the mock returned
    assert result_hosts == mock_return_value
    assert len(result_hosts) == 2
    assert result_hosts[0].ip == "192.168.1.1"

def test_discover_live_hosts_no_hosts_up(mocker):
    """Test discover_live_hosts when NmapHandler finds no hosts up."""
    # Arrange
    mock_return_value = [] # Simulate NmapHandler finding no hosts up
    
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

def test_scan_host_deep_success(mocker):
    """Test scan_host_deep processing successful NmapHandler results."""
    # Arrange
    engine = ARKEngine()
    # The input Host object, potentially from discover_live_hosts
    input_host = Host(ip="192.168.1.101", hostname="host1.local", status="up") 
    top_ports = 100
    include_os = True
    
    # Define the mock data structure NmapHandler would return
    mock_nmap_handler_result = {
        "ports": [
            Port(number=22, protocol='tcp', status='open', service=Service(name='ssh')),
            Port(number=80, protocol='tcp', status='open', service=Service(name='http'))
        ],
        "os_matches": [
            OSMatch(name='Linux 5.X', accuracy=95)
        ],
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "vendor": "TestVendor",
        "uptime_seconds": 5000,
        "last_boot": "SomeTime",
        "distance": 1
    }
    
    mock_scan_method = mocker.patch.object(
        engine.nmap_handler, 
        'run_port_scan_with_services', 
        return_value=mock_nmap_handler_result
    )

    # Act
    result_host = engine.scan_host_deep(input_host, top_ports=top_ports, include_os_detection=include_os)

    # Assert
    # Check that the NmapHandler method was called correctly
    mock_scan_method.assert_called_once_with(
        input_host.ip, 
        top_ports=top_ports, 
        include_os_detection=include_os
    )
    
    # Check that the returned Host object was populated correctly
    assert result_host.ip == "192.168.1.101"
    assert result_host.hostname == "host1.local" # Check it preserved existing info
    assert len(result_host.ports) == 2
    assert result_host.ports[0].number == 22
    assert result_host.ports[0].service.name == "ssh"
    assert len(result_host.os_matches) == 1
    assert result_host.os_matches[0].name == "Linux 5.X"
    assert result_host.mac_address == "AA:BB:CC:DD:EE:FF"
    assert result_host.uptime_seconds == 5000
    assert result_host.distance == 1

def test_scan_host_deep_nmap_handler_returns_empty(mocker):
    """Test scan_host_deep when NmapHandler returns empty data (e.g., scan failed)."""
    # Arrange
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.101", status="up") 
    
    mock_nmap_handler_result = { "ports": [], "os_matches": [], "mac_address": None } # Empty result
    
    mock_scan_method = mocker.patch.object(
        engine.nmap_handler, 
        'run_port_scan_with_services', 
        return_value=mock_nmap_handler_result
    )

    # Act
    result_host = engine.scan_host_deep(input_host, top_ports=100, include_os_detection=False)

    # Assert
    mock_scan_method.assert_called_once()
    assert result_host.ports == []
    assert result_host.os_matches == []
    assert result_host.mac_address is None

# --- Test ARKEngine.perform_basic_recon (Example Stub) ---

# Testing this requires mocking both run_ping_scan and run_port_scan_with_services
# It might involve mocker.patch.object multiple times or setting side_effects
# This test is more complex, let's start with the above ones.
def test_perform_basic_recon_workflow(mocker):
    # Arrange
    engine = ARKEngine()
    target_scope = "192.168.1.0/24"
    top_ports = 50
    include_os = True

    # 1. Mock discover_live_hosts's underlying call (run_ping_scan)
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    mock_host2 = Host(ip="192.168.1.5", status="up", hostname=None)
    mock_ping_scan_return = [mock_host1, mock_host2]
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=mock_ping_scan_return)

    # 2. Mock scan_host_deep's underlying call (run_port_scan_with_services)
    # We need it to return different results based on the IP maybe, or just generic results
    mock_scan_result_host1 = { "ports": [Port(number=80)], "os_matches": [OSMatch(name="Linux")], "mac_address": "AA..." }
    mock_scan_result_host2 = { "ports": [Port(number=443)], "os_matches": [OSMatch(name="Windows")], "mac_address": "BB..." }
    
    # Use side_effect to return different values for consecutive calls
    mock_run_port_scan = mocker.patch.object(
        engine.nmap_handler, 
        'run_port_scan_with_services', 
        side_effect=[mock_scan_result_host1, mock_scan_result_host2] # Return these in order
    )

    # Act
    final_results = engine.perform_basic_recon(target_scope, top_ports=top_ports, include_os_detection=include_os)

    # Assert
    # Check run_ping_scan was called
    mock_run_ping_scan.assert_called_once_with(target_scope)

    # Check run_port_scan_with_services was called twice (once for each live host)
    assert mock_run_port_scan.call_count == 2
    mock_run_port_scan.assert_any_call("192.168.1.1", top_ports=top_ports, include_os_detection=include_os)
    mock_run_port_scan.assert_any_call("192.168.1.5", top_ports=top_ports, include_os_detection=include_os)
    
    # Check the final results list
    assert len(final_results) == 2
    assert final_results[0].ip == "192.168.1.1"
    assert final_results[0].ports[0].number == 80
    assert final_results[0].os_matches[0].name == "Linux"
    assert final_results[0].mac_address == "AA..." 
    
    assert final_results[1].ip == "192.168.1.5"
    assert final_results[1].ports[0].number == 443
    assert final_results[1].os_matches[0].name == "Windows"
    assert final_results[1].mac_address == "BB..."