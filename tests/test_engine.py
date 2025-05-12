# tests/test_engine.py
import pytest
from unittest.mock import MagicMock, patch
import subprocess # Keep import in case future tests need it directly
import json
import csv
from pathlib import Path
from dataclasses import asdict, is_dataclass
import logging

from autork.engine import ARKEngine
from autork.nmap_handler import NmapHandler # Import for spec in mock
from autork.datamodels import Host, Port, Service, OSMatch
from typing import List, Dict, Any, Optional, Type

# --- Helper to create sample scan data (4 hosts, IPv4) ---
def get_sample_scan_results() -> List[Host]:
    """Generates sample Host data for testing export and save/load."""
    host1_port_scripts = {"http-methods": "GET, POST"}
    host1_host_scripts = {"smb-os-discovery": "OS: Windows 10", "http-title": "Welcome Page"}
    host1 = Host(
        ip="192.168.1.101", hostname="server1.example.com", status="up",
        ports=[
            Port(number=80, protocol="tcp", status="open", service=Service(name="http", product="nginx"), scripts=host1_port_scripts),
            Port(number=443, protocol="tcp", status="open", service=Service(name="https")),
            Port(number=53, protocol="udp", status="open|filtered", service=Service(name="domain"))
        ],
        os_matches=[OSMatch(name="Linux 5.x", accuracy=95)], mac_address="AA:BB:CC:00:11:22", vendor="TestVendor1",
        host_scripts=host1_host_scripts, uptime_seconds=123, last_boot="prev boot", distance=2
    )
    host2 = Host(ip="192.168.1.102", hostname="server2.example.com", status="up", ports=[Port(number=22, protocol="tcp", status="open", service=Service(name="ssh"))])
    host3_filtered_port = Host(ip="192.168.1.103", hostname="server3.example.com", status="up", ports=[Port(number=135, protocol="tcp", status="filtered", reason="no-response")], host_scripts={"info":"Host3"})
    host4_no_ports_at_all = Host(ip="192.168.1.104", hostname="server4.example.com", status="up", ports=[])
    return [host1, host2, host3_filtered_port, host4_no_ports_at_all]

def get_sample_ipv6_host_for_engine_tests(ip="2001:db8::a") -> Host:
    """Generates a sample IPv6 Host object for testing."""
    return Host(ip=ip, status="up", hostname="ipv6.test.com")

@pytest.fixture
def engine_instance(mocker):
    """Provides an ARKEngine instance with a mocked NmapHandler."""
    engine = ARKEngine()
    # Mock the NmapHandler instance within ARKEngine
    mocker.patch.object(engine, 'nmap_handler', MagicMock(spec=NmapHandler))
    return engine

# --- Test ARKEngine Initialization ---
def test_arkengine_initialization(mocker):
    """Tests ARKEngine initialization and NmapHandler instantiation."""
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    ARKEngine(nmap_path="/custom/nmap")
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path="/custom/nmap")

# --- Test ARKEngine.discover_live_hosts ---
def test_discover_live_hosts_ipv4_with_options(engine_instance: ARKEngine, mocker):
    """Tests host discovery for IPv4 with various target management options."""
    mock_host1 = Host(ip="192.168.1.1", status="up")
    engine_instance.nmap_handler.run_ping_scan.return_value = [mock_host1]
    params = {
        "target_scope":"1.1.1.0/24", "timing_template":2, "input_target_file":"tf",
        "exclude_targets":"et", "exclude_file":"ef", "ipv6":False
    }
    results = engine_instance.discover_live_hosts(**params)
    engine_instance.nmap_handler.run_ping_scan.assert_called_once_with(**params)
    assert results == [mock_host1]

def test_discover_live_hosts_ipv6(engine_instance: ARKEngine, mocker):
    """Tests host discovery for IPv6."""
    target_ipv6_scope = "2001:db8::/64"
    mock_ipv6_hosts = [Host(ip="2001:db8::1", status="up")]
    engine_instance.nmap_handler.run_ping_scan.return_value = mock_ipv6_hosts
    results = engine_instance.discover_live_hosts(target_scope=target_ipv6_scope, ipv6=True)
    # Assert call to handler, engine uses defaults for None params
    engine_instance.nmap_handler.run_ping_scan.assert_called_once_with(
        target_scope=target_ipv6_scope, timing_template=None,
        input_target_file=None, exclude_targets=None, exclude_file=None,
        ipv6=True
    )
    assert results == mock_ipv6_hosts

def test_discover_live_hosts_no_hosts_found(engine_instance: ARKEngine, mocker):
    """Tests host discovery when the handler returns no live hosts."""
    engine_instance.nmap_handler.run_ping_scan.return_value = []
    results = engine_instance.discover_live_hosts(target_scope="10.0.0.0/24", ipv6=False)
    engine_instance.nmap_handler.run_ping_scan.assert_called_once()
    assert results == []

# --- Test ARKEngine.scan_host_deep ---
def test_scan_host_deep_ipv4_all_features(engine_instance: ARKEngine, mocker):
    """Tests deep scan on an IPv4 host with all features enabled."""
    input_host = Host(ip="192.168.1.105", status="up") # IPv4
    params = {
        "top_ports":10, "include_os_detection":True, "nse_scripts":"default,vuln",
        "nse_script_args":"a=b,c=d", "timing_template":3, "tcp_scan_type":"S"
    }
    # Mock handler to return some data matching features
    mock_handler_res: Dict[str, Any] = {
        "ports": [Port(number=80)], "os_matches":[OSMatch(name="Linux")], "host_scripts": {"s1":"o1"}
    }
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = mock_handler_res
    
    returned_host = engine_instance.scan_host_deep(input_host, **params)
    
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(
        input_host.ip, **params, ipv6=False # Engine derives ipv6=False from IPv4
    )
    # Check if host object was updated (basic check)
    assert returned_host is input_host # Should update in place
    assert len(returned_host.ports) > 0
    assert len(returned_host.os_matches) > 0
    assert len(returned_host.host_scripts) > 0

def test_scan_host_deep_ipv6_target(engine_instance: ARKEngine, mocker):
    """Tests deep scan on an IPv6 host."""
    ipv6_host_obj = get_sample_ipv6_host_for_engine_tests()
    mock_scan_data: Dict[str, Any] = {"ports": [Port(number=80, protocol="tcp", status="open")]}
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = mock_scan_data
    
    engine_instance.scan_host_deep(ipv6_host_obj, top_ports=10, tcp_scan_type="S")
    
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(
        ipv6_host_obj.ip, top_ports=10, include_os_detection=False,
        nse_scripts=None, nse_script_args=None, timing_template=None,
        tcp_scan_type="S", ipv6=True # Engine should detect ipv6=True from IP
    )

def test_scan_host_deep_empty_result(engine_instance: ARKEngine, mocker):
    """Tests deep scan when the handler returns an empty dictionary."""
    input_host = Host(ip="192.168.1.105", status="up")
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = {} # Empty result
    
    returned_host = engine_instance.scan_host_deep(input_host, top_ports=10)
    
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(
        input_host.ip, top_ports=10, include_os_detection=False, nse_scripts=None,
        nse_script_args=None, timing_template=None, tcp_scan_type=None, ipv6=False
    )
    assert returned_host.ports == [] # Check ports were cleared/not populated

# --- Test ARKEngine.scan_host_udp ---
def test_scan_host_udp_ipv4(engine_instance: ARKEngine, mocker):
    """Tests UDP scan on an IPv4 host."""
    input_host = Host(ip="192.168.1.101", status="up")
    mock_udp_ports = [Port(number=53, protocol="udp", status="open|filtered")]
    engine_instance.nmap_handler.run_udp_scan.return_value = mock_udp_ports

    engine_instance.scan_host_udp(input_host, top_ports=5, timing_template=1)

    engine_instance.nmap_handler.run_udp_scan.assert_called_once_with(
        input_host.ip, top_ports=5, include_version=True,
        timing_template=1, ipv6=False # Expect ipv6=False derived from IP
    )
    # Check if host object was updated (should have only the UDP port now)
    assert len(input_host.ports) == 1
    assert input_host.ports[0].protocol == 'udp'

def test_scan_host_udp_ipv6_target(engine_instance: ARKEngine, mocker):
    """Tests UDP scan on an IPv6 host."""
    ipv6_host_obj = get_sample_ipv6_host_for_engine_tests()
    mock_udp_ports = [Port(number=53, protocol="udp", status="open|filtered")]
    engine_instance.nmap_handler.run_udp_scan.return_value = mock_udp_ports

    engine_instance.scan_host_udp(ipv6_host_obj, top_ports=5, timing_template=1)

    engine_instance.nmap_handler.run_udp_scan.assert_called_once_with(
        ipv6_host_obj.ip, top_ports=5, include_version=True,
        timing_template=1, ipv6=True # Expect ipv6=True derived from IP
    )

# --- Test ARKEngine.perform_basic_recon (Comprehensive Tests) ---
def test_perform_basic_recon_all_features_enabled_ipv4(engine_instance: ARKEngine, mocker):
    """Tests the main recon workflow with all options enabled for IPv4."""
    target_scope_val = "192.168.1.0/24"
    recon_params_call = {
        "top_ports": 50, "include_os_detection": True, "nse_scripts": "default",
        "nse_script_args": "arg=val", "include_udp_scan": True, "top_udp_ports": 25,
        "timing_template": 2, "tcp_scan_type": "S", "ipv6": False,
        "input_target_file": None, "exclude_targets": None, "exclude_file": None
    }
    expected_discover_args = {
        "target_scope": target_scope_val, "timing_template": recon_params_call["timing_template"],
        "input_target_file": None, "exclude_targets": None, "exclude_file": None, "ipv6": False
    }
    expected_deep_scan_handler_args = {
        "top_ports": recon_params_call["top_ports"], "include_os_detection": recon_params_call["include_os_detection"],
        "nse_scripts": recon_params_call["nse_scripts"], "nse_script_args": recon_params_call["nse_script_args"],
        "timing_template": recon_params_call["timing_template"], "tcp_scan_type": recon_params_call["tcp_scan_type"],
        "ipv6": False # Derived from IPv4 host object
    }
    expected_udp_scan_handler_args = {
        "top_ports": recon_params_call["top_udp_ports"], "include_version": True,
        "timing_template": recon_params_call["timing_template"], "ipv6": False # Derived
    }

    mock_h1 = Host(ip="192.168.1.1"); mock_h2 = Host(ip="192.168.1.5")
    # Mock the discover_live_hosts method *on the instance*
    mocker.patch.object(engine_instance, 'discover_live_hosts', return_value=[mock_h1, mock_h2])
    # Configure the mocked nmap_handler (accessed via engine_instance.nmap_handler)
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = {"ports": []}
    engine_instance.nmap_handler.run_udp_scan.return_value = []

    engine_instance.perform_basic_recon(target_scope=target_scope_val, **recon_params_call)

    engine_instance.discover_live_hosts.assert_called_once_with(**expected_discover_args)
    assert engine_instance.nmap_handler.run_port_scan_with_services.call_count == 2
    engine_instance.nmap_handler.run_port_scan_with_services.assert_any_call(mock_h1.ip, **expected_deep_scan_handler_args)
    engine_instance.nmap_handler.run_port_scan_with_services.assert_any_call(mock_h2.ip, **expected_deep_scan_handler_args)
    if recon_params_call["include_udp_scan"]:
        assert engine_instance.nmap_handler.run_udp_scan.call_count == 2
        engine_instance.nmap_handler.run_udp_scan.assert_any_call(mock_h1.ip, **expected_udp_scan_handler_args)
        engine_instance.nmap_handler.run_udp_scan.assert_any_call(mock_h2.ip, **expected_udp_scan_handler_args)


def test_perform_basic_recon_minimal_options_ipv4(engine_instance: ARKEngine, mocker):
    """Tests the main recon workflow with minimal options for IPv4."""
    target_scope_val = "192.168.1.10"
    mock_h1 = Host(ip="192.168.1.10")
    mocker.patch.object(engine_instance, 'discover_live_hosts', return_value=[mock_h1])
    # Expected args for discover_live_hosts call
    expected_discover_args = {
        "target_scope": target_scope_val, "timing_template": None,
        "input_target_file": None, "exclude_targets": None, "exclude_file": None, "ipv6": False
    }
    # Expected args for nmap_handler.run_port_scan_with_services call
    expected_deep_scan_handler_args = {
        "top_ports": 100, "include_os_detection": False, "nse_scripts": None,
        "nse_script_args": None, "timing_template": None, "tcp_scan_type": None, "ipv6": False
    }

    engine_instance.perform_basic_recon(target_scope=target_scope_val) # All optional args use defaults

    engine_instance.discover_live_hosts.assert_called_once_with(**expected_discover_args)
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(mock_h1.ip, **expected_deep_scan_handler_args)
    engine_instance.nmap_handler.run_udp_scan.assert_not_called() # UDP defaults to False


def test_perform_basic_recon_ipv6_workflow(engine_instance: ARKEngine, mocker):
    """Tests the main recon workflow for IPv6."""
    target_ipv6_scope = "2001:db8::/120"
    recon_opts_ipv6 = {
        "top_ports":10, "include_os_detection":False, "nse_scripts":"http-title", 
        "nse_script_args":None, "include_udp_scan":True, "top_udp_ports":5,
        "timing_template":1, "tcp_scan_type":"T", "ipv6": True # IPv6 scan
    }
    expected_discover_args_ipv6 = {
        "target_scope":target_ipv6_scope, "timing_template":recon_opts_ipv6["timing_template"],
        "input_target_file":None, "exclude_targets":None, "exclude_file":None, "ipv6":True
    }
    expected_deep_scan_handler_args_ipv6 = {
        "top_ports":recon_opts_ipv6["top_ports"], "include_os_detection":recon_opts_ipv6["include_os_detection"],
        "nse_scripts":recon_opts_ipv6["nse_scripts"], "nse_script_args":recon_opts_ipv6["nse_script_args"],
        "timing_template":recon_opts_ipv6["timing_template"], "tcp_scan_type":recon_opts_ipv6["tcp_scan_type"],
        "ipv6": True # Derived from IPv6 host
    }
    expected_udp_scan_handler_args_ipv6 = {
        "top_ports":recon_opts_ipv6["top_udp_ports"], "include_version":True,
        "timing_template":recon_opts_ipv6["timing_template"], "ipv6":True # Derived
    }

    mock_ipv6_host = Host(ip="2001:db8::cafe")
    mocker.patch.object(engine_instance, 'discover_live_hosts', return_value=[mock_ipv6_host])
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = {"ports": []}
    engine_instance.nmap_handler.run_udp_scan.return_value = []

    engine_instance.perform_basic_recon(target_scope=target_ipv6_scope, **recon_opts_ipv6)

    engine_instance.discover_live_hosts.assert_called_once_with(**expected_discover_args_ipv6)
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(
        mock_ipv6_host.ip, **expected_deep_scan_handler_args_ipv6
    )
    if recon_opts_ipv6["include_udp_scan"]:
        engine_instance.nmap_handler.run_udp_scan.assert_called_once_with(
            mock_ipv6_host.ip, **expected_udp_scan_handler_args_ipv6
        )

# --- EXPORT TESTS (Comprehensive) ---
@pytest.fixture
def engine_instance_for_export(mocker): # Fixture specifically for export/save/load if needed, otherwise reuse engine_instance
    engine = ARKEngine()
    mocker.patch.object(engine, 'nmap_handler', MagicMock(spec=NmapHandler))
    return engine

def test_export_to_json_success(engine_instance_for_export: ARKEngine, tmp_path: Path):
    """Tests successful export to JSON."""
    sample_results = get_sample_scan_results()
    json_file = tmp_path / "output.json"
    engine_instance_for_export.export_to_json(sample_results, str(json_file))
    assert json_file.exists()
    with open(json_file, 'r') as f:
        loaded_data = json.load(f)
    # Use asdict for comparison, assuming internal converter is for loading mostly
    expected_data = [asdict(host) for host in sample_results]
    assert loaded_data == expected_data

def test_export_to_json_io_error(engine_instance_for_export: ARKEngine, mocker, caplog):
    """Tests JSON export failure due to IOError."""
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Disk full"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export.export_to_json(sample_results, "restricted.json")
    assert "IOError exporting results to JSON file restricted.json: Disk full" in caplog.text

def test_export_to_csv_success(engine_instance_for_export: ARKEngine, tmp_path: Path):
    """Tests successful export to CSV."""
    sample_results = get_sample_scan_results() # This sample produces 6 data rows
    csv_file = tmp_path / "output.csv"
    engine_instance_for_export.export_to_csv(sample_results, str(csv_file))
    assert csv_file.exists()
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        rows = list(reader)
    expected_headers = [
        "Host IP", "Hostname", "Host Status", "MAC Address", "MAC Vendor",
        "OS Guesses", "Host Scripts (Summary)", "Port Number", "Port Protocol", "Port Status", "Port Reason",
        "Service Name", "Service Product", "Service Version", "Service ExtraInfo", "Port Scripts (Summary)"
    ]
    assert rows[0] == expected_headers
    assert len(rows) == 1 + 6 # 1 header + 6 data rows from the 4-host sample
    # Basic data check
    assert rows[1][0] == "192.168.1.101" # Host1 IP
    assert rows[1][7] == "80" # Host1 Port 80

def test_export_to_csv_io_error(engine_instance_for_export: ARKEngine, mocker, caplog):
    """Tests CSV export failure due to IOError."""
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Permission denied"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export.export_to_csv(sample_results, "restricted.csv")
    assert "IOError exporting results to CSV file restricted.csv: Permission denied" in caplog.text

# --- SAVE/LOAD TESTS (Comprehensive) ---
def test_save_and_load_scan_results_success(engine_instance_for_export: ARKEngine, tmp_path: Path):
    """Tests saving and loading back scan results successfully."""
    sample_data = get_sample_scan_results()
    save_file = tmp_path / "ark_session_test.json"
    engine_instance_for_export.save_scan_results(sample_data, str(save_file))
    assert save_file.exists()
    loaded_data = engine_instance_for_export.load_scan_results(str(save_file))
    assert isinstance(loaded_data, list)
    assert len(loaded_data) == len(sample_data)
    # Compare structure and values using asdict for robust comparison
    original_as_dicts = [asdict(host) for host in sample_data]
    loaded_as_dicts = [asdict(host) for host in loaded_data]
    assert original_as_dicts == loaded_as_dicts

def test_load_scan_results_file_not_found(engine_instance_for_export: ARKEngine, tmp_path: Path, caplog):
    """Tests loading from a non-existent file."""
    non_existent_file = tmp_path / "not_real.json"
    with caplog.at_level(logging.ERROR):
        loaded_data = engine_instance_for_export.load_scan_results(str(non_existent_file))
    assert loaded_data == []
    assert f"File not found: {non_existent_file}" in caplog.text

def test_load_scan_results_invalid_json(engine_instance_for_export: ARKEngine, tmp_path: Path, caplog):
    """Tests loading from a file with invalid JSON."""
    invalid_json_file = tmp_path / "invalid.json"
    invalid_json_file.write_text("{not json,,,")
    with caplog.at_level(logging.ERROR):
        loaded_data = engine_instance_for_export.load_scan_results(str(invalid_json_file))
    assert loaded_data == []
    assert f"Error decoding JSON from {invalid_json_file}" in caplog.text

def test_save_scan_results_io_error(engine_instance_for_export: ARKEngine, mocker, caplog): # Use the correct fixture name
    """Tests saving failure due to IOError during the underlying JSON export."""
    # --- CORRECTED: Ensure sample_results (or sample_data) is defined ---
    sample_results = get_sample_scan_results() 
    # --- END CORRECTION ---
    
    # Mock open to raise IOError specifically for the save operation
    mocker.patch('builtins.open', side_effect=IOError("Cannot write"))

    with caplog.at_level(logging.ERROR):
        # Use the defined variable name (sample_results in this case)
        engine_instance_for_export.save_scan_results(sample_results, "restricted_save.json") 
    
    # Check for the error logged by export_to_json, as save_scan_results calls it
    # (or the error from save_scan_results' own except block if export_to_json re-raises)
    # Based on current ARKEngine.save_scan_results, it calls export_to_json, which logs its own specific error.
    assert "IOError exporting results to JSON file restricted_save.json: Cannot write" in caplog.text or \
           "Failed to save scan results to restricted_save.json (error during underlying export): Cannot write" in caplog.text or \
           "An unexpected error occurred during JSON export to restricted_save.json: Cannot write" in caplog.text

def test_load_scan_results_empty_file(engine_instance_for_export: ARKEngine, tmp_path: Path, caplog):
    """Tests loading from an empty file (causes JSONDecodeError)."""
    empty_file = tmp_path / "empty.json"
    empty_file.touch()
    with caplog.at_level(logging.ERROR):
        loaded_data = engine_instance_for_export.load_scan_results(str(empty_file))
    assert loaded_data == []
    assert f"Error decoding JSON from {empty_file}" in caplog.text

def test_load_scan_results_not_a_list(engine_instance_for_export: ARKEngine, tmp_path: Path, caplog):
    """Tests loading from a file containing a JSON object, not a list."""
    not_list_file = tmp_path / "not_list.json"
    not_list_file.write_text('{"ip": "1.1.1.1"}') # Write a JSON object
    with caplog.at_level(logging.ERROR):
        loaded_data = engine_instance_for_export.load_scan_results(str(not_list_file))
    assert loaded_data == []
    assert f"Invalid format in {not_list_file}: Expected list." in caplog.text