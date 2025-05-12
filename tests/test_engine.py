# tests/test_engine.py
import pytest
from unittest.mock import MagicMock, patch
import subprocess
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
    # ... (Full sample data as in previous response) ...
    host1_port_scripts = {"http-methods": "GET, POST"}
    host1_host_scripts = {"smb-os-discovery": "OS: Windows 10", "http-title": "Welcome Page"}
    host1 = Host(ip="192.168.1.101", hostname="server1.example.com", status="up", ports=[Port(number=80, protocol="tcp", status="open", service=Service(name="http", product="nginx"), scripts=host1_port_scripts, reason="syn-ack"), Port(number=443, protocol="tcp", status="open", service=Service(name="https")), Port(number=53, protocol="udp", status="open|filtered", service=Service(name="domain"), reason="udp-response")], os_matches=[OSMatch(name="Linux 5.x", accuracy=95)], mac_address="AA:BB:CC:00:11:22", vendor="TestVendor1", host_scripts=host1_host_scripts, uptime_seconds=123, last_boot="prev boot", distance=2)
    host2 = Host(ip="192.168.1.102", hostname="server2.example.com", status="up", ports=[Port(number=22, protocol="tcp", status="open", service=Service(name="ssh"), reason="syn-ack")])
    host3_filtered_port = Host(ip="192.168.1.103", hostname="server3.example.com", status="up", ports=[Port(number=135, protocol="tcp", status="filtered", reason="no-response")], host_scripts={"info":"Host3"})
    host4_no_ports_at_all = Host(ip="192.168.1.104", hostname="server4.example.com", status="up", ports=[])
    return [host1, host2, host3_filtered_port, host4_no_ports_at_all]

def get_sample_ipv6_host_for_engine_tests(ip="2001:db8::a") -> Host:
    return Host(ip=ip, status="up", hostname="ipv6.test.com")

@pytest.fixture
def engine_instance(mocker):
    engine = ARKEngine()
    engine.nmap_handler = MagicMock(spec=NmapHandler) # Replace the handler with a mock
    engine.nmap_handler.run_ping_scan.return_value = [] # Default mock returns
    engine.nmap_handler.run_port_scan_with_services.return_value = {"ports": [], "os_matches": [], "host_scripts": {}}
    engine.nmap_handler.run_udp_scan.return_value = []
    return engine

# --- Test ARKEngine Initialization ---
def test_arkengine_initialization(mocker):
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    ARKEngine(nmap_path="/custom/nmap")
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path="/custom/nmap")

# --- Test ARKEngine.discover_live_hosts ---
def test_discover_live_hosts_all_params(engine_instance: ARKEngine):
    mock_host1 = Host(ip="192.168.1.1", status="up")
    engine_instance.nmap_handler.run_ping_scan.return_value = [mock_host1]
    call_args = {
        "target_scope":"1.1.1.0/24", "timing_template":2, "input_target_file":"tf",
        "exclude_targets":"et", "exclude_file":"ef", "ipv6":False
    }
    results = engine_instance.discover_live_hosts(**call_args)
    engine_instance.nmap_handler.run_ping_scan.assert_called_once_with(**call_args)
    assert results == [mock_host1]

# --- Test ARKEngine.scan_host_deep ---
def test_scan_host_deep_all_features_enabled(engine_instance: ARKEngine): # CORRECTED CALL
    input_host = Host(ip="192.168.1.105", status="up") # IPv4
    call_params_to_engine = {
        "top_ports":10, "include_os_detection":True, "nse_scripts":"default",
        "nse_script_args":"a=b", "timing_template":3, "tcp_scan_type":"S",
        "include_reason": True
    }
    expected_args_to_handler = {
        "host_ip": input_host.ip, **call_params_to_engine, "ipv6": False
    }
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = {"ports": [Port(number=80)]}
    
    engine_instance.scan_host_deep(input_host, **call_params_to_engine)
    
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(**expected_args_to_handler)

def test_scan_host_deep_ipv6_target_passes_ipv6_flag(engine_instance: ARKEngine): # CORRECTED CALL
    ipv6_host_obj = get_sample_ipv6_host_for_engine_tests()
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = {"ports": []}
    
    engine_instance.scan_host_deep(ipv6_host_obj, top_ports=5, tcp_scan_type="T", include_reason=False)
    
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(
        host_ip=ipv6_host_obj.ip, top_ports=5, include_os_detection=False,
        nse_scripts=None, nse_script_args=None, timing_template=None,
        tcp_scan_type="T", include_reason=False, ipv6=True
    )

def test_scan_host_deep_nmap_handler_returns_empty(engine_instance: ARKEngine): # CORRECTED CALL
    input_host = Host(ip="192.168.1.101", status="up")
    mock_handler_res: Dict[str, Any] = { "ports": [], "os_matches": [], "mac_address": None, "vendor": None, "uptime_seconds": None, "last_boot": None, "distance": None, "host_scripts": {} }
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = mock_handler_res
    
    engine_instance.scan_host_deep(input_host) # Call with all scan_host_deep defaults
    
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(
        host_ip=input_host.ip, top_ports=100, include_os_detection=False, 
        nse_scripts=None, nse_script_args=None, timing_template=None,
        tcp_scan_type=None, ipv6=False, include_reason=False
    )

# --- Test ARKEngine.scan_host_udp ---
def test_scan_host_udp_params_passthrough_ipv4(engine_instance: ARKEngine): # Renamed from your log for clarity
    input_host = Host(ip="192.168.1.101", status="up")
    # Parameters for scan_host_udp call by the test
    call_params_to_engine = {"top_ports":5, "include_version":False, "timing_template":0, "include_reason":True}
    
    # Expected parameters for the nmap_handler.run_udp_scan call
    # ARKEngine.scan_host_udp derives ipv6=False for an IPv4 input_host.ip
    expected_handler_args = {
        "host_ip": input_host.ip, # <<< Pass host_ip as a keyword
        "top_ports": call_params_to_engine["top_ports"],
        "include_version": call_params_to_engine["include_version"],
        "timing_template": call_params_to_engine["timing_template"],
        "include_reason": call_params_to_engine["include_reason"],
        "ipv6": False 
    }
    engine_instance.nmap_handler.run_udp_scan.return_value = [] # Mock return
    
    # Act: Call the engine method
    engine_instance.scan_host_udp(input_host, **call_params_to_engine)
    
    # Assert: Call to the handler method
    engine_instance.nmap_handler.run_udp_scan.assert_called_once_with(**expected_handler_args)

def test_scan_host_udp_ipv6_target_passes_ipv6_flag(engine_instance: ARKEngine): # CORRECTED CALL
    ipv6_host_obj = get_sample_ipv6_host_for_engine_tests()
    engine_instance.nmap_handler.run_udp_scan.return_value = []
    
    engine_instance.scan_host_udp(ipv6_host_obj, top_ports=3, include_reason=True)
    
    engine_instance.nmap_handler.run_udp_scan.assert_called_once_with(
        host_ip=ipv6_host_obj.ip, top_ports=3, include_version=True,
        timing_template=None, include_reason=True, ipv6=True
    )

# --- Test ARKEngine.perform_basic_recon ---
def test_perform_basic_recon_all_features_enabled(engine_instance: ARKEngine, mocker): # CORRECTED
    target_scope_val = "192.168.1.0/24"
    # Parameters for the main perform_basic_recon call by the test
    recon_call_params = {
        "top_ports": 50, "include_os_detection": True, "nse_scripts": "default",
        "nse_script_args": "arg=val", "include_udp_scan": True, "top_udp_ports": 25,
        "timing_template": 2, "tcp_scan_type": "S", "ipv6": False,
        "input_target_file": None, "exclude_targets": None, "exclude_file": None,
        "include_reason": True
    }
    # How discover_live_hosts (which is an engine method itself, now mocked via handler for simplicity)
    # should be called by perform_basic_recon (via its call to the handler)
    expected_discover_handler_args = {
        "target_scope": target_scope_val, 
        "timing_template": recon_call_params["timing_template"],
        "input_target_file": recon_call_params["input_target_file"],
        "exclude_targets": recon_call_params["exclude_targets"],
        "exclude_file": recon_call_params["exclude_file"], 
        "ipv6": recon_call_params["ipv6"]
    }
    # How nmap_handler.run_port_scan_with_services is expected to be called by scan_host_deep
    expected_deep_scan_handler_args = {
        # host_ip will be asserted with assert_any_call
        "top_ports": recon_call_params["top_ports"], 
        "include_os_detection": recon_call_params["include_os_detection"],
        "nse_scripts": recon_call_params["nse_scripts"], 
        "nse_script_args": recon_call_params["nse_script_args"],
        "timing_template": recon_call_params["timing_template"], 
        "tcp_scan_type": recon_call_params["tcp_scan_type"],
        "ipv6": False, # Derived from IPv4 host object by scan_host_deep
        "include_reason": recon_call_params["include_reason"]
    }
    # How nmap_handler.run_udp_scan is expected to be called by scan_host_udp
    expected_udp_scan_handler_args = {
        # host_ip will be asserted with assert_any_call
        "top_ports": recon_call_params["top_udp_ports"], 
        "include_version": True, # scan_host_udp defaults this
        "timing_template": recon_call_params["timing_template"], 
        "ipv6": False, # Derived from IPv4 host object by scan_host_udp
        "include_reason": recon_call_params["include_reason"]
    }

    mock_h1 = Host(ip="192.168.1.1"); mock_h2 = Host(ip="192.168.1.5")
    # Configure the mocked nmap_handler on the engine_instance from the fixture
    engine_instance.nmap_handler.run_ping_scan.return_value = [mock_h1, mock_h2]
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = {"ports": []}
    engine_instance.nmap_handler.run_udp_scan.return_value = []

    # Act: Call perform_basic_recon
    engine_instance.perform_basic_recon(target_scope=target_scope_val, **recon_call_params)

    # Assert calls to nmap_handler methods
    engine_instance.nmap_handler.run_ping_scan.assert_called_once_with(**expected_discover_handler_args)
    
    assert engine_instance.nmap_handler.run_port_scan_with_services.call_count == 2
    engine_instance.nmap_handler.run_port_scan_with_services.assert_any_call(host_ip=mock_h1.ip, **expected_deep_scan_handler_args)
    engine_instance.nmap_handler.run_port_scan_with_services.assert_any_call(host_ip=mock_h2.ip, **expected_deep_scan_handler_args)
    
    if recon_call_params["include_udp_scan"]:
        assert engine_instance.nmap_handler.run_udp_scan.call_count == 2
        engine_instance.nmap_handler.run_udp_scan.assert_any_call(host_ip=mock_h1.ip, **expected_udp_scan_handler_args)
        engine_instance.nmap_handler.run_udp_scan.assert_any_call(host_ip=mock_h2.ip, **expected_udp_scan_handler_args)


def test_perform_basic_recon_minimal_options_ipv4(engine_instance: ARKEngine, mocker): # CORRECTED
    target_scope_val = "192.168.1.10"
    mock_h1 = Host(ip="192.168.1.10")
    engine_instance.nmap_handler.run_ping_scan.return_value = [mock_h1]
    engine_instance.nmap_handler.run_port_scan_with_services.return_value = {"ports": []}
    
    # Expected args for the call to nmap_handler.run_ping_scan
    expected_discover_handler_args = {
        "target_scope": target_scope_val, "timing_template": None,
        "input_target_file": None, "exclude_targets": None, "exclude_file": None, "ipv6": False
    }
    # Expected args for the call to nmap_handler.run_port_scan_with_services
    expected_deep_scan_handler_args = {
        "host_ip": mock_h1.ip, # This is positional for the handler method itself
        "top_ports": 100, "include_os_detection": False, "nse_scripts": None,
        "nse_script_args": None, "timing_template": None, "tcp_scan_type": None,
        "ipv6": False, "include_reason": False
    }

    # Act: Call perform_basic_recon with only target_scope, all others default
    engine_instance.perform_basic_recon(target_scope_val) 

    # Assert calls to nmap_handler methods
    engine_instance.nmap_handler.run_ping_scan.assert_called_once_with(**expected_discover_handler_args)
    engine_instance.nmap_handler.run_port_scan_with_services.assert_called_once_with(**expected_deep_scan_handler_args)
    engine_instance.nmap_handler.run_udp_scan.assert_not_called()


# --- EXPORT and SAVE/LOAD TESTS (Remain the same as last corrected version) ---
@pytest.fixture
def engine_instance_for_export_sl(mocker): # Keep this distinct fixture for export/save/load tests
    engine = ARKEngine()
    mocker.patch.object(engine, 'nmap_handler', MagicMock(spec=NmapHandler))
    return engine

def test_export_to_json_success(engine_instance_for_export_sl: ARKEngine, tmp_path: Path):
    sample_results = get_sample_scan_results(); json_file = tmp_path / "output.json"
    engine_instance_for_export_sl.export_to_json(sample_results, str(json_file)); assert json_file.exists()
    with open(json_file, 'r') as f: loaded_data = json.load(f)
    expected_data = [engine_instance_for_export_sl._dataclass_to_dict_converter(host) for host in sample_results]
    assert loaded_data == expected_data

def test_export_to_json_io_error(engine_instance_for_export_sl: ARKEngine, mocker, caplog):
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Disk full"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export_sl.export_to_json(sample_results, "restricted.json")
    assert "IOError exporting results to JSON file restricted.json: Disk full" in caplog.text

def test_export_to_csv_success(engine_instance_for_export_sl: ARKEngine, tmp_path: Path):
    sample_results = get_sample_scan_results() # This sample produces 6 data rows
    csv_file = tmp_path / "output.csv"
    engine_instance_for_export_sl.export_to_csv(sample_results, str(csv_file))
    assert csv_file.exists()
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f); rows = list(reader)
    expected_headers = [
        "Host IP", "Hostname", "Host Status", "MAC Address", "MAC Vendor",
        "OS Guesses", "Host Scripts (Summary)",
        "Port Number", "Port Protocol", "Port Status", "Port Reason",
        "Service Name", "Service Product", "Service Version", "Service ExtraInfo",
        "Port Scripts (Summary)"
    ]
    assert rows[0] == expected_headers
    assert len(rows) == 1 + 6 # 1 header + 6 data rows from the 4-host sample
    # Corrected checks based on the 4-host sample data
    host1_port80_row = next((r for r in rows[1:] if r[0] == "192.168.1.101" and r[7] == "80"), None)
    assert host1_port80_row is not None and host1_port80_row[11] == "http" and host1_port80_row[12] == "nginx"
    host3_port135_row = next((r for r in rows[1:] if r[0] == "192.168.1.103" and r[7] == "135"), None)
    assert host3_port135_row is not None and host3_port135_row[9] == "filtered"

def test_export_to_csv_io_error(engine_instance_for_export_sl: ARKEngine, mocker, caplog):
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Permission denied"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export_sl.export_to_csv(sample_results, "restricted.csv")
    assert "IOError exporting results to CSV file restricted.csv: Permission denied" in caplog.text

def test_save_and_load_scan_results_success(engine_instance_for_export_sl: ARKEngine, tmp_path: Path):
    sample_data = get_sample_scan_results()
    save_file = tmp_path / "ark_session_test.json"
    engine_instance_for_export_sl.save_scan_results(sample_data, str(save_file)); assert save_file.exists()
    loaded_data = engine_instance_for_export_sl.load_scan_results(str(save_file))
    assert isinstance(loaded_data, list) and len(loaded_data) == len(sample_data)
    original_as_dicts = [asdict(host) for host in sample_data] # Use asdict for reliable comparison
    loaded_as_dicts = [asdict(host) for host in loaded_data]
    assert original_as_dicts == loaded_as_dicts

def test_load_scan_results_file_not_found(engine_instance_for_export_sl: ARKEngine, tmp_path: Path, caplog):
    non_existent_file = tmp_path / "not_real.json"
    with caplog.at_level(logging.ERROR):
        assert engine_instance_for_export_sl.load_scan_results(str(non_existent_file)) == []
    assert f"File not found: {non_existent_file}" in caplog.text

def test_load_scan_results_invalid_json(engine_instance_for_export_sl: ARKEngine, tmp_path: Path, caplog):
    invalid_json_file = tmp_path / "invalid.json"; invalid_json_file.write_text("{not json")
    with caplog.at_level(logging.ERROR):
        assert engine_instance_for_export_sl.load_scan_results(str(invalid_json_file)) == []
    assert f"Error decoding JSON from {invalid_json_file}" in caplog.text

def test_save_scan_results_io_error(engine_instance_for_export_sl: ARKEngine, mocker, caplog):
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Cannot write"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export_sl.save_scan_results(sample_results, "restricted_save.json")
    # This assertion should now reflect the specific IOError logged by export_to_json
    assert "IOError exporting results to JSON file restricted_save.json: Cannot write" in caplog.text

def test_load_scan_results_empty_file(engine_instance_for_export_sl: ARKEngine, tmp_path: Path, caplog):
    empty_file = tmp_path / "empty.json"; empty_file.touch()
    with caplog.at_level(logging.ERROR):
        assert engine_instance_for_export_sl.load_scan_results(str(empty_file)) == []
    assert f"Error decoding JSON from {empty_file}" in caplog.text

def test_load_scan_results_not_a_list(engine_instance_for_export_sl: ARKEngine, tmp_path: Path, caplog):
    not_list_file = tmp_path / "not_list.json"; not_list_file.write_text('{"ip": "1.1.1.1"}')
    with caplog.at_level(logging.ERROR):
        assert engine_instance_for_export_sl.load_scan_results(str(not_list_file)) == []
    assert f"Invalid format in {not_list_file}: Expected list." in caplog.text