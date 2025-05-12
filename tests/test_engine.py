# tests/test_engine.py
import pytest
from unittest.mock import MagicMock, patch
import subprocess
import json
import csv
from pathlib import Path
from dataclasses import asdict, is_dataclass # Ensure is_dataclass is imported
import logging # For caplog

from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
from typing import List, Dict, Any, Optional, Type

# --- Helper to create sample scan data (4 hosts) ---
def get_sample_scan_results() -> List[Host]:
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
    host2 = Host(ip="192.168.1.102", hostname="server2.example.com", status="up", ports=[Port(number=22, protocol="tcp", status="open")])
    host3_filtered_port = Host(ip="192.168.1.103", hostname="server3.example.com", status="up", ports=[Port(number=135, protocol="tcp", status="filtered", reason="no-response")], host_scripts={"info":"Host3"})
    host4_no_ports_at_all = Host(ip="192.168.1.104", hostname="server4.example.com", status="up", ports=[])
    return [host1, host2, host3_filtered_port, host4_no_ports_at_all]

@pytest.fixture
def engine_instance(mocker):
    engine = ARKEngine()
    mocker.patch.object(engine, 'nmap_handler', MagicMock())
    return engine

# --- Test ARKEngine Initialization ---
def test_arkengine_initialization(mocker):
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    engine = ARKEngine(nmap_path="/custom/nmap")
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path="/custom/nmap")

# --- Test ARKEngine.discover_live_hosts ---
def test_discover_live_hosts_with_target_scope(mocker):
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_host1])
    target_s = "192.168.1.0/24"; time_t = 2
    engine.discover_live_hosts(target_scope=target_s, timing_template=time_t, input_target_file=None, exclude_targets=None, exclude_file=None)
    mock_run_ping_scan.assert_called_once_with(target_scope=target_s, timing_template=time_t, input_target_file=None, exclude_targets=None, exclude_file=None)

def test_discover_live_hosts_with_input_file(mocker):
    mock_host1 = Host(ip="192.168.1.10", status="up")
    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_host1])
    target_f = "targets.txt"; exclude_s = "1.1.1.1"
    engine.discover_live_hosts(target_scope=None, input_target_file=target_f, exclude_targets=exclude_s, exclude_file=None, timing_template=None)
    mock_run_ping_scan.assert_called_once_with(target_scope=None, input_target_file=target_f, exclude_targets=exclude_s, exclude_file=None, timing_template=None)

# --- Test ARKEngine.scan_host_deep ---
def test_scan_host_deep_all_features_enabled(mocker): # Corrected based on user's last traceback
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.105", status="up")
    params = {
        "top_ports": 100, "include_os_detection": True, "nse_scripts": "default",
        "nse_script_args": "arg=val", "timing_template": 3, "tcp_scan_type": "S"
    }
    mock_handler_res: Dict[str, Any] = {"ports": [Port(number=80)], "os_matches": [OSMatch(name="L")], "host_scripts": {"s1":"o1"}}
    mock_scan_method = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_handler_res)
    
    engine.scan_host_deep(input_host, **params)
    
    mock_scan_method.assert_called_once_with(input_host.ip, **params)
    assert len(input_host.ports) > 0 # Basic check that ports were processed

# --- Test ARKEngine.perform_basic_recon ---
def test_perform_basic_recon_all_features_enabled(mocker):
    engine = ARKEngine()
    target_scope_val = "192.168.1.0/24"
    
    # Define all parameters for perform_basic_recon
    top_tcp_ports_val = 50
    include_os_val = True
    nse_scripts_val = "default"
    nse_script_args_val = "arg=val"
    include_udp_val = True
    top_udp_ports_val = 25
    timing_template_val = 2 # This is the crucial value
    tcp_scan_type_val = "S"
    input_target_file_val = None # For this test case
    exclude_targets_val = None   # For this test case
    exclude_file_val = None      # For this test case

    mock_h1 = Host(ip="192.168.1.1")
    mock_h2 = Host(ip="192.168.1.5")
    # Mock engine's discover_live_hosts method directly
    mock_discover = mocker.patch.object(engine, 'discover_live_hosts', return_value=[mock_h1, mock_h2])
    
    mock_tcp_res: Dict[str, Any] = {"ports": [], "os_matches":[], "host_scripts": {}}
    mock_tcp_scan_handler_method = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_tcp_res)
    mock_udp_scan_handler_method = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=[])

    # Act: Call perform_basic_recon with all its defined parameters
    engine.perform_basic_recon(
        target_scope=target_scope_val, # Now explicitly passing this as kwarg
        top_ports=top_tcp_ports_val,
        include_os_detection=include_os_val,
        nse_scripts=nse_scripts_val,
        nse_script_args=nse_script_args_val,
        include_udp_scan=include_udp_val,
        top_udp_ports=top_udp_ports_val,
        timing_template=timing_template_val, # <<< This will be 2
        tcp_scan_type=tcp_scan_type_val,
        input_target_file=input_target_file_val,
        exclude_targets=exclude_targets_val,
        exclude_file=exclude_file_val
    )

    # Assert how perform_basic_recon calls its own discover_live_hosts
    mock_discover.assert_called_once_with(
        target_scope=target_scope_val,
        timing_template=timing_template_val, # <<< Expecting 2
        input_target_file=input_target_file_val,
        exclude_targets=exclude_targets_val,
        exclude_file=exclude_file_val
    )
    
    # Assert calls to nmap_handler methods (made via scan_host_deep and scan_host_udp)
    assert mock_tcp_scan_handler_method.call_count == 2
    mock_tcp_scan_handler_method.assert_any_call(
        mock_h1.ip, top_ports=top_tcp_ports_val, include_os_detection=include_os_val,
        nse_scripts=nse_scripts_val, nse_script_args=nse_script_args_val, 
        timing_template=timing_template_val, tcp_scan_type=tcp_scan_type_val
    )
    mock_tcp_scan_handler_method.assert_any_call(
        mock_h2.ip, top_ports=top_tcp_ports_val, include_os_detection=include_os_val,
        nse_scripts=nse_scripts_val, nse_script_args=nse_script_args_val, 
        timing_template=timing_template_val, tcp_scan_type=tcp_scan_type_val
    )
    
    if include_udp_val:
        assert mock_udp_scan_handler_method.call_count == 2
        mock_udp_scan_handler_method.assert_any_call(
            mock_h1.ip, top_ports=top_udp_ports_val, include_version=True, timing_template=timing_template_val
        )
        mock_udp_scan_handler_method.assert_any_call(
            mock_h2.ip, top_ports=top_udp_ports_val, include_version=True, timing_template=timing_template_val
        )

def test_perform_basic_recon_minimal_options(mocker): # Corrected based on user's last traceback
    engine = ARKEngine(); target_scope_val = "192.168.1.10"
    mock_h1 = Host(ip="192.168.1.10")
    mock_discover = mocker.patch.object(engine, 'discover_live_hosts', return_value=[mock_h1])
    mock_tcp_scan_handler = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value={"ports": [], "os_matches":[], "host_scripts": {}})
    mock_udp_scan_handler = mocker.patch.object(engine.nmap_handler, 'run_udp_scan')

    engine.perform_basic_recon(target_scope_val) # All optional args for recon use their defaults

    mock_discover.assert_called_once_with(
        target_scope=target_scope_val, timing_template=None,
        input_target_file=None, exclude_targets=None, exclude_file=None
    )
    mock_tcp_scan_handler.assert_called_once_with(
        mock_h1.ip, top_ports=100, include_os_detection=False,
        nse_scripts=None, nse_script_args=None, timing_template=None,
        tcp_scan_type=None
    )
    mock_udp_scan_handler.assert_not_called()

# --- EXPORT TESTS (remain the same from last corrected version) ---
@pytest.fixture
def engine_instance_for_export(mocker): # Keep this name
    engine = ARKEngine(); mocker.patch.object(engine, 'nmap_handler', MagicMock()); return engine

def test_export_to_json_success(engine_instance_for_export: ARKEngine, tmp_path: Path):
    sample_results = get_sample_scan_results(); json_file = tmp_path / "output.json"
    engine_instance_for_export.export_to_json(sample_results, str(json_file)); assert json_file.exists()
    with open(json_file, 'r') as f: loaded_data = json.load(f)
    expected_data = [engine_instance_for_export._dataclass_to_dict_converter(host) for host in sample_results]
    assert loaded_data == expected_data

def test_export_to_json_io_error(engine_instance_for_export: ARKEngine, mocker, caplog):
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Disk full"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export.export_to_json(sample_results, "restricted.json")
    assert "IOError exporting results to JSON file restricted.json: Disk full" in caplog.text # Assuming IOError block is hit

def test_export_to_csv_success(engine_instance_for_export: ARKEngine, tmp_path: Path):
    sample_results = get_sample_scan_results() # This sample produces 6 data rows
    csv_file = tmp_path / "output.csv"
    engine_instance_for_export.export_to_csv(sample_results, str(csv_file))
    assert csv_file.exists()
    with open(csv_file, 'r', newline='') as f:
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

    host1_port80_row = next((r for r in rows[1:] if r[0] == "192.168.1.101" and r[7] == "80"), None)
    assert host1_port80_row is not None and host1_port80_row[11] == "http" and host1_port80_row[12] == "nginx"
    host3_port135_row = next((r for r in rows[1:] if r[0] == "192.168.1.103" and r[7] == "135"), None)
    assert host3_port135_row is not None and host3_port135_row[9] == "filtered"

def test_export_to_csv_io_error(engine_instance_for_export: ARKEngine, mocker, caplog):
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Permission denied"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export.export_to_csv(sample_results, "restricted.csv")
    assert "IOError exporting results to CSV file restricted.csv: Permission denied" in caplog.text # Assuming IOError block

# --- Save/Load Tests (from previous step, ensure they use correct engine_instance and asdict) ---
def test_save_and_load_scan_results_success(engine_instance_for_export: ARKEngine, tmp_path: Path):
    sample_data = get_sample_scan_results()
    save_file = tmp_path / "ark_session_test.json"
    engine_instance_for_export.save_scan_results(sample_data, str(save_file))
    assert save_file.exists()
    loaded_data = engine_instance_for_export.load_scan_results(str(save_file))
    assert isinstance(loaded_data, list) and len(loaded_data) == len(sample_data)
    original_as_dicts = [asdict(host) for host in sample_data]
    loaded_as_dicts = [asdict(host) for host in loaded_data]
    assert original_as_dicts == loaded_as_dicts
