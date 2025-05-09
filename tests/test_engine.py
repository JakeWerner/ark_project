# tests/test_engine.py
import pytest
from unittest.mock import MagicMock, patch
import subprocess
import json
import csv
from pathlib import Path
from dataclasses import asdict
import logging # For caplog

from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
from typing import List, Dict, Any, Optional

# --- Helper to create sample scan data for export tests (4 hosts, expecting 6 data rows for CSV) ---
def get_sample_scan_results() -> List[Host]:
    host1_port_scripts = {"http-methods": "GET, POST"}
    host1_host_scripts = {"smb-os-discovery": "OS: Windows 10", "http-title": "Welcome"}
    host1 = Host(
        ip="192.168.1.101", hostname="server1.example.com", status="up",
        ports=[
            Port(number=80, protocol="tcp", status="open", service=Service(name="http", product="nginx"), scripts=host1_port_scripts),
            Port(number=443, protocol="tcp", status="open", service=Service(name="https")),
            Port(number=53, protocol="udp", status="open|filtered", service=Service(name="domain"))
        ],
        os_matches=[OSMatch(name="Linux 5.x", accuracy=95)], mac_address="AA:BB:CC:00:11:22", vendor="TestVendor1",
        host_scripts=host1_host_scripts
    )
    host2 = Host(
        ip="192.168.1.102", hostname="server2.example.com", status="up",
        ports=[Port(number=22, protocol="tcp", status="open", service=Service(name="ssh"))]
    )
    host3_filtered_port = Host(
        ip="192.168.1.103", hostname="server3.example.com", status="up",
        ports=[Port(number=135, protocol="tcp", status="filtered", reason="no-response")]
    )
    host4_no_ports_at_all = Host(ip="192.168.1.104", hostname="server4.example.com", status="up", ports=[]) # Empty ports list
    return [host1, host2, host3_filtered_port, host4_no_ports_at_all]

# --- Test ARKEngine Initialization ---
def test_arkengine_initialization(mocker):
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    engine = ARKEngine(nmap_path="/custom/nmap")
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path="/custom/nmap")

# --- Test ARKEngine.discover_live_hosts ---
def test_discover_live_hosts_with_target_scope(mocker):
    mock_host1 = Host(ip="192.168.1.1", status="up")
    engine = ARKEngine(); mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_host1])
    engine.discover_live_hosts(target_scope="1.1.1.0/24", timing_template=1, input_target_file="tf", exclude_targets="et", exclude_file="ef")
    mock_run_ping_scan.assert_called_once_with(target_scope="1.1.1.0/24", timing_template=1, input_target_file="tf", exclude_targets="et", exclude_file="ef")

# --- Test ARKEngine.scan_host_deep ---
def test_scan_host_deep_all_features_enabled(mocker):
    engine = ARKEngine(); input_host = Host(ip="192.168.1.105", status="up")
    params = {"top_ports":10, "include_os_detection":True, "nse_scripts":"default", "nse_script_args":"a=b", "timing_template":3, "tcp_scan_type":"S"}
    mock_handler_res: Dict[str, Any] = {"ports": [Port(number=80)], "os_matches":[OSMatch(name="L")], "host_scripts": {"s1":"o1"}}
    mock_scan = mocker.patch.object(engine.nmap_handler,'run_port_scan_with_services', return_value=mock_handler_res)
    engine.scan_host_deep(input_host, **params)
    mock_scan.assert_called_once_with(input_host.ip, **params)
    assert len(input_host.ports) == 1 # Assumes it clears old TCP and adds new
    assert len(input_host.os_matches) == 1
    assert input_host.host_scripts == {"s1":"o1"}


# --- Test ARKEngine.scan_host_udp ---
def test_scan_host_udp_success(mocker):
    engine = ARKEngine(); input_host = Host(ip="192.168.1.200", status="up", ports=[Port(number=80, protocol="tcp")]) # Existing TCP port
    params = {"top_ports":50, "include_version":True, "timing_template":1}
    mock_udp_ports = [Port(number=53, protocol='udp', status='open', service=Service(name='domain'))]
    mock_handler_udp_scan = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=mock_udp_ports)
    engine.scan_host_udp(input_host, **params)
    mock_handler_udp_scan.assert_called_once_with(input_host.ip, **params)
    assert any(p.number == 53 and p.protocol == 'udp' for p in input_host.ports)
    assert any(p.number == 80 and p.protocol == 'tcp' for p in input_host.ports) # Check TCP preserved
    assert len(input_host.ports) == 2


# --- Test ARKEngine.perform_basic_recon ---
def test_perform_basic_recon_all_features_enabled(mocker):
    engine = ARKEngine(); target_scope = "192.168.1.0/24"
    engine = ARKEngine()
    target_scope = "192.168.1.0/24"

    # Define all parameters for the call to perform_basic_recon
    time_t = 2  # <<< ENSURE THIS LINE (OR SIMILAR) IS PRESENT AND CORRECT
    # Define all parameters that will be passed
    ping_scan_params = {"timing_template": 2, "input_target_file": None, "exclude_targets": None, "exclude_file": None}
    deep_scan_params = {"top_ports": 50, "include_os_detection": True, "nse_scripts": "default", 
                        "nse_script_args": "arg=val", "timing_template": 2, "tcp_scan_type": "S"}
    udp_scan_params = {"top_ports": 25, "include_version": True, "timing_template": 2}

    mock_h1 = Host(ip="192.168.1.1"); mock_h2 = Host(ip="192.168.1.5")
    mock_discover = mocker.patch.object(engine, 'discover_live_hosts', return_value=[mock_h1, mock_h2])
    mock_deep_scan_method = mocker.patch.object(engine, 'scan_host_deep') # Mock the engine's own method
    mock_udp_scan_method = mocker.patch.object(engine, 'scan_host_udp')   # Mock the engine's own method

    engine.perform_basic_recon(
        target_scope, top_ports=deep_scan_params["top_ports"], include_os_detection=deep_scan_params["include_os_detection"],
        nse_scripts=deep_scan_params["nse_scripts"], nse_script_args=deep_scan_params["nse_script_args"],
        include_udp_scan=True, top_udp_ports=udp_scan_params["top_ports"],
        timing_template=ping_scan_params["timing_template"], tcp_scan_type=deep_scan_params["tcp_scan_type"]
    )

    mock_discover.assert_called_once_with(target_scope=target_scope, timing_template=time_t, input_target_file=None, exclude_targets=None, exclude_file=None)
    
    assert mock_deep_scan_method.call_count == 2
    mock_deep_scan_method.assert_any_call(mock_h1, **deep_scan_params)
    mock_deep_scan_method.assert_any_call(mock_h2, **deep_scan_params)
    
    assert mock_udp_scan_method.call_count == 2
    mock_udp_scan_method.assert_any_call(mock_h1, top_ports=udp_scan_params["top_ports"], include_version=udp_scan_params["include_version"], timing_template=udp_scan_params["timing_template"])
    mock_udp_scan_method.assert_any_call(mock_h2, top_ports=udp_scan_params["top_ports"], include_version=udp_scan_params["include_version"], timing_template=udp_scan_params["timing_template"])


def test_perform_basic_recon_minimal_options(mocker):
    engine = ARKEngine(); target_scope = "192.168.1.10"
    mock_h1 = Host(ip="192.168.1.10")
    mock_discover = mocker.patch.object(engine, 'discover_live_hosts', return_value=[mock_h1])
    mock_deep_scan_method = mocker.patch.object(engine, 'scan_host_deep')
    mock_udp_scan_method = mocker.patch.object(engine, 'scan_host_udp')

    engine.perform_basic_recon(target_scope) # All optional args for recon use their defaults

    mock_discover.assert_called_once_with(
    target_scope=target_scope, # <<< Pass as keyword argument
    timing_template=None, 
    input_target_file=None, 
    exclude_targets=None, 
    exclude_file=None
    )
    mock_deep_scan_method.assert_called_once_with(
        mock_h1, top_ports=100, include_os_detection=False,
        nse_scripts=None, nse_script_args=None, timing_template=None,
        tcp_scan_type=None
    )
    mock_udp_scan_method.assert_not_called()


# --- EXPORT TESTS ---
@pytest.fixture
def engine_instance_for_export(mocker):
    engine = ARKEngine(); mocker.patch.object(engine, 'nmap_handler', MagicMock()); return engine

def test_export_to_json_success(engine_instance_for_export: ARKEngine, tmp_path: Path):
    sample_results = get_sample_scan_results()
    json_file = tmp_path / "output.json"
    engine_instance_for_export.export_to_json(sample_results, str(json_file)); assert json_file.exists()
    with open(json_file, 'r') as f: loaded_data = json.load(f)
    expected_data = [engine_instance_for_export._dataclass_to_dict_converter(host) for host in sample_results]
    assert loaded_data == expected_data

def test_export_to_json_io_error(engine_instance_for_export: ARKEngine, mocker, caplog):
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Disk full"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export.export_to_json(sample_results, "restricted.json")
    # Match the actual logged message prefix if IOError is not caught specifically first
    assert "An error occurred during JSON export to restricted.json: Disk full" in caplog.text


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

    # Check data for Host1, Port 80
    host1_port80_row = next((r for r in rows[1:] if r[0] == "192.168.1.101" and r[7] == "80"), None)
    assert host1_port80_row is not None
    assert host1_port80_row[11] == "http"  # Service Name
    assert host1_port80_row[12] == "nginx" # Service Product

    # Check data for Host3 (filtered port 135)
    host3_port135_row = next((r for r in rows[1:] if r[0] == "192.168.1.103" and r[7] == "135"), None)
    assert host3_port135_row is not None
    assert host3_port135_row[9] == "filtered" # Port Status

    # Check Host4 (host-only row)
    host4_row = next((r for r in rows[1:] if r[0] == "192.168.1.104"), None)
    assert host4_row is not None
    assert host4_row[7] == "" # Port Number should be empty


def test_export_to_csv_io_error(engine_instance_for_export: ARKEngine, mocker, caplog):
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Permission denied"))
    with caplog.at_level(logging.ERROR):
        engine_instance_for_export.export_to_csv(sample_results, "restricted.csv")
    # Match the actual logged message prefix
    assert "An error occurred during CSV export to restricted.csv: Permission denied" in caplog.text