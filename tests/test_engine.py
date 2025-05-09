# tests/test_engine.py
import pytest
from unittest.mock import MagicMock, patch
import subprocess

from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
from pathlib import Path
import json
import csv
# from autork.nmap_handler import NmapHandler # Only if patching class
from typing import List, Dict, Any, Optional

# --- Test ARKEngine Initialization (remains same) ---
def test_arkengine_initialization(mocker):
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    engine = ARKEngine(nmap_path="/custom/nmap")
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path="/custom/nmap")

# --- Test ARKEngine.discover_live_hosts (remains same, uses timing) ---
def test_discover_live_hosts_success(mocker):
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    mock_return_value = [mock_host1]
    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=mock_return_value)
    target_scope = "192.168.1.0/24"; custom_timing = 2
    result_hosts = engine.discover_live_hosts(target_scope, timing_template=custom_timing)
    mock_run_ping_scan.assert_called_once_with(target_scope, timing_template=custom_timing)
    assert result_hosts == mock_return_value

# --- Test ARKEngine.scan_host_deep (Updated for tcp_scan_type) ---
def test_scan_host_deep_all_features_enabled(mocker):
    engine = ARKEngine(); input_host = Host(ip="192.168.1.105", status="up")
    top_ports=100; inc_os=True; nse_s="default"; nse_sa="arg=val"; time_t=3; tcp_st="S" # All options

    mock_handler_res: Dict[str, Any] = {"ports": [], "os_matches": [], "host_scripts": {}}
    mock_scan_method = mocker.patch.object(engine.nmap_handler,'run_port_scan_with_services', return_value=mock_handler_res)

    engine.scan_host_deep(
        input_host, top_ports=top_ports, include_os_detection=inc_os,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=time_t,
        tcp_scan_type=tcp_st # Pass TCP scan type
    )
    mock_scan_method.assert_called_once_with(
        input_host.ip, top_ports=top_ports, include_os_detection=inc_os,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=time_t,
        tcp_scan_type=tcp_st # Assert TCP scan type passed
    )

def test_scan_host_deep_nmap_handler_returns_empty(mocker):
    engine = ARKEngine(); input_host = Host(ip="192.168.1.101", status="up")
    mock_handler_res: Dict[str, Any] = { "ports": [], "os_matches": [], "mac_address": None, "host_scripts": {} }
    mock_scan_method = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_handler_res)
    result_host = engine.scan_host_deep(
        input_host, top_ports=100, include_os_detection=False, 
        nse_scripts=None, nse_script_args=None, timing_template=None,
        tcp_scan_type=None # Pass None for tcp_scan_type
    )
    mock_scan_method.assert_called_once_with(
        input_host.ip, top_ports=100, include_os_detection=False, 
        nse_scripts=None, nse_script_args=None, timing_template=None,
        tcp_scan_type=None # Assert None
    )
    assert result_host.ports == []

# --- Test ARKEngine.scan_host_udp (remains same, uses timing) ---
def test_scan_host_udp_success(mocker):
    engine = ARKEngine(); input_host = Host(ip="192.168.1.200", status="up")
    top_ports_udp = 50; include_ver_udp = True; timing_arg = 1
    mock_udp_ports = [Port(number=53, protocol='udp')]
    mock_handler_udp_scan = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=mock_udp_ports)
    engine.scan_host_udp(input_host, top_ports=top_ports_udp, include_version=include_ver_udp, timing_template=timing_arg)
    mock_handler_udp_scan.assert_called_once_with(
        input_host.ip, top_ports=top_ports_udp, include_version=include_ver_udp, timing_template=timing_arg
    )

# --- Test ARKEngine.perform_basic_recon (Updated for tcp_scan_type) ---
def test_perform_basic_recon_all_features_enabled(mocker):
    engine = ARKEngine(); target_scope = "192.168.1.0/24"
    top_tcp=50; top_udp=25; inc_os=True; inc_udp=True; nse_s="default"; nse_sa="arg=val"; time_t=2
    tcp_st = "S" # Specify scan type for recon

    mock_h1=Host(ip="192.168.1.1"); mock_h2=Host(ip="192.168.1.5")
    mock_ping = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_h1, mock_h2])
    mock_tcp_res: Dict[str, Any] = {"ports": [], "os_matches":[], "host_scripts": {}}
    mock_tcp = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_tcp_res)
    mock_udp = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=[])

    engine.perform_basic_recon(target_scope, top_ports=top_tcp, include_os_detection=inc_os,
                                nse_scripts=nse_s, nse_script_args=nse_sa,
                                include_udp_scan=inc_udp, top_udp_ports=top_udp,
                                timing_template=time_t,
                                tcp_scan_type=tcp_st) # Pass TCP scan type

    mock_ping.assert_called_once_with(target_scope, timing_template=time_t)
    assert mock_tcp.call_count == 2
    mock_tcp.assert_any_call("192.168.1.1", top_ports=top_tcp, include_os_detection=inc_os, nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=time_t, tcp_scan_type=tcp_st) # Assert
    mock_tcp.assert_any_call("192.168.1.5", top_ports=top_tcp, include_os_detection=inc_os, nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=time_t, tcp_scan_type=tcp_st) # Assert
    if inc_udp:
        assert mock_udp.call_count == 2
        mock_udp.assert_any_call("192.168.1.1", top_ports=top_udp, include_version=True, timing_template=time_t)
        mock_udp.assert_any_call("192.168.1.5", top_ports=top_udp, include_version=True, timing_template=time_t)

# ... (test_perform_basic_recon_scripts_and_args_disabled needs similar updates for tcp_scan_type=None)
# ... (Export tests remain the same)
def get_sample_scan_results() -> List[Host]:
    host1 = Host(ip="192.168.1.101", hostname="server1.example.com", status="up", ports=[Port(number=80, protocol="tcp", status="open", service=Service(name="http", product="nginx"), scripts={"http-title":"Test"})], os_matches=[OSMatch(name="Linux")], host_scripts={"info":"Host1"})
    host2 = Host(ip="192.168.1.102", ports=[Port(number=22, protocol="tcp", status="open")])
    return [host1, host2]
@pytest.fixture
def engine_instance(mocker):
    engine = ARKEngine(); mocker.patch.object(engine, 'nmap_handler', MagicMock()); return engine
def test_export_to_json_success(engine_instance: ARKEngine, tmp_path: Path):
    # ... (as before)
    sample_results = get_sample_scan_results(); json_file = tmp_path / "output.json"
    engine_instance.export_to_json(sample_results, str(json_file)); assert json_file.exists()
    with open(json_file, 'r') as f: loaded_data = json.load(f)
    expected_data = [engine_instance._dataclass_to_dict_converter(host) for host in sample_results]
    assert loaded_data == expected_data
def test_export_to_csv_success(engine_instance: ARKEngine, tmp_path: Path):
    # ... (as before)
    sample_results = get_sample_scan_results(); csv_file = tmp_path / "output.csv"
    engine_instance.export_to_csv(sample_results, str(csv_file)); assert csv_file.exists()
    with open(csv_file, 'r', newline='') as f: reader = csv.reader(f); rows = list(reader)
    expected_headers = ["Host IP", "Hostname", "Host Status", "MAC Address", "MAC Vendor", "OS Guesses", "Host Scripts (Summary)", "Port Number", "Port Protocol", "Port Status", "Port Reason", "Service Name", "Service Product", "Service Version", "Service ExtraInfo", "Port Scripts (Summary)"]
    assert rows[0] == expected_headers; assert len(rows) == 1 + 2