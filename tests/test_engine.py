import pytest
from unittest.mock import MagicMock, patch
import subprocess
import json # For JSON test
import csv   # For CSV test
from pathlib import Path # For tmp_path
from dataclasses import asdict # For comparing with JSON output
import logging

# Import the class we are testing
from autork.engine import ARKEngine
# Import the datamodels used in the return types and arguments
from autork.datamodels import Host, Port, Service, OSMatch
# We might need NmapHandler for type hinting or patching the class itself
# from autork.nmap_handler import NmapHandler # Not directly needed for these tests if mocking engine's handler
from typing import List, Dict, Any, Optional

# --- Helper to create sample scan data for export tests ---
def get_sample_scan_results() -> List[Host]:
    host1_scripts = {"http-title": "Welcome Page", "ssl-cert": "Cert Details"}
    host1_port_scripts = {"http-methods": "GET, POST", "another-script": "output"}
    
    host1 = Host(
        ip="192.168.1.101",
        hostname="server1.example.com",
        status="up",
        ports=[
            Port(number=80, protocol="tcp", status="open",
                 service=Service(name="http", product="nginx", version="1.18"),
                 scripts=host1_port_scripts),
            Port(number=443, protocol="tcp", status="open",
                 service=Service(name="https", product="nginx", version="1.18")),
            Port(number=53, protocol="udp", status="open|filtered",
                 service=Service(name="domain"))
        ],
        os_matches=[OSMatch(name="Linux 5.x", accuracy=95), OSMatch(name="Linux Kernel 5.4", accuracy=90)],
        mac_address="AA:BB:CC:00:11:22",
        vendor="TestVendor1",
        uptime_seconds=123456,
        last_boot="2025-05-01 10:00:00",
        distance=1,
        host_scripts=host1_scripts
    )
    
    host2 = Host(
        ip="192.168.1.102",
        hostname="server2.example.com",
        status="up",
        ports=[
            Port(number=22, protocol="tcp", status="open",
                 service=Service(name="ssh", product="OpenSSH", version="8.2p1"))
        ],
        os_matches=[OSMatch(name="Windows Server 2019", accuracy=98)],
        host_scripts={"smb-os-discovery": "Windows Server 2019"}
    )
    
    host3_no_open_ports = Host(
        ip="192.168.1.103",
        hostname="server3.example.com",
        status="up",
        ports=[Port(number=135, protocol="tcp", status="filtered")], # No open or open|filtered ports
        host_scripts={"host-script-info": "some data"}
    )

    host4_no_ports_at_all = Host(
        ip="192.168.1.104",
        hostname="server4.example.com",
        status="up" # From ping scan, no port scan done
    )
    return [host1, host2, host3_no_open_ports, host4_no_ports_at_all]

# --- Test ARKEngine Initialization ---
def test_arkengine_initialization(mocker):
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    engine = ARKEngine(nmap_path="/custom/nmap")
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path="/custom/nmap")

# --- Test ARKEngine.discover_live_hosts ---
def test_discover_live_hosts_success(mocker):
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    mock_return_value = [mock_host1]
    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=mock_return_value)
    target_scope = "192.168.1.0/24"
    custom_timing = 2
    result_hosts = engine.discover_live_hosts(target_scope, timing_template=custom_timing)
    mock_run_ping_scan.assert_called_once_with(target_scope, timing_template=custom_timing)
    assert result_hosts == mock_return_value

def test_discover_live_hosts_no_hosts_up_default_timing(mocker):
    engine = ARKEngine()
    mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[])
    engine.discover_live_hosts("10.0.0.0/24", timing_template=None)
    engine.nmap_handler.run_ping_scan.assert_called_once_with("10.0.0.0/24", timing_template=None)

# --- Test ARKEngine.scan_host_deep ---
def test_scan_host_deep_all_features_enabled(mocker):
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.105", status="up")
    top_ports_arg=100; include_os_arg=True; nse_s="default"; nse_sa="arg=val"; timing_arg=3
    mock_handler_result: Dict[str, Any] = {"ports": [], "os_matches": [], "host_scripts": {}} # Simplified mock
    mock_scan_method = mocker.patch.object(engine.nmap_handler,'run_port_scan_with_services', return_value=mock_handler_result)
    engine.scan_host_deep(
        input_host, top_ports=top_ports_arg, include_os_detection=include_os_arg,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=timing_arg
    )
    mock_scan_method.assert_called_once_with(
        input_host.ip, top_ports=top_ports_arg, include_os_detection=include_os_arg,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=timing_arg
    )

def test_scan_host_deep_nmap_handler_returns_empty(mocker):
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.101", status="up")
    mock_handler_result: Dict[str, Any] = { "ports": [], "os_matches": [], "mac_address": None, "host_scripts": {} }
    mock_scan_method = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_handler_result)
    result_host = engine.scan_host_deep(input_host, top_ports=100, include_os_detection=False, nse_scripts=None, nse_script_args=None, timing_template=None)
    mock_scan_method.assert_called_once_with(
        input_host.ip, top_ports=100, include_os_detection=False, nse_scripts=None, nse_script_args=None, timing_template=None
    )
    assert result_host.ports == [] and result_host.os_matches == [] and result_host.host_scripts == {}

# --- Test ARKEngine.scan_host_udp ---
def test_scan_host_udp_success(mocker):
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.200", status="up")
    top_ports_udp = 50; include_ver_udp = True; timing_arg = 1
    mock_udp_ports = [Port(number=53, protocol='udp')]
    mock_handler_udp_scan = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=mock_udp_ports)
    engine.scan_host_udp(input_host, top_ports=top_ports_udp, include_version=include_ver_udp, timing_template=timing_arg)
    mock_handler_udp_scan.assert_called_once_with(
        input_host.ip, top_ports=top_ports_udp, include_version=include_ver_udp, timing_template=timing_arg
    )

# --- Test ARKEngine.perform_basic_recon ---
def test_perform_basic_recon_all_features_enabled(mocker):
    # ... (This test as provided before, ensuring timing_template is passed and asserted) ...
    engine = ARKEngine(); target_scope = "192.168.1.0/24"
    top_tcp=50; top_udp=25; inc_os=True; inc_udp=True; nse_s="default"; nse_sa="arg=val"; timing_arg=2
    mock_h1=Host(ip="192.168.1.1"); mock_h2=Host(ip="192.168.1.5")
    mock_ping = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_h1, mock_h2])
    mock_tcp_res: Dict[str, Any] = {"ports": [], "os_matches":[], "host_scripts": {}}
    mock_tcp = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_tcp_res)
    mock_udp = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=[])
    engine.perform_basic_recon(target_scope, top_ports=top_tcp, include_os_detection=inc_os,
                                nse_scripts=nse_s, nse_script_args=nse_sa,
                                include_udp_scan=inc_udp, top_udp_ports=top_udp,
                                timing_template=timing_arg)
    mock_ping.assert_called_once_with(target_scope, timing_template=timing_arg)
    mock_tcp.assert_any_call("192.168.1.1", top_ports=top_tcp, include_os_detection=inc_os, nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=timing_arg)


def test_perform_basic_recon_scripts_and_args_disabled(mocker):
    # ... (This test as provided before, ensuring timing_template is passed and asserted if not None) ...
    engine = ARKEngine(); target_scope = "192.168.1.0/2" # Corrected target for consistency
    mock_h1 = Host(ip="192.168.1.1")
    mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_h1])
    mock_tcp1: Dict[str, Any] = {"ports": [], "os_matches":[], "host_scripts": {}}
    mock_tcp = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_tcp1)
    mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=[])
    results = engine.perform_basic_recon(target_scope, top_ports=10, nse_scripts=None, nse_script_args=None, include_udp_scan=False, timing_template=None)
    mock_tcp.assert_called_once_with("192.168.1.1", top_ports=10, include_os_detection=False, nse_scripts=None, nse_script_args=None, timing_template=None)


# --- NEW TESTS FOR EXPORT FUNCTIONALITY ---

def test_export_to_json_success(mocker, tmp_path: Path):
    """Test exporting scan results to a JSON file."""
    engine = ARKEngine()
    # Use a simplified NmapHandler mock for these tests as we're not testing scanning
    mocker.patch.object(engine, 'nmap_handler', MagicMock()) 
    
    sample_results = get_sample_scan_results()
    json_file = tmp_path / "output.json"

    engine.export_to_json(sample_results, str(json_file))

    assert json_file.exists()
    with open(json_file, 'r') as f:
        loaded_data = json.load(f)
    
    # Convert original sample_results to dicts for comparison
    # Need to handle nested dataclasses for asdict to work as expected by json.dump
    expected_data = [engine._dataclass_to_dict_converter(host) for host in sample_results]

    assert loaded_data == expected_data
    assert len(loaded_data) == 4
    assert loaded_data[0]['ip'] == "192.168.1.101"
    assert len(loaded_data[0]['ports']) == 3
    assert loaded_data[0]['ports'][0]['scripts']['http-methods'] == "GET, POST"
    assert loaded_data[0]['host_scripts']['http-title'] == "Welcome Page"

def test_export_to_json_io_error(mocker, caplog):
    """Test IOError during JSON export."""
    engine = ARKEngine()
    mocker.patch.object(engine, 'nmap_handler', MagicMock())
    sample_results = get_sample_scan_results()

    # Patch open to raise IOError
    mocker.patch('builtins.open', side_effect=IOError("Disk full"))

    with caplog.at_level(logging.ERROR):
        engine.export_to_json(sample_results, "restricted_output.json")
    
    assert "IOError exporting results to JSON file restricted_output.json: Disk full" in caplog.text

def test_export_to_csv_success(mocker, tmp_path: Path):
    """Test exporting scan results to a CSV file."""
    engine = ARKEngine()
    mocker.patch.object(engine, 'nmap_handler', MagicMock())
    sample_results = get_sample_scan_results() # Contains 4 hosts, one with no open ports, one with no ports
    csv_file = tmp_path / "output.csv"

    engine.export_to_csv(sample_results, str(csv_file))

    assert csv_file.exists()
    with open(csv_file, 'r', newline='') as f:
        reader = csv.reader(f)
        rows = list(reader)
    
    # Expected headers (ensure it matches headers in export_to_csv)
    expected_headers = [
        "Host IP", "Hostname", "Host Status", "MAC Address", "MAC Vendor",
        "OS Guesses", "Host Scripts (Summary)",
        "Port Number", "Port Protocol", "Port Status", "Port Reason",
        "Service Name", "Service Product", "Service Version", "Service ExtraInfo",
        "Port Scripts (Summary)"
    ]
    assert rows[0] == expected_headers

    # Expected number of data rows:
    # Host1: 3 open/open|filtered ports -> 3 rows
    # Host2: 1 open port -> 1 row
    # Host3: 0 open/open|filtered ports (but host is up) -> 1 row (host info only)
    # Host4: 0 ports at all (but host is up) -> 1 row (host info only)
    assert len(rows) == 1 + 3 + 1 + 1 + 1 # 1 header + 6 data rows

    # Check some data from Host1, Port 80
    # Find the row for host1, port 80 (this is a bit fragile if order changes)
    # A better check might be to parse with DictReader and find specific entries.
    found_host1_port80 = False
    for row in rows[1:]: # Skip header
        if row[0] == "192.168.1.101" and row[7] == "80": # IP and Port Number
            found_host1_port80 = True
            assert row[1] == "server1.example.com" # Hostname
            assert row[8] == "tcp"                 # Port Protocol
            assert row[9] == "open"                # Port Status
            assert row[11] == "http"              # Service Product
            assert "http-methods:GET, POST" in row[15] # Port Scripts
            assert "Linux 5.x (95%)" in row[5]     # OS Guesses
            assert "http-title:Welcome Page" in row[6] # Host Scripts
            break
    assert found_host1_port80, "CSV data for Host 1, Port 80 not found or incorrect."

    # Check Host3 (no open/filtered ports, so port details should be empty)
    found_host3 = False
    for row in rows[1:]: # Skip header
        if row[0] == "192.168.1.103": # Host IP
            found_host3 = True
            assert row[1] == "server3.example.com"     # Hostname
            assert row[2] == "up"                      # Host Status
            # Headers: 0:IP, 1:Hostname, 2:Status, ... 6:HostScripts, 7:PortNum, 8:Proto, 9:PortStatus, ...
            assert row[7] == "135"                     # CORRECTED: Port Number
            assert row[8] == "tcp"                     # Port Protocol
            assert row[9] == "filtered"                # Port Status
            assert row[11] == ""                       # Service Name (no service on filtered port in sample)
            assert row[12] == ""                       # Service Product
            assert "host-script-info:some data" in row[6] # Host Scripts
            break
    assert found_host3, "CSV data for Host 3 (192.168.1.103) not found or incorrect."

    # ... (assertions for Host4, which has no ports at all, would verify an empty port row) ...
    # For Host4, if you add a check, it would be similar to Host3's original expectation
    # but ensuring it's specifically for Host4's IP.
    found_host4 = False
    for row in rows[1:]:
        if row[0] == "192.168.1.104": # Host4 IP
            found_host4 = True
            assert row[7] == "" # Port Number should be empty as no ports in datamodel
            assert row[11] == ""# Service Name should be empty
            break
    assert found_host4, "CSV data for Host 4 (192.168.1.104) not found or incorrect."


def test_export_to_csv_io_error(mocker, caplog):
    """Test IOError during CSV export."""
    engine = ARKEngine()
    mocker.patch.object(engine, 'nmap_handler', MagicMock())
    sample_results = get_sample_scan_results()
    mocker.patch('builtins.open', side_effect=IOError("Permission denied"))

    with caplog.at_level(logging.ERROR):
        engine.export_to_csv(sample_results, "restricted_output.csv")
    
    assert "IOError exporting results to CSV file restricted_output.csv: Permission denied" in caplog.text