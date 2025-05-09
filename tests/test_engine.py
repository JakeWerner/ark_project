# tests/test_engine.py
import pytest
from unittest.mock import MagicMock, patch
import subprocess

from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
from autork.nmap_handler import NmapHandler # Not strictly needed unless patching NmapHandler class itself
from typing import List, Dict, Any, Optional

# --- Test ARKEngine Initialization ---
def test_arkengine_initialization(mocker):
    mock_nmap_handler_constructor = mocker.patch('autork.engine.NmapHandler')
    engine = ARKEngine(nmap_path="/custom/nmap")
    mock_nmap_handler_constructor.assert_called_once_with(nmap_path="/custom/nmap")

# --- Test ARKEngine.discover_live_hosts ---
def test_discover_live_hosts_success(mocker):
    # ... (remains the same) ...
    mock_host1 = Host(ip="192.168.1.1", status="up", hostname="host1.local")
    mock_return_value = [mock_host1]
    engine = ARKEngine()
    mock_run_ping_scan = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=mock_return_value)
    result_hosts = engine.discover_live_hosts("192.168.1.0/24")
    mock_run_ping_scan.assert_called_once_with("192.168.1.0/24")
    assert result_hosts == mock_return_value


def test_discover_live_hosts_no_hosts_up(mocker):
    # ... (remains the same) ...
    engine = ARKEngine()
    mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[])
    assert engine.discover_live_hosts("10.0.0.0/24") == []


# --- Test ARKEngine.scan_host_deep (Updated for nse_script_args) ---
def test_scan_host_deep_all_features_enabled(mocker): # Renamed for clarity
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.105", status="up")
    top_ports_arg = 100; include_os_arg = True; nse_scripts_param = "default"; nse_args_param = "http.useragent=ARK"

    mock_handler_result: Dict[str, Any] = {
        "ports": [Port(number=80, scripts={"http-title": "Title"})], "os_matches": [OSMatch(name="Linux")],
        "host_scripts": {"smb-os": "Win"}, "mac_address": "AA:BB:CC:DD:EE:FF"
    }
    mock_scan_method = mocker.patch.object(engine.nmap_handler,'run_port_scan_with_services', return_value=mock_handler_result)

    result_host = engine.scan_host_deep(
        input_host, top_ports=top_ports_arg, include_os_detection=include_os_arg,
        nse_scripts=nse_scripts_param, nse_script_args=nse_args_param # Pass all args
    )

    mock_scan_method.assert_called_once_with(
        input_host.ip, top_ports=top_ports_arg, include_os_detection=include_os_arg,
        nse_scripts=nse_scripts_param, nse_script_args=nse_args_param # Assert all args
    )
    assert result_host.ports[0].scripts.get("http-title") == "Title"
    assert result_host.host_scripts.get("smb-os") == "Win"
    assert result_host.os_matches[0].name == "Linux"
    assert result_host.mac_address == "AA:BB:CC:DD:EE:FF"

def test_scan_host_deep_nmap_handler_returns_empty(mocker):
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.101", status="up")
    mock_handler_result: Dict[str, Any] = { "ports": [], "os_matches": [], "mac_address": None, "host_scripts": {} }
    mock_scan_method = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_handler_result)
    
    # Call with nse_scripts and nse_script_args as None (or default)
    result_host = engine.scan_host_deep(input_host, top_ports=100, include_os_detection=False, nse_scripts=None, nse_script_args=None)
    
    mock_scan_method.assert_called_once_with(
        input_host.ip, top_ports=100, include_os_detection=False, nse_scripts=None, nse_script_args=None
    )
    assert result_host.ports == [] and result_host.os_matches == [] and result_host.host_scripts == {}

# --- Test ARKEngine.scan_host_udp (Remains the same) ---
def test_scan_host_udp_success(mocker):
    # ... (as before) ...
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.200", status="up", ports=[Port(number=80, protocol='tcp', status='open')])
    top_ports_udp = 50; include_ver_udp = True
    mock_udp_ports = [Port(number=53, protocol='udp', status='open', service=Service(name='domain'))]
    mock_handler_udp_scan = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=mock_udp_ports)
    engine.scan_host_udp(input_host, top_ports=top_ports_udp, include_version=include_ver_udp)
    mock_handler_udp_scan.assert_called_once_with(input_host.ip, top_ports=top_ports_udp, include_version=include_ver_udp)
    assert len(input_host.ports) == 2


# --- Test ARKEngine.perform_basic_recon (Updated for nse_script_args) ---
def test_perform_basic_recon_all_features_enabled(mocker): # Renamed for clarity
    engine = ARKEngine(); target_scope = "192.168.1.0/24"
    top_tcp=50; top_udp=25; inc_os=True; inc_udp=True; nse_s="default"; nse_sa="http.useragent='ARK'"

    mock_h1=Host(ip="192.168.1.1"); mock_h2=Host(ip="192.168.1.5")
    mock_ping = mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_h1, mock_h2])
    mock_tcp1: Dict[str, Any] = {"ports": [], "os_matches":[], "host_scripts": {}}
    mock_tcp2: Dict[str, Any] = {"ports": [], "os_matches":[], "host_scripts": {}}
    mock_tcp = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', side_effect=[mock_tcp1, mock_tcp2])
    mock_udp = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', side_effect=[[], []])

    engine.perform_basic_recon(target_scope, top_ports=top_tcp, include_os_detection=inc_os,
                                nse_scripts=nse_s, nse_script_args=nse_sa, # Pass args
                                include_udp_scan=inc_udp, top_udp_ports=top_udp)

    mock_ping.assert_called_once_with(target_scope)
    assert mock_tcp.call_count == 2
    mock_tcp.assert_any_call("192.168.1.1", top_ports=top_tcp, include_os_detection=inc_os, nse_scripts=nse_s, nse_script_args=nse_sa) # Assert args
    mock_tcp.assert_any_call("192.168.1.5", top_ports=top_tcp, include_os_detection=inc_os, nse_scripts=nse_s, nse_script_args=nse_sa) # Assert args
    assert mock_udp.call_count == 2


def test_perform_basic_recon_scripts_and_args_disabled(mocker): # Renamed
    engine = ARKEngine(); target_scope = "192.168.1.0/2"
    mock_h1 = Host(ip="192.168.1.1")
    mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[mock_h1])
    mock_tcp1: Dict[str, Any] = {"ports": [], "os_matches":[], "host_scripts": {}}
    mock_tcp = mocker.patch.object(engine.nmap_handler, 'run_port_scan_with_services', return_value=mock_tcp1)
    mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=[])

    engine.perform_basic_recon(target_scope, top_ports=10, nse_scripts=None, nse_script_args=None) # Pass None

    mock_tcp.assert_called_once_with("192.168.1.1", top_ports=10, include_os_detection=False, nse_scripts=None, nse_script_args=None) # Assert None