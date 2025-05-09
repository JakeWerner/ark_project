# tests/test_engine.py
import pytest
from unittest.mock import MagicMock, patch
import subprocess

from autork.engine import ARKEngine
from autork.datamodels import Host, Port, Service, OSMatch
from autork.nmap_handler import NmapHandler
from typing import List, Dict, Any, Optional

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
    
    # Assert that engine passes timing_template to handler
    mock_run_ping_scan.assert_called_once_with(target_scope, timing_template=custom_timing)
    assert result_hosts == mock_return_value

def test_discover_live_hosts_no_hosts_up_default_timing(mocker):
    engine = ARKEngine()
    mocker.patch.object(engine.nmap_handler, 'run_ping_scan', return_value=[])
    engine.discover_live_hosts("10.0.0.0/24", timing_template=None) # Pass None
    # Assertion on the call to handler method
    engine.nmap_handler.run_ping_scan.assert_called_once_with("10.0.0.0/24", timing_template=None)


# --- Test ARKEngine.scan_host_deep (Updated for timing_template) ---
def test_scan_host_deep_all_features_enabled(mocker):
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.105", status="up")
    top_ports_arg=100; include_os_arg=True; nse_s="default"; nse_sa="arg=val"; timing_arg=3

    mock_handler_result: Dict[str, Any] = {"ports": [], "os_matches": [], "host_scripts": {}}
    mock_scan_method = mocker.patch.object(engine.nmap_handler,'run_port_scan_with_services', return_value=mock_handler_result)

    engine.scan_host_deep(
        input_host, top_ports=top_ports_arg, include_os_detection=include_os_arg,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=timing_arg
    )
    mock_scan_method.assert_called_once_with(
        input_host.ip, top_ports=top_ports_arg, include_os_detection=include_os_arg,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=timing_arg # Assert timing passed
    )

# ... (scan_host_deep_nmap_handler_returns_empty also needs timing_template in call and assertion)

# --- Test ARKEngine.scan_host_udp (Updated for timing_template) ---
def test_scan_host_udp_success(mocker):
    engine = ARKEngine()
    input_host = Host(ip="192.168.1.200", status="up")
    top_ports_udp = 50; include_ver_udp = True; timing_arg = 1
    mock_udp_ports = [Port(number=53, protocol='udp')]
    mock_handler_udp_scan = mocker.patch.object(engine.nmap_handler, 'run_udp_scan', return_value=mock_udp_ports)
    
    engine.scan_host_udp(input_host, top_ports=top_ports_udp, include_version=include_ver_udp, timing_template=timing_arg)
    
    mock_handler_udp_scan.assert_called_once_with(
        input_host.ip, top_ports=top_ports_udp, include_version=include_ver_udp, timing_template=timing_arg # Assert timing
    )

# --- Test ARKEngine.perform_basic_recon (Updated for timing_template) ---
def test_perform_basic_recon_all_features_enabled(mocker):
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
                                timing_template=timing_arg) # Pass timing

    mock_ping.assert_called_once_with(target_scope, timing_template=timing_arg) # Assert timing passed
    assert mock_tcp.call_count == 2
    mock_tcp.assert_any_call("192.168.1.1", top_ports=top_tcp, include_os_detection=inc_os, nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=timing_arg)
    mock_tcp.assert_any_call("192.168.1.5", top_ports=top_tcp, include_os_detection=inc_os, nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=timing_arg)
    if inc_udp:
        assert mock_udp.call_count == 2
        mock_udp.assert_any_call("192.168.1.1", top_ports=top_udp, include_version=True, timing_template=timing_arg)
        mock_udp.assert_any_call("192.168.1.5", top_ports=top_udp, include_version=True, timing_template=timing_arg)

# ... (other engine tests like _scripts_disabled should also be updated for timing_template) ...