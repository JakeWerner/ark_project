# tests/test_nmap_handler.py
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import subprocess
from pathlib import Path
from typing import Any, List, Optional

import pytest

from autork.nmap_handler import NmapHandler
from autork.datamodels import Host, Port, Service, OSMatch

TEST_DIR = Path(__file__).resolve().parent
TEST_DATA_DIR = TEST_DIR / "test_data"

def load_xml_from_file(filename: str) -> str:
    xml_file_path = TEST_DATA_DIR / filename
    try:
        with open(xml_file_path, 'r', encoding='utf-8') as f: return f.read()
    except FileNotFoundError: pytest.fail(f"Test XML file not found: {xml_file_path}", pytrace=False)
    except Exception as e: pytest.fail(f"Error reading test XML file {xml_file_path}: {e}", pytrace=False)
    return ""

# --- Tests for NmapHandler._get_validated_timing_template_value ---
def test_get_validated_timing_template_value():
    handler = NmapHandler()
    assert handler._get_validated_timing_template_value(None) == 4
    assert handler._get_validated_timing_template_value(0) == 0; assert handler._get_validated_timing_template_value(5) == 5
    assert handler._get_validated_timing_template_value(6) == 4; assert handler._get_validated_timing_template_value("abc") == 4

# --- Tests for NmapHandler.run_ping_scan ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_hosts_up_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)
    assert len(result_hosts) == 2

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; custom_timing = 2
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope, timing_template=custom_timing)
    expected_cmd = [handler.nmap_path, '-sn', f'-T{custom_timing}', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_invalid_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; invalid_timing = 7
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope, timing_template=invalid_timing)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope] # Expects handler default T4
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_no_hosts_up(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_no_hosts_up.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)
    assert len(result_hosts) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_fails(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['nmap'], stderr="Fail")
    assert handler.run_ping_scan("target", timing_template=None) == []

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_not_found(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); mock_subprocess_run.side_effect = FileNotFoundError("Not found")
    assert handler.run_ping_scan("target", timing_template=None) == []

# --- Tests for NmapHandler.run_port_scan_with_services (Updated for tcp_scan_type and timing) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_default_behavior(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, timing_template=None, tcp_scan_type=None)
    # Expect no specific TCP scan type flag, Nmap defaults with -sV. Handler defaults to T4.
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_syn_scan(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="S", timing_template=None)
    expected_cmd = [handler.nmap_path, '-sS', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_connect_scan(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="T", timing_template=None)
    expected_cmd = [handler.nmap_path, '-sT', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_fin_scan(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    sample_xml = load_xml_from_file("port_os_scan_success.xml") # Use a generic success XML
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="F", timing_template=None)
    expected_cmd = [handler.nmap_path, '-sF', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)


@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_invalid_tcp_scan_type(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="Invalid", timing_template=None)
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip] # No specific TCP flag
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_all_options_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip="192.168.1.105"; top_ports=2; include_os=True; nse_s="default"; nse_sa="user=admin"; custom_timing=1; tcp_type="S"
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=custom_timing, tcp_scan_type=tcp_type
    )
    expected_cmd = [handler.nmap_path, f'-s{tcp_type}', '-sV', f'-T{custom_timing}', '--top-ports', str(top_ports),
                    '-O', '--script', nse_s, '--script-args', nse_sa, '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

# Ensure other port scan tests (scripts, no_open_ports, etc.) also pass tcp_scan_type=None and timing_template=None
# For example:
@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_scripts_default_success(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 2
    nse_scripts_param = "default"; sample_xml = load_xml_from_file("scan_with_scripts_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, nse_scripts=nse_scripts_param, tcp_scan_type=None, timing_template=None
    )
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '--script', nse_scripts_param, '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)
    # ... assertions for script output ...

# --- UDP Scan Tests (Updated for timing, tcp_scan_type is not applicable) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_success_default_timing(mock_subprocess_run: MagicMock):
    # ... (as before, no tcp_scan_type here) ...
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True
    sample_xml = load_xml_from_file("udp_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_ports = handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=None)
    expected_nmap_command = [handler.nmap_path, '-sU', '-T4', '-sV', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    assert len(result_ports) == 3

# ... (other UDP tests for custom_timing, invalid_timing, version_disabled, nmap_fails remain as is, as they don't use tcp_scan_type)