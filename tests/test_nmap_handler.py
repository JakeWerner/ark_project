# tests/test_nmap_handler.py
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import subprocess
from pathlib import Path
from typing import Any, List, Optional # Added Optional

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

# --- Ping Scan Tests (Remain the same) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_hosts_up(mock_subprocess_run: MagicMock):
    # ... (as before) ...
    handler = NmapHandler()
    target_scope = "192.168.1.0/24"
    sample_xml = load_xml_from_file("ping_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope)
    expected_nmap_command = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    assert len(result_hosts) == 2


@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_no_hosts_up(mock_subprocess_run: MagicMock):
    # ... (as before) ...
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    sample_xml = load_xml_from_file("ping_scan_no_hosts_up.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope)
    assert len(result_hosts) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_fails(mock_subprocess_run: MagicMock):
    # ... (as before) ...
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['nmap'], stderr="Fail")
    result_hosts = handler.run_ping_scan(target_scope)
    assert len(result_hosts) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_not_found(mock_subprocess_run: MagicMock):
    # ... (as before) ...
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    mock_subprocess_run.side_effect = FileNotFoundError("Not found")
    result_hosts = handler.run_ping_scan(target_scope)
    assert len(result_hosts) == 0

# --- Tests for NmapHandler.run_port_scan_with_services (Updated for nse_scripts and nse_script_args) ---

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_scripts_default_success(mock_subprocess_run: MagicMock): # Renamed
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 2
    include_os = False; nse_scripts_param = "default"; nse_args_param = None # Test default scripts
    sample_xml = load_xml_from_file("scan_with_scripts_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os,
        nse_scripts=nse_scripts_param, nse_script_args=nse_args_param
    )
    expected_nmap_command = [
        handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports),
        '--script', nse_scripts_param, # Expect --script default
        '-oX', '-', target_ip
    ]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    # ... (assertions for script output as before) ...
    assert "host_scripts" in scan_results and len(scan_results["host_scripts"]) == 2
    port80 = next((p for p in scan_results["ports"] if p.number == 80), None)
    assert port80 and port80.scripts and len(port80.scripts) == 2


@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_script_and_args(mock_subprocess_run: MagicMock): # NEW Test
    """Test using a custom script with arguments."""
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 1
    nse_scripts_param = "http-title"; nse_args_param = "http.useragent='TestAgent'"
    sample_xml = load_xml_from_file("scan_with_scripts_success.xml") # Reuse XML for structure
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, nse_scripts=nse_scripts_param, nse_script_args=nse_args_param
    )
    expected_nmap_command = [
        handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports),
        '--script', nse_scripts_param,
        '--script-args', nse_args_param, # Expect script args
        '-oX', '-', target_ip
    ]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_scripts_disabled(mock_subprocess_run: MagicMock): # Modified
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 2
    nse_scripts_param = None; nse_args_param = None # Disable scripts
    sample_xml = load_xml_from_file("scan_with_scripts_success.xml") # XML still has scripts
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, nse_scripts=nse_scripts_param, nse_script_args=nse_args_param
    )
    actual_command_args = mock_subprocess_run.call_args[0][0]
    assert '--script' not in actual_command_args # Should not be present
    assert '--script-args' not in actual_command_args # Should not be present
    assert len(scan_results["host_scripts"]) == 0 # Should be empty if not parsed
    port80 = next((p for p in scan_results["ports"] if p.number == 80), None)
    assert port80 and port80.scripts is None # Should be None if not parsed

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_script_args_without_scripts(mock_subprocess_run: MagicMock): # NEW Test
    """Test that --script-args is not added if nse_scripts is None."""
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 1
    nse_scripts_param = None; nse_args_param = "key=val" # Args provided, but no scripts
    sample_xml = load_xml_from_file("port_os_scan_success.xml") # Generic XML
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, nse_scripts=nse_scripts_param, nse_script_args=nse_args_param
    )
    actual_command_args = mock_subprocess_run.call_args[0][0]
    assert '--script' not in actual_command_args
    assert '--script-args' not in actual_command_args # Should not be added by handler


@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_no_open_ports(mock_subprocess_run: MagicMock):
    # ... (This test remains largely the same, just ensure nse_scripts=None is passed) ...
    handler = NmapHandler(); target_ip = "192.168.1.102"; top_ports = 20
    sample_xml = load_xml_from_file("port_scan_no_open_ports.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    scan_results = handler.run_port_scan_with_services(target_ip, top_ports=top_ports, nse_scripts=None)
    expected_nmap_command = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    assert len(scan_results["ports"]) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_os_disabled_and_no_scripts(mock_subprocess_run: MagicMock): # Renamed
    # ... (This test also ensures nse_scripts=None and OS disabled) ...
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 2
    include_os = False; nse_scripts_param = None
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os, nse_scripts=nse_scripts_param
    )
    expected_nmap_command = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    actual_command_args = mock_subprocess_run.call_args[0][0]
    assert actual_command_args == expected_nmap_command
    assert '-O' not in actual_command_args and '--script' not in actual_command_args
    assert len(scan_results["os_matches"]) == 0 and len(scan_results["host_scripts"]) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_nmap_command_fails(mock_subprocess_run: MagicMock):
    # ... (This test remains the same, nse_scripts=None by default) ...
    handler = NmapHandler(); target_ip = "192.168.1.101"
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['nmap'], stderr="Fail")
    scan_results = handler.run_port_scan_with_services(target_ip)
    assert scan_results.get("ports") == []

# --- UDP Scan Tests (Remain the same) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_success(mock_subprocess_run: MagicMock):
    # ... (as before) ...
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True
    sample_xml = load_xml_from_file("udp_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_ports = handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver)
    expected_nmap_command = [handler.nmap_path, '-sU', '-T4', '-sV', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    assert len(result_ports) == 3


@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_version_disabled(mock_subprocess_run: MagicMock):
    # ... (as before) ...
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = False
    sample_xml = load_xml_from_file("udp_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_ports = handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver)
    expected_nmap_command = [handler.nmap_path, '-sU', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    assert len(result_ports) == 3

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_nmap_fails(mock_subprocess_run: MagicMock):
    # ... (as before) ...
    handler = NmapHandler(); target_ip = "192.168.1.200"
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['nmap'], stderr="UDP Fail")
    result_ports = handler.run_udp_scan(target_ip)
    assert len(result_ports) == 0