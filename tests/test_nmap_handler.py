# tests/test_nmap_handler.py
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import subprocess
from pathlib import Path
from typing import Any, List, Optional

import pytest # Not strictly required for these tests but good if you use its features

from autork.nmap_handler import NmapHandler
from autork.datamodels import Host, Port, Service, OSMatch # Ensure all used models are imported

# --- Test Setup: Path to test data ---
TEST_DIR = Path(__file__).resolve().parent
TEST_DATA_DIR = TEST_DIR / "test_data"

def load_xml_from_file(filename: str) -> str:
    """Helper function to load XML content from a file."""
    xml_file_path = TEST_DATA_DIR / filename
    try:
        with open(xml_file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        pytest.fail(f"Test XML file not found: {xml_file_path}", pytrace=False)
    except Exception as e:
        pytest.fail(f"Error reading test XML file {xml_file_path}: {e}", pytrace=False)
    return "" # Should not be reached

# --- Tests for NmapHandler._get_validated_timing_template_value ---
def test_get_validated_timing_template_value():
    handler = NmapHandler() # Need an instance to call the non-static method
    assert handler._get_validated_timing_template_value(None) == 4 # Handler default
    assert handler._get_validated_timing_template_value(0) == 0
    assert handler._get_validated_timing_template_value(3) == 3
    assert handler._get_validated_timing_template_value(5) == 5
    assert handler._get_validated_timing_template_value(6) == 4 # Invalid, defaults to 4
    assert handler._get_validated_timing_template_value(-1) == 4 # Invalid, defaults to 4
    assert handler._get_validated_timing_template_value("abc") == 4 # Invalid type, defaults to 4

# --- Tests for NmapHandler.run_ping_scan (Updated for timing) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_hosts_up_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    sample_xml = load_xml_from_file("ping_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope, timing_template=None) # Test with None
    expected_nmap_command = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope] # Expect handler's default T4
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    assert len(result_hosts) == 2

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; custom_timing = 2
    sample_xml = load_xml_from_file("ping_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope, timing_template=custom_timing)
    expected_nmap_command = [handler.nmap_path, '-sn', f'-T{custom_timing}', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_invalid_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; invalid_timing = 7
    sample_xml = load_xml_from_file("ping_scan_success.xml") # Content doesn't matter, just command
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope, timing_template=invalid_timing)
    expected_nmap_command = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope] # Expect handler's default T4
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_no_hosts_up(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    sample_xml = load_xml_from_file("ping_scan_no_hosts_up.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope, timing_template=None) # Test with default timing
    expected_nmap_command = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    assert len(result_hosts) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_fails(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['nmap'], stderr="Fail")
    assert handler.run_ping_scan("target", timing_template=None) == [] # Call with timing

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_not_found(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); mock_subprocess_run.side_effect = FileNotFoundError("Not found")
    assert handler.run_ping_scan("target", timing_template=None) == [] # Call with timing


# --- Tests for NmapHandler.run_port_scan_with_services (Updated for timing) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_all_features_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip="192.168.1.105"; top_ports=2; include_os=True; nse_s="default"; nse_sa="user=admin"
    sample_xml = load_xml_from_file("port_os_scan_success.xml") # Assumes this XML has OS and script-like data
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=None # Default T4
    )
    expected_nmap_command = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports),
                             '-O', '--script', nse_s, '--script-args', nse_sa, '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    # Add assertions for content based on port_os_scan_success.xml
    assert "ports" in scan_results and len(scan_results["ports"]) > 0
    assert "os_matches" in scan_results and len(scan_results["os_matches"]) > 0 # Expect OS matches


@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip="192.168.1.105"; top_ports=1; custom_timing=1
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, timing_template=custom_timing # Only testing timing here
    )
    expected_nmap_command = [handler.nmap_path, '-sV', f'-T{custom_timing}', '--top-ports', str(top_ports),
                             '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_invalid_timing_uses_default(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip="192.168.1.105"; top_ports=1; invalid_timing=7
    sample_xml = load_xml_from_file("port_os_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, timing_template=invalid_timing
    )
    expected_nmap_command = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), # Expects default T4
                             '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

# Keep and update existing port scan tests to pass timing_template=None (or specific values)
# and ensure their expected_nmap_command includes the correct -T flag (usually -T4 by default)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_scripts_default_success_with_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 2
    include_os = False; nse_scripts_param = "default"; nse_args_param = None
    sample_xml = load_xml_from_file("scan_with_scripts_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os,
        nse_scripts=nse_scripts_param, nse_script_args=nse_args_param, timing_template=None # Test default timing
    )
    expected_nmap_command = [
        handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), # Expect T4
        '--script', nse_scripts_param, '-oX', '-', target_ip
    ]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )
    # ... (assertions for script output as before) ...

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_script_and_args_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 1
    nse_scripts_param = "http-title"; nse_args_param = "http.useragent='TestAgent'"
    sample_xml = load_xml_from_file("scan_with_scripts_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, nse_scripts=nse_scripts_param, nse_script_args=nse_args_param, timing_template=None
    )
    expected_nmap_command = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports),
                             '--script', nse_scripts_param, '--script-args', nse_args_param,
                             '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

# ... (other port scan tests like _scripts_disabled, _args_without_scripts, _no_open_ports, _os_disabled, _nmap_fails updated similarly)

# --- UDP Scan Tests (Updated for timing) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_success_default_timing(mock_subprocess_run: MagicMock):
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

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True; custom_timing = 0
    sample_xml = load_xml_from_file("udp_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=custom_timing)
    expected_nmap_command = [handler.nmap_path, '-sU', f'-T{custom_timing}', '-sV', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_invalid_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True; invalid_timing = 6
    sample_xml = load_xml_from_file("udp_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=invalid_timing)
    expected_nmap_command = [handler.nmap_path, '-sU', '-T4', '-sV', '--top-ports', str(top_ports), '-oX', '-', target_ip] # Defaults to T4
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

# ... (Keep _version_disabled and _nmap_fails for UDP, update them to pass timing_template=None and assert default -T4 in command if applicable)