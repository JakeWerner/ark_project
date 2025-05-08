import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import subprocess # Ensure this is imported
from pathlib import Path
from typing import Any # For type hinting if needed later

import pytest # Optional, but good for potential future pytest-specific features

# Assuming autork package is structured correctly and tests are run from ark_project root
from autork.nmap_handler import NmapHandler
from autork.datamodels import Host, Port, Service, OSMatch

# --- Test Setup: Path to test data ---
TEST_DIR = Path(__file__).resolve().parent # Gets the directory where this test file is located (tests/)
TEST_DATA_DIR = TEST_DIR / "test_data"    # Path to tests/test_data/

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
    return "" # Should not be reached if pytest.fail works

# --- Tests for NmapHandler.run_ping_scan ---

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_hosts_up(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    target_scope = "192.168.1.0/24" # Example target
    sample_xml = load_xml_from_file("ping_scan_success.xml")

    mock_response = MagicMock()
    mock_response.stdout = sample_xml
    mock_response.stderr = ""
    mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    result_hosts = handler.run_ping_scan(target_scope)

    expected_nmap_command = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=600
    )
    assert len(result_hosts) == 2
    host1 = next(h for h in result_hosts if h.ip == "192.168.1.1")
    host3 = next(h for h in result_hosts if h.ip == "192.168.1.3")
    assert host1.status == "up"
    assert host1.hostname == "host1.example.com"
    assert host3.status == "up"
    assert host3.hostname is None

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_no_hosts_up(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    target_scope = "192.168.1.0/24"
    sample_xml = load_xml_from_file("ping_scan_no_hosts_up.xml")

    mock_response = MagicMock()
    mock_response.stdout = sample_xml
    mock_response.stderr = ""
    mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    result_hosts = handler.run_ping_scan(target_scope)
    mock_subprocess_run.assert_called_once()
    assert len(result_hosts) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_fails(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    target_scope = "192.168.1.0/24"
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd=['nmap', '...'], stderr="Nmap failed!"
    )
    result_hosts = handler.run_ping_scan(target_scope)
    mock_subprocess_run.assert_called_once()
    assert len(result_hosts) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_not_found(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    target_scope = "192.168.1.0/24"
    mock_subprocess_run.side_effect = FileNotFoundError("Nmap not found")
    result_hosts = handler.run_ping_scan(target_scope)
    mock_subprocess_run.assert_called_once()
    assert len(result_hosts) == 0

# --- Tests for NmapHandler.run_port_scan_with_services ---

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_success(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    target_ip = "192.168.1.101"
    top_ports = 2
    include_os = True
    sample_xml = load_xml_from_file("port_os_scan_success.xml")

    mock_response = MagicMock()
    mock_response.stdout = sample_xml
    mock_response.stderr = ""
    mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os
    )

    expected_nmap_command = [
        handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), 
        '-O', '-oX', '-', target_ip
    ]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=600
    )

    assert "ports" in scan_results and len(scan_results["ports"]) == 3
    open_ports = [p for p in scan_results["ports"] if p.status == "open"]
    assert len(open_ports) == 2
    ssh_port = next((p for p in open_ports if p.number == 22), None)
    assert ssh_port and ssh_port.service and ssh_port.service.name == "ssh"
    http_port = next((p for p in open_ports if p.number == 80), None)
    assert http_port and http_port.service and http_port.service.name == "http"

    assert "os_matches" in scan_results and len(scan_results["os_matches"]) == 2
    assert scan_results["os_matches"][0].name == "Linux 4.15 - 5.8"
    
    assert scan_results.get("mac_address") == "AA:BB:CC:DD:EE:FF"
    assert scan_results.get("vendor") == "TestMACVendor"
    assert scan_results.get("uptime_seconds") == 1234567
    assert scan_results.get("last_boot") == "Mon Apr 28 10:00:00 2025"
    assert scan_results.get("distance") == 1

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_no_open_ports(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    target_ip = "192.168.1.102"
    top_ports = 20
    include_os = False
    sample_xml = load_xml_from_file("port_scan_no_open_ports.xml")

    mock_response = MagicMock()
    mock_response.stdout = sample_xml
    mock_response.stderr = ""
    mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os
    )

    expected_nmap_command = [
        handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports),
        '-oX', '-', target_ip # No -O
    ]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=600
    )
    assert "ports" in scan_results and len(scan_results["ports"]) == 0
    assert "os_matches" in scan_results and len(scan_results["os_matches"]) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_os_disabled(mock_subprocess_run: MagicMock):
    # 1. Arrange
    handler = NmapHandler()
    target_ip = "192.168.1.101" # Can use the same IP as success case
    top_ports = 2
    include_os = False # Explicitly disable OS detection
    
    # Use the success XML, but OS parsing part should be skipped by NmapHandler logic
    # or Nmap command should not include -O
    sample_xml = load_xml_from_file("port_os_scan_success.xml") 

    mock_response = MagicMock()
    mock_response.stdout = sample_xml # NmapHandler should ignore OS data if include_os is False
    mock_response.stderr = ""
    mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    # 2. Act
    scan_results = handler.run_port_scan_with_services(
        target_ip, 
        top_ports=top_ports, 
        include_os_detection=include_os # This is False
    )

    # 3. Assert
    # Check Nmap command call - ensure -O is NOT present
    actual_command_args = mock_subprocess_run.call_args[0][0]
    assert '-O' not in actual_command_args 
    
    # Port details should still be parsed
    assert "ports" in scan_results and len(scan_results["ports"]) == 3 # from port_os_scan_success.xml
    open_ports = [p for p in scan_results["ports"] if p.status == "open"]
    assert len(open_ports) == 2

    # OS matches should be empty because include_os_detection was False
    assert "os_matches" in scan_results and len(scan_results["os_matches"]) == 0


@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_nmap_fails(mock_subprocess_run: MagicMock): # Renamed for clarity
    # 1. Arrange
    handler = NmapHandler()
    target_ip = "192.168.1.101"
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd=['nmap', '...'], stderr="Nmap port scan failed!"
    )
    
    # 2. Act
    scan_results = handler.run_port_scan_with_services(target_ip, top_ports=20, include_os_detection=False)

    # 3. Assert
    mock_subprocess_run.assert_called_once()
    # Expecting default empty structure on failure
    assert scan_results.get("ports") == []
    assert scan_results.get("os_matches") == []
    assert scan_results.get("mac_address") is None


@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_os_disabled(mock_subprocess_run: MagicMock):
    """Verify Nmap command does not include -O and os_matches is empty if disabled."""
    # 1. Arrange
    handler = NmapHandler()
    target_ip = "192.168.1.101"
    top_ports = 5
    include_os = False # Explicitly disable OS detection

    # We can reuse the successful scan XML, as the test focuses on the command
    # sent to Nmap and ensuring OS results aren't parsed when disabled.
    sample_xml = load_xml_from_file("port_os_scan_success.xml")

    mock_response = MagicMock()
    mock_response.stdout = sample_xml
    mock_response.stderr = ""
    mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response

    # 2. Act
    scan_results = handler.run_port_scan_with_services(
        target_ip,
        top_ports=top_ports,
        include_os_detection=include_os # Passed as False
    )

    # 3. Assert
    # Check Nmap command call - ensure -O is NOT present
    expected_base_command = [
        handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip
    ]
    actual_command_args = mock_subprocess_run.call_args[0][0]
    
    # Verify the command matches the expected base, explicitly checking -O is absent
    assert actual_command_args == expected_base_command
    assert '-O' not in actual_command_args

    # Port details should still be parsed correctly from the sample XML
    assert "ports" in scan_results and len(scan_results["ports"]) == 3
    assert len([p for p in scan_results["ports"] if p.status == "open"]) == 2

    # OS matches should be empty because include_os_detection was False
    assert "os_matches" in scan_results
    assert len(scan_results["os_matches"]) == 0

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_nmap_command_fails(mock_subprocess_run: MagicMock):
    """Test behavior when the Nmap subprocess command fails."""
    # 1. Arrange
    handler = NmapHandler()
    target_ip = "192.168.1.101"

    # Simulate Nmap command failing by raising CalledProcessError
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(
        returncode=137, cmd=['nmap', '-sV', target_ip], stderr="Nmap terminated!"
    )

    # 2. Act
    scan_results = handler.run_port_scan_with_services(target_ip, top_ports=20, include_os_detection=False)

    # 3. Assert
    # Check Nmap command was attempted
    mock_subprocess_run.assert_called_once()

    # Expecting default empty/None structure on failure, as defined in the method
    assert isinstance(scan_results, dict)
    assert scan_results.get("ports") == []
    assert scan_results.get("os_matches") == []
    assert scan_results.get("mac_address") is None
    assert scan_results.get("vendor") is None
    assert scan_results.get("uptime_seconds") is None
    assert scan_results.get("last_boot") is None
    assert scan_results.get("distance") is None