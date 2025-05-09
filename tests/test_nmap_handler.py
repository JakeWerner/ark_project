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
    assert handler._get_validated_timing_template_value(0) == 0
    assert handler._get_validated_timing_template_value(3) == 3
    assert handler._get_validated_timing_template_value(5) == 5
    assert handler._get_validated_timing_template_value(6) == 4
    assert handler._get_validated_timing_template_value("abc") == 4

# --- Tests for NmapHandler.run_ping_scan ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_target_scope_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope=target_scope, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)
    assert len(result_hosts) == 2

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; custom_timing = 2
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, timing_template=custom_timing)
    expected_cmd = [handler.nmap_path, '-sn', f'-T{custom_timing}', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_invalid_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; invalid_timing = 7
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, timing_template=invalid_timing)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_with_input_file(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_file = "targets.lst"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(input_target_file=target_file, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-iL', target_file, '-oX', '-']
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_with_exclude_string(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; exclude_str = "192.168.1.1"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, exclude_targets=exclude_str, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '--exclude', exclude_str, '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_with_exclude_file(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; exclude_f = "exclude.lst"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, exclude_file=exclude_f, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '--excludefile', exclude_f, '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_input_file_precedence(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "ignored"; target_file = "targets.lst"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, input_target_file=target_file, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-iL', target_file, '-oX', '-']
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_no_target_spec(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    results = handler.run_ping_scan(target_scope=None, input_target_file=None)
    mock_subprocess_run.assert_not_called()
    assert results == []

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


# --- Tests for NmapHandler.run_port_scan_with_services ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_default_behavior(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip="192.168.1.101"; top_ports=10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, timing_template=None, tcp_scan_type=None,
        include_os_detection=False, nse_scripts=None, nse_script_args=None
    )
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_syn_scan(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="S", timing_template=None)
    expected_cmd = [handler.nmap_path, '-sS', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_connect_scan(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="T", timing_template=None)
    expected_cmd = [handler.nmap_path, '-sT', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_invalid_tcp_scan_type(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="Invalid", timing_template=None)
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_all_options_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip="192.168.1.105"; top_ports=5; include_os=True; nse_s="default"; nse_sa="user=admin"; custom_timing=1; tcp_st="S"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=custom_timing, tcp_scan_type=tcp_st
    )
    expected_cmd = [handler.nmap_path, f'-s{tcp_st}', '-sV', f'-T{custom_timing}', '--top-ports', str(top_ports),
                    '-O', '--script', nse_s, '--script-args', nse_sa, '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_scripts_default_success_with_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 2
    nse_s="default"; sample_xml = load_xml_from_file("scan_with_scripts_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    scan_results = handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, nse_scripts=nse_s, timing_template=None, tcp_scan_type=None
    )
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '--script', nse_s, '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)
    assert "host_scripts" in scan_results and len(scan_results["host_scripts"]) == 2

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_script_and_args_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.105"; top_ports = 1
    nse_s = "http-title"; nse_sa = "http.useragent='TestAgent'"
    sample_xml = load_xml_from_file("scan_with_scripts_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=None, tcp_scan_type=None
    )
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports),
                    '--script', nse_s, '--script-args', nse_sa, '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

# --- UDP Scan Tests (Updated for timing) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_success_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("udp_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_ports = handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sU', '-T4', '-sV', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)
    assert len(result_ports) == 3

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True; custom_timing = 0
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("udp_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=custom_timing)
    expected_cmd = [handler.nmap_path, '-sU', f'-T{custom_timing}', '-sV', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_invalid_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True; invalid_timing = 7 # Example invalid
    sample_xml = load_xml_from_file("udp_scan_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=invalid_timing)
    expected_nmap_command = [
        handler.nmap_path, '-sU', 
        '-T4', # <<< Crucially, expect the handler's default for invalid input
        '-sV', 
        '--top-ports', str(top_ports), 
        '-oX', '-', target_ip
    ]
    mock_subprocess_run.assert_called_once_with(
        expected_nmap_command, capture_output=True, text=True, check=True, timeout=900
    )

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_version_disabled(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = False
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("udp_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sU', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip] # No -sV
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=900)

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_nmap_fails(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['nmap'], stderr="UDP Fail")
    assert handler.run_udp_scan("target", timing_template=None) == []