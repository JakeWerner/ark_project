# tests/test_nmap_handler.py
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import subprocess
from pathlib import Path
from typing import Any, List, Optional

import pytest

from autork.nmap_handler import NmapHandler
from autork.datamodels import Host, Port, Service, OSMatch # Ensure all are imported

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
    return ""

# --- Tests for NmapHandler._get_validated_timing_template_value ---
def test_get_validated_timing_template_value():
    handler = NmapHandler()
    assert handler._get_validated_timing_template_value(None) == 4
    assert handler._get_validated_timing_template_value(0) == 0
    assert handler._get_validated_timing_template_value(3) == 3
    assert handler._get_validated_timing_template_value(5) == 5
    assert handler._get_validated_timing_template_value(6) == 4
    assert handler._get_validated_timing_template_value(-1) == 4
    assert handler._get_validated_timing_template_value("abc") == 4

# --- Tests for NmapHandler.run_ping_scan ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_ipv4_target_scope_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, timing_template=None, ipv6=False)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_ipv4_custom_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; custom_timing = 1
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, timing_template=custom_timing, ipv6=False)
    expected_cmd = [handler.nmap_path, '-sn', f'-T{custom_timing}', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_ipv4_invalid_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; invalid_timing = 7
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, timing_template=invalid_timing, ipv6=False)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_ipv6_success_default_timing(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope_ipv6 = "2001:db8::/64"
    sample_xml = load_xml_from_file("ping_scan_ipv6_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    result_hosts = handler.run_ping_scan(target_scope=target_scope_ipv6, ipv6=True, timing_template=None)
    expected_cmd = [handler.nmap_path, "-6", "-sn", "-T4", "-oX", "-", target_scope_ipv6]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)
    assert len(result_hosts) == 1 and result_hosts[0].ip == "2001:db8::1"

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_with_input_file_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_file = "targets.list"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(input_target_file=target_file, ipv6=False, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-iL', target_file, '-oX', '-']
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_with_input_file_ipv6(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_file = "ipv6_targets.list"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_ipv6_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(input_target_file=target_file, ipv6=True, timing_template=None)
    expected_cmd = [handler.nmap_path, '-6', '-sn', '-T4', '-iL', target_file, '-oX', '-']
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_with_exclude_string_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; exclude_str = "192.168.1.1"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, exclude_targets=exclude_str, ipv6=False, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '--exclude', exclude_str, '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_with_exclude_file_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"; exclude_f = "exclude.list"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, exclude_file=exclude_f, ipv6=False, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '--excludefile', exclude_f, '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_input_file_precedence_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "ignored"; target_file = "targets.list"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope=target_scope, input_target_file=target_file, ipv6=False, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-iL', target_file, '-oX', '-']
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_no_target_spec(mock_subprocess_run: MagicMock):
    handler = NmapHandler()
    assert handler.run_ping_scan(target_scope=None, input_target_file=None, ipv6=False) == []
    mock_subprocess_run.assert_not_called()

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_no_hosts_up(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_scope = "192.168.1.0/24"
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("ping_scan_no_hosts_up.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_ping_scan(target_scope, ipv6=False, timing_template=None)
    expected_cmd = [handler.nmap_path, '-sn', '-T4', '-oX', '-', target_scope]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_fails(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['nmap'], stderr="Fail")
    assert handler.run_ping_scan("target", ipv6=False, timing_template=None) == []

@patch('autork.nmap_handler.subprocess.run')
def test_run_ping_scan_nmap_not_found(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); mock_subprocess_run.side_effect = FileNotFoundError("Not found")
    assert handler.run_ping_scan("target", ipv6=False, timing_template=None) == []

# --- Tests for NmapHandler.run_port_scan_with_services ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_ipv4_default_behavior(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, ipv6=False, timing_template=None, tcp_scan_type=None, include_reason=False)
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_syn_scan_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="S", ipv6=False, timing_template=None, include_reason=False)
    expected_cmd = [handler.nmap_path, '-sS', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_connect_scan_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="T", ipv6=False, timing_template=None, include_reason=False)
    expected_cmd = [handler.nmap_path, '-sT', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_tcp_fin_scan_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="F", ipv6=False, timing_template=None, include_reason=False)
    expected_cmd = [handler.nmap_path, '-sF', '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_invalid_tcp_scan_type_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, tcp_scan_type="Invalid", ipv6=False, timing_template=None, include_reason=False)
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--top-ports', str(top_ports), '-oX', '-', target_ip] # No specific TCP flag
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_with_reason_enabled_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.101"; top_ports = 10
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(target_ip, top_ports=top_ports, include_reason=True, ipv6=False, timing_template=None, tcp_scan_type=None)
    expected_cmd = [handler.nmap_path, '-sV', '-T4', '--reason', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_all_options_custom_timing_ipv4(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip="192.168.1.105"; top_ports=5; include_os=True; nse_s="default"; nse_sa="user=admin"; custom_timing=1; tcp_st="S"; inc_reason=True
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("port_os_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_port_scan_with_services(
        target_ip, top_ports=top_ports, include_os_detection=include_os,
        nse_scripts=nse_s, nse_script_args=nse_sa, timing_template=custom_timing, tcp_scan_type=tcp_st, ipv6=False, include_reason=inc_reason
    )
    expected_cmd = [handler.nmap_path, f'-s{tcp_st}', '-sV', f'-T{custom_timing}', '--reason', '--top-ports', str(top_ports),
                    '-O', '--script', nse_s, '--script-args', nse_sa, '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_port_scan_ipv6_target_all_features(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip_ipv6 = "2001:db8::a"; top_ports = 2
    include_os=True; nse_s="default"; time_t=4; tcp_st="S"; inc_reason=True
    sample_xml = load_xml_from_file("port_scan_ipv6_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    scan_results = handler.run_port_scan_with_services(
        target_ip_ipv6, top_ports=top_ports, include_os_detection=include_os,
        nse_scripts=nse_s, timing_template=time_t, tcp_scan_type=tcp_st, ipv6=True, include_reason=inc_reason
    )
    expected_cmd = [handler.nmap_path, "-6", f"-s{tcp_st}", "-sV", f"-T{time_t}", "--reason",
                    "--top-ports", str(top_ports), "-O", "--script", nse_s,
                    "-oX", "-", target_ip_ipv6]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)
    # Add more assertions based on port_scan_ipv6_success.xml if needed
    assert len(scan_results["ports"]) == 2

# ... (Keep other existing port scan tests like _scripts_default_success, _with_script_and_args, _scripts_disabled, _args_without_scripts, _no_open_ports, _os_disabled_and_no_scripts, _nmap_command_fails.
#      Ensure they ALL pass ipv6=False, include_reason=False, and the correct timing/tcp_scan_type (often None for defaults)
#      and that their expected_nmap_command is accurate.)

# --- UDP Scan Tests (Updated for IPv6, timing, and include_reason) ---
@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_ipv4_default_timing_no_reason(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("udp_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=None, ipv6=False, include_reason=False)
    expected_cmd = [handler.nmap_path, '-sU', '-T4', '-sV', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_ipv4_with_reason(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip = "192.168.1.200"; top_ports = 3; include_ver = True
    mock_response = MagicMock(); mock_response.stdout = load_xml_from_file("udp_scan_success.xml"); mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip, top_ports=top_ports, include_version=include_ver, timing_template=None, ipv6=False, include_reason=True)
    expected_cmd = [handler.nmap_path, '-sU', '-T4', '-sV', '--reason', '--top-ports', str(top_ports), '-oX', '-', target_ip]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

@patch('autork.nmap_handler.subprocess.run')
def test_run_udp_scan_ipv6_success_with_reason(mock_subprocess_run: MagicMock):
    handler = NmapHandler(); target_ip_ipv6 = "2001:db8::b"; top_ports = 1; include_ver = True
    sample_xml = load_xml_from_file("udp_scan_ipv6_success.xml")
    mock_response = MagicMock(); mock_response.stdout = sample_xml; mock_response.returncode = 0
    mock_subprocess_run.return_value = mock_response
    handler.run_udp_scan(target_ip_ipv6, top_ports=top_ports, include_version=include_ver, ipv6=True, timing_template=None, include_reason=True)
    expected_cmd = [handler.nmap_path, "-6", "-sU", "-T4", "-sV", "--reason", "--top-ports", str(top_ports), "-oX", "-", target_ip_ipv6]
    mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=True, timeout=1800)

# ... (Add/update other UDP tests: _custom_timing, _invalid_timing, _version_disabled, _nmap_fails for both IPv4 and IPv6 contexts,
#      passing include_reason=False/True as appropriate and asserting the command.)