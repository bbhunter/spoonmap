"""Tests for spoonmap.py"""
import datetime
import json
import textwrap
from unittest.mock import patch

import pytest
import xml.etree.ElementTree as etree

import spoonmap
from spoonmap import (
    EXTERNAL_PROBE_PORT_PRIORITY,
    EXTERNAL_SENSITIVE_PORTS,
    INTERNAL_PORT_SCRIPTS,
    PROBE_PORT_PRIORITY,
    SERVICE_CATEGORIES,
    _calc_scan_wait,
    _cleanup_cmd,
    _delete_previous_results,
    _get_scripts_for_port,
    _host_elem_to_dict,
    _previous_results_exist,
    _select_probe_ports,
    _write_findings_json,
    _write_findings_md,
    _write_findings_txt,
    generate_findings,
    is_hostname,
    lineCount,
    mass_scan,
)


# ── is_hostname ───────────────────────────────────────────────────────────────

class TestIsHostname:
    def test_ipv4_address(self):
        assert is_hostname('192.168.1.1') is False

    def test_cidr_notation(self):
        assert is_hostname('10.0.0.0/8') is False

    def test_host_cidr(self):
        assert is_hostname('192.168.1.5/32') is False

    def test_plain_hostname(self):
        assert is_hostname('example.com') is True

    def test_internal_hostname(self):
        assert is_hostname('internal-host') is True

    def test_subdomain(self):
        assert is_hostname('mail.corp.example.com') is True

    def test_empty_string(self):
        assert is_hostname('') is False

    def test_whitespace_only(self):
        assert is_hostname('   ') is False

    def test_comment_line(self):
        assert is_hostname('#192.168.0.0/24') is False

    def test_loopback(self):
        assert is_hostname('127.0.0.1') is False

    def test_hostname_with_surrounding_whitespace(self):
        assert is_hostname('  example.com  ') is True


# ── _select_probe_ports ───────────────────────────────────────────────────────

class TestSelectProbePorts:
    def test_selects_priority_ports_first(self):
        # 80, 443, 22 are all in PROBE_PORT_PRIORITY; 9999 is not
        result = _select_probe_ports(['9999', '80', '443', '22'])
        assert result[0] in ('80', '443', '22')
        assert '9999' not in result[:3] or len(result) > 3

    def test_respects_priority_ordering(self):
        # 443 is now first in PROBE_PORT_PRIORITY
        result = _select_probe_ports(['22', '443', '445'], max_ports=1)
        assert result == ['443']

    def test_caps_at_default_max(self):
        ports = ['445', '3389', '80', '443', '22', '135', '139']
        assert len(_select_probe_ports(ports)) == 5

    def test_custom_max_ports(self):
        ports = ['445', '3389', '80']
        assert len(_select_probe_ports(ports, max_ports=2)) == 2

    def test_falls_back_when_no_priority_match(self):
        ports = ['9997', '9998', '9999']
        result = _select_probe_ports(ports)
        assert result == ['9997', '9998', '9999']

    def test_fallback_also_caps_at_max(self):
        ports = ['9991', '9992', '9993', '9994', '9995', '9996']
        assert len(_select_probe_ports(ports)) == 5

    def test_empty_input(self):
        assert _select_probe_ports([]) == []

    def test_subset_of_priority_list(self):
        # Only two priority ports available; should return both, not pad with fallback
        result = _select_probe_ports(['22', '443'], max_ports=5)
        assert set(result) == {'22', '443'}


# ── _calc_scan_wait ────────────────────────────────────────────────────────────

class TestCalcScanWait:
    def test_small_network_gets_full_wait(self):
        # /24 = 256 hosts at 1000 pps → scan_duration ≈ 0.25s → wait ≈ 29s
        result = _calc_scan_wait(256, '1000')
        assert result == 29

    def test_large_network_gets_zero_wait(self):
        # /16 = 65536 hosts at 1000 pps → scan_duration ≈ 65s > 30s → wait = 0
        result = _calc_scan_wait(65536, '1000')
        assert result == 0

    def test_medium_network_partial_wait(self):
        # 1000 hosts at 1000 pps → scan_duration = 1s → wait = 29s
        result = _calc_scan_wait(1000, '1000')
        assert result == 29

    def test_none_host_count_returns_default(self):
        assert _calc_scan_wait(None, '1000') == 2

    def test_zero_host_count_returns_default(self):
        assert _calc_scan_wait(0, '1000') == 2

    def test_higher_rate_reduces_wait_threshold(self):
        # 10000 pps: 30000 hosts needed for scan_duration = 3s
        # 1000 hosts / 10000 pps = 0.1s → wait = 29s
        result = _calc_scan_wait(1000, '10000')
        assert result == 29

    def test_threshold_boundary(self):
        # 30000 hosts / 1000 pps = 30s = recovery_window → wait = 0
        result = _calc_scan_wait(30000, '1000')
        assert result == 0


# ── _get_scripts_for_port ─────────────────────────────────────────────────────

class TestGetScriptsForPort:
    def test_external_ssh(self):
        assert _get_scripts_for_port('22', 'External') == 'ssh-auth-methods,ssh2-enum-algos'

    def test_external_ftp(self):
        assert _get_scripts_for_port('21', 'External') == 'ftp-anon'

    def test_external_ssl_cert_ports(self):
        for port in ('443', '8443', '636', '10443'):
            assert 'ssl-cert' in _get_scripts_for_port(port, 'External'), port

    def test_external_mssql(self):
        assert _get_scripts_for_port('1433', 'External') == 'ms-sql-ntlm-info'

    def test_internal_ftp(self):
        assert _get_scripts_for_port('21', 'Internal') == 'ftp-anon'

    def test_internal_smb(self):
        result = _get_scripts_for_port('445', 'Internal')
        assert 'smb-security-mode' in result
        assert 'smb2-security-mode' in result
        assert 'smb-vuln-ms17-010' in result

    def test_internal_mssql(self):
        assert _get_scripts_for_port('1433', 'Internal') == 'ms-sql-info'

    def test_internal_udp_mssql(self):
        assert _get_scripts_for_port('U:1434', 'Internal') == 'ms-sql-info'

    def test_mssql_differs_by_scan_type(self):
        assert _get_scripts_for_port('1433', 'External') != _get_scripts_for_port('1433', 'Internal')

    def test_443_not_in_internal_table(self):
        # ssl-cert is external-only
        assert _get_scripts_for_port('443', 'Internal') is None

    def test_4786_external_uses_cisco_siet(self):
        result = _get_scripts_for_port('4786', 'External')
        assert result is not None and result.endswith('cisco-siet.nse')

    def test_4786_internal_uses_cisco_siet(self):
        result = _get_scripts_for_port('4786', 'Internal')
        assert result is not None and result.endswith('cisco-siet.nse')

    def test_445_internal_includes_ms17010(self):
        result = _get_scripts_for_port('445', 'Internal')
        assert result is not None and 'smb-vuln-ms17-010' in result

    def test_unknown_port_external(self):
        assert _get_scripts_for_port('9999', 'External') is None

    def test_unknown_port_internal(self):
        assert _get_scripts_for_port('9999', 'Internal') is None


# ── lineCount ─────────────────────────────────────────────────────────────────

class TestLineCount:
    def test_counts_lines(self, tmp_path):
        f = tmp_path / 'hosts.txt'
        f.write_text('10.0.0.1\n10.0.0.2\n10.0.0.3\n')
        assert lineCount(str(f)) == 3

    def test_empty_file_returns_zero(self, tmp_path):
        f = tmp_path / 'empty.txt'
        f.write_text('')
        assert lineCount(str(f)) == 0

    def test_missing_file_returns_zero(self, tmp_path):
        assert lineCount(str(tmp_path / 'nonexistent.txt')) == 0

    def test_single_line_no_newline(self, tmp_path):
        f = tmp_path / 'one.txt'
        f.write_text('10.0.0.1')
        assert lineCount(str(f)) == 1


# ── _write_findings_txt ───────────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    ('HIGH',   '10.0.0.1', 'tcp/21',   'Anonymous FTP',      'Login allowed'),
    ('MEDIUM', '10.0.0.2', 'tcp/22',   'Weak SSH Algorithms', 'arcfour offered'),
    ('INFO',   '10.0.0.3', 'tcp/1433', 'SQL Server Found',    'version info'),
]


class TestWriteFindingsTxt:
    def test_creates_file(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        assert (tmp_path / 'findings.txt').exists()

    def test_contains_severity_headings(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'HIGH' in content
        assert 'MEDIUM' in content
        assert 'INFO' in content

    def test_contains_host_and_title(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert '10.0.0.1' in content
        assert 'Anonymous FTP' in content

    def test_total_count_line(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert f'Total findings: {len(SAMPLE_FINDINGS)}' in content

    def test_empty_findings(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', [])
        assert 'Total findings: 0' in (tmp_path / 'findings.txt').read_text()

    def test_severity_ordering_in_output(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert content.index('HIGH') < content.index('MEDIUM') < content.index('INFO')


# ── _write_findings_md ────────────────────────────────────────────────────────

class TestWriteFindingsMd:
    def test_creates_file(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        assert (tmp_path / 'findings.md').exists()

    def test_markdown_report_header(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '# SpooNMAP Security Findings Report' in content

    def test_scan_type_in_header(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        assert 'External' in (tmp_path / 'findings.md').read_text()

    def test_contains_table_row(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '10.0.0.1' in content
        assert 'Anonymous FTP' in content

    def test_pipe_in_detail_is_escaped(self, tmp_path):
        findings = [('HIGH', '1.2.3.4', 'tcp/80', 'Test Finding', 'a|b|c')]
        _write_findings_md(str(tmp_path), 'Internal', findings)
        content = (tmp_path / 'findings.md').read_text()
        assert r'a\|b\|c' in content

    def test_total_count_line(self, tmp_path):
        _write_findings_md(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert f'**Total findings:** {len(SAMPLE_FINDINGS)}' in content

    def test_finding_title_is_h3_subheading(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '### Anonymous FTP' in content
        assert '### Weak SSH Algorithms' in content

    def test_finding_column_absent_from_table_header(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '| Host | Port | Detail |' in content
        assert '| Finding |' not in content

    def test_multiple_hosts_same_finding_single_heading(self, tmp_path):
        findings = [
            ('HIGH', '10.0.0.1', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
            ('HIGH', '10.0.0.2', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
            ('HIGH', '10.0.0.3', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
        ]
        _write_findings_md(str(tmp_path), 'Internal', findings)
        content = (tmp_path / 'findings.md').read_text()
        assert content.count('### Anonymous FTP') == 1
        assert '10.0.0.1' in content
        assert '10.0.0.2' in content
        assert '10.0.0.3' in content

    def test_different_findings_same_severity_separate_headings(self, tmp_path):
        findings = [
            ('HIGH', '10.0.0.1', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
            ('HIGH', '10.0.0.2', 'tcp/22', 'Weak SSH Auth', 'password accepted'),
        ]
        _write_findings_md(str(tmp_path), 'External', findings)
        content = (tmp_path / 'findings.md').read_text()
        assert '### Anonymous FTP' in content
        assert '### Weak SSH Auth' in content
        assert content.count('| Host | Port | Detail |') == 2


# ── _write_findings_json ──────────────────────────────────────────────────────

class TestWriteFindingsJson:
    def test_findings_written_as_json_array(self, tmp_path):
        findings = [('HIGH', '10.0.0.1', 'tcp/22', 'Weak SSH', 'detail')]
        _write_findings_json(str(tmp_path), findings)
        data = json.loads((tmp_path / 'findings.json').read_text())
        assert len(data) == 1
        assert data[0] == {'severity': 'HIGH', 'host': '10.0.0.1',
                           'port': 'tcp/22', 'title': 'Weak SSH', 'detail': 'detail'}

    def test_empty_findings_writes_empty_array(self, tmp_path):
        _write_findings_json(str(tmp_path), [])
        data = json.loads((tmp_path / 'findings.json').read_text())
        assert data == []

    def test_multiple_findings_all_fields_present(self, tmp_path):
        _write_findings_json(str(tmp_path), SAMPLE_FINDINGS)
        data = json.loads((tmp_path / 'findings.json').read_text())
        assert len(data) == len(SAMPLE_FINDINGS)
        for record in data:
            assert set(record.keys()) == {'severity', 'host', 'port', 'title', 'detail'}


# ── generate_findings ─────────────────────────────────────────────────────────

def _script_elems(scripts):
    return ''.join(
        '<script id="{}" output="{}"/>\n'.format(
            sid, out.replace('"', '&quot;').replace('\n', '&#10;')
        )
        for sid, out in (scripts or {}).items()
    )


def _nmap_xml(host_ip, protocol, portid, scripts=None, service_attrs=None):
    """Build a minimal nmap XML with scripts inside a <port> element."""
    service_elem = ''
    if service_attrs:
        attrs = ' '.join(f'{k}="{v}"' for k, v in service_attrs.items())
        service_elem = f'<service {attrs}/>'
    return textwrap.dedent(f"""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="{host_ip}" addrtype="ipv4"/>
            <ports>
              <port protocol="{protocol}" portid="{portid}">
                {service_elem}
                {_script_elems(scripts)}
              </port>
            </ports>
          </host>
        </nmaprun>
    """)


def _nmap_xml_hostscript(host_ip, protocol, portid, hostscripts):
    """Build a minimal nmap XML with scripts inside a <hostscript> element.

    SMB security-mode and ms-sql-info use hostrule and appear here in real
    nmap output, not inside <port>.
    """
    return textwrap.dedent(f"""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="{host_ip}" addrtype="ipv4"/>
            <ports>
              <port protocol="{protocol}" portid="{portid}"/>
            </ports>
            <hostscript>
              {_script_elems(hostscripts)}
            </hostscript>
          </host>
        </nmaprun>
    """)


@pytest.fixture()
def nmap_dir(tmp_path):
    d = tmp_path / 'nmap_results'
    d.mkdir()
    return tmp_path  # callers write files under tmp_path/nmap_results/


class TestGenerateFindings:
    # ── anonymous FTP ────────────────────────────────────────────────────────

    def test_anonymous_ftp_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Anonymous FTP' in content
        assert '10.0.0.1' in content

    def test_anonymous_ftp_not_triggered_when_denied(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login not allowed'})
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' not in (nmap_dir / 'findings.txt').read_text()

    def test_anonymous_ftp_suppressed_via_port_9100(self, nmap_dir):
        (nmap_dir / 'live_hosts').mkdir()
        (nmap_dir / 'live_hosts' / 'port9100.txt').write_text('10.0.0.3\n')
        xml = _nmap_xml('10.0.0.3', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' not in (nmap_dir / 'findings.txt').read_text()

    def test_anonymous_ftp_not_suppressed_for_different_host(self, nmap_dir):
        # port9100.txt lists a different IP — the scanned host is not a printer
        (nmap_dir / 'live_hosts').mkdir()
        (nmap_dir / 'live_hosts' / 'port9100.txt').write_text('10.0.0.99\n')
        xml = _nmap_xml('10.0.0.4', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' in (nmap_dir / 'findings.txt').read_text()

    # ── SMB signing ──────────────────────────────────────────────────────────

    def test_smb2_signing_not_required(self, nmap_dir):
        # smb2-security-mode is a hostrule script — appears under <hostscript>
        xml = _nmap_xml_hostscript('10.0.0.5', 'tcp', '445',
                                   hostscripts={'smb2-security-mode': 'Message signing enabled but not required'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Signing Not Required' in content
        assert '10.0.0.5' in content

    def test_smb_signing_required_not_flagged(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.5', 'tcp', '445',
                                   hostscripts={'smb2-security-mode': 'Message signing enabled and required'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Signing Not Required' not in (nmap_dir / 'findings.txt').read_text()

    # ── SMBv1 Enabled ─────────────────────────────────────────────────────────

    def test_smbv1_enabled_detected(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.6', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'account_used: guest message_signing: required'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Enabled' in content
        assert 'MEDIUM' in content
        assert '10.0.0.6' in content

    def test_smbv1_enabled_not_on_external(self, nmap_dir):
        xml = _nmap_xml_hostscript('1.2.3.4', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'account_used: guest message_signing: required'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'SMBv1 Enabled' not in (nmap_dir / 'findings.txt').read_text()

    def test_smbv1_enabled_and_signing_not_required_both_fire(self, nmap_dir):
        # Signing disabled implies SMBv1 is active — both findings should appear
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'message_signing: disabled (dangerous, but default)'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Enabled' in content
        assert 'SMBv1 Signing Not Required' in content
        assert '10.0.0.9' in content

    # ── EternalBlue (MS17-010) ────────────────────────────────────────────────

    def test_ms17010_vulnerable_critical_finding(self, nmap_dir):
        # smb-vuln-ms17-010 is a hostrule script — appears under <hostscript>
        xml = _nmap_xml_hostscript('10.0.0.7', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'MS17-010' in content
        assert 'CRITICAL' in content
        assert '10.0.0.7' in content

    def test_ms17010_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.7', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'NOT VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'MS17-010' not in (nmap_dir / 'findings.txt').read_text()

    def test_ms17010_only_on_internal(self, nmap_dir):
        # Should not fire on External scans
        xml = _nmap_xml_hostscript('1.2.3.4', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'MS17-010' not in (nmap_dir / 'findings.txt').read_text()

    # ── MS08-067 (NetAPI / Conficker) ─────────────────────────────────────────

    def test_ms08067_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.8', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms08-067': 'VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'MS08-067' in content
        assert 'CRITICAL' in content
        assert '10.0.0.8' in content

    def test_ms08067_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.8', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms08-067': 'NOT VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'MS08-067' not in (nmap_dir / 'findings.txt').read_text()

    # ── DoublePulsar ──────────────────────────────────────────────────────────

    def test_doublepulsar_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-double-pulsar-backdoor': 'VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'DoublePulsar' in content
        assert 'CRITICAL' in content

    def test_doublepulsar_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-double-pulsar-backdoor': 'NOT VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'DoublePulsar' not in (nmap_dir / 'findings.txt').read_text()

    # ── SambaCry ──────────────────────────────────────────────────────────────

    def test_sambacry_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={'smb-vuln-cve-2017-7494': 'VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SambaCry' in content
        assert 'CRITICAL' in content

    def test_sambacry_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={'smb-vuln-cve-2017-7494': 'NOT VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SambaCry' not in (nmap_dir / 'findings.txt').read_text()

    # ── Unauthenticated Docker API ────────────────────────────────────────────

    def test_docker_api_exposed_on_2375(self, nmap_dir):
        xml = _nmap_xml('10.0.0.12', 'tcp', '2375',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nmap_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Docker API' in content
        assert 'CRITICAL' in content
        assert '10.0.0.12' in content

    def test_docker_api_exposed_on_4243(self, nmap_dir):
        xml = _nmap_xml('10.0.0.12', 'tcp', '4243',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nmap_results' / 'port4243.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Docker API' in (nmap_dir / 'findings.txt').read_text()

    def test_docker_api_no_response_no_finding(self, nmap_dir):
        # No docker-version script output means API did not respond
        xml = _nmap_xml('10.0.0.12', 'tcp', '2375')
        (nmap_dir / 'nmap_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Docker API' not in (nmap_dir / 'findings.txt').read_text()

    def test_docker_api_fires_on_external_too(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '2375',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nmap_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Docker API' in (nmap_dir / 'findings.txt').read_text()

    # ── NTLM info disclosure ─────────────────────────────────────────────────

    def test_ntlm_disclosure_on_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '25',
                        scripts={'smtp-ntlm-info': 'NetBIOS_Domain_Name: CORP'})
        (nmap_dir / 'nmap_results' / 'port25.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'NTLM Information Disclosure' in (nmap_dir / 'findings.txt').read_text()

    def test_ntlm_disclosure_not_on_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.2', 'tcp', '25',
                        scripts={'smtp-ntlm-info': 'NetBIOS_Domain_Name: CORP'})
        (nmap_dir / 'nmap_results' / 'port25.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'NTLM Information Disclosure' not in (nmap_dir / 'findings.txt').read_text()

    # ── external sensitive port exposure ─────────────────────────────────────

    def test_sensitive_port_flagged_on_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '445')
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Service Exposed Externally' in (nmap_dir / 'findings.txt').read_text()

    def test_sensitive_port_not_flagged_on_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '445')
        (nmap_dir / 'nmap_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Service Exposed Externally' not in (nmap_dir / 'findings.txt').read_text()

    # ── TLS certificate expiry ────────────────────────────────────────────────

    def test_expired_cert_flagged(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Not valid after:  2020-06-01T00:00:00'})
        (nmap_dir / 'nmap_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Expired TLS Certificate' in (nmap_dir / 'findings.txt').read_text()

    def test_valid_cert_not_flagged(self, nmap_dir):
        future = datetime.date.today().replace(
            year=datetime.date.today().year + 2
        ).isoformat()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': f'Not valid after:  {future}T00:00:00'})
        (nmap_dir / 'nmap_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Expired TLS Certificate' not in (nmap_dir / 'findings.txt').read_text()

    # ── known-bad service detection ───────────────────────────────────────────

    def test_dameware_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '6129',
                        service_attrs={'name': 'dameware',
                                       'product': 'DameWare Mini Remote Control'})
        (nmap_dir / 'nmap_results' / 'port6129.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Dameware' in (nmap_dir / 'findings.txt').read_text()

    def test_cisco_smart_install_vulnerable(self, nmap_dir):
        # cisco-siet.nse confirms VULNERABLE → finding raised
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786',
                        scripts={'cisco-siet': 'Host: 10.0.0.1  Status: VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' in (nmap_dir / 'findings.txt').read_text()

    def test_cisco_smart_install_not_vulnerable_no_finding(self, nmap_dir):
        # cisco-siet.nse returns NOT VULNERABLE → no finding
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786',
                        scripts={'cisco-siet': 'Host: 10.0.0.1  Status: NOT VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' not in (nmap_dir / 'findings.txt').read_text()

    def test_cisco_smart_install_no_script_no_finding(self, nmap_dir):
        # port 4786 open but no cisco-siet script output → no finding (avoid false positives)
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786')
        (nmap_dir / 'nmap_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' not in (nmap_dir / 'findings.txt').read_text()

    def test_sap_gateway_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '3300')
        (nmap_dir / 'nmap_results' / 'port3300.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SAP Gateway' in (nmap_dir / 'findings.txt').read_text()

    # ── output files ─────────────────────────────────────────────────────────

    def test_both_output_files_created(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert (nmap_dir / 'findings.txt').exists()
        assert (nmap_dir / 'findings.md').exists()

    def test_no_output_when_nmap_results_missing(self, tmp_path):
        generate_findings(str(tmp_path), 'Internal')
        assert not (tmp_path / 'findings.txt').exists()

    def test_severity_order_in_output(self, nmap_dir):
        # HIGH from ftp-anon, INFO from ms-sql-info — HIGH must come first
        # ms-sql-info is a hostrule script — appears under <hostscript>
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(
            _nmap_xml('10.0.0.1', 'tcp', '21',
                      scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        )
        (nmap_dir / 'nmap_results' / 'port1433.xml').write_text(
            _nmap_xml_hostscript('10.0.0.2', 'tcp', '1433',
                                 hostscripts={'ms-sql-info': 'SQL Server 2019'})
        )
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert content.index('HIGH') < content.index('INFO')

    def test_generate_findings_writes_json(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        data = json.loads((nmap_dir / 'findings.json').read_text())
        assert any(r['title'] == 'Anonymous FTP' for r in data)


# ── _previous_results_exist / _delete_previous_results ───────────────────────

class TestPreviousResults:
    def test_empty_dir_returns_false(self, tmp_path):
        assert _previous_results_exist(str(tmp_path)) is False

    def test_detects_masscan_results_dir(self, tmp_path):
        d = tmp_path / 'masscan_results'
        d.mkdir()
        (d / 'port80.xml').write_text('<nmaprun/>')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_live_hosts_dir(self, tmp_path):
        d = tmp_path / 'live_hosts'
        d.mkdir()
        (d / 'port80.txt').write_text('10.0.0.1\n')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_nmap_results_dir(self, tmp_path):
        d = tmp_path / 'nmap_results'
        d.mkdir()
        (d / 'port22.xml').write_text('<nmaprun/>')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_aggregate_file(self, tmp_path):
        (tmp_path / 'all_live_hosts.txt').write_text('10.0.0.1\n')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_spoonmap_output_xml(self, tmp_path):
        (tmp_path / 'spoonmap_output.xml').write_text('<nmaprun/>')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_findings_txt(self, tmp_path):
        (tmp_path / 'findings.txt').write_text('findings\n')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_empty_result_dir_not_detected(self, tmp_path):
        # An empty result directory is not considered a previous run
        (tmp_path / 'masscan_results').mkdir()
        assert _previous_results_exist(str(tmp_path)) is False

    def test_delete_removes_result_dirs(self, tmp_path):
        for d in ('masscan_results', 'live_hosts', 'nmap_results'):
            p = tmp_path / d
            p.mkdir()
            (p / 'file.xml').write_text('<nmaprun/>')
        _delete_previous_results(str(tmp_path))
        for d in ('masscan_results', 'live_hosts', 'nmap_results'):
            assert not (tmp_path / d).exists()

    def test_delete_removes_aggregate_files(self, tmp_path):
        for f in ('all_live_hosts.txt', 'masscan_targets.txt',
                  'ip_hostname_map.json', 'spoonmap_output.xml',
                  'findings.txt', 'findings.md'):
            (tmp_path / f).write_text('data')
        _delete_previous_results(str(tmp_path))
        for f in ('all_live_hosts.txt', 'masscan_targets.txt',
                  'ip_hostname_map.json', 'spoonmap_output.xml',
                  'findings.txt', 'findings.md'):
            assert not (tmp_path / f).exists()

    def test_delete_leaves_other_files_untouched(self, tmp_path):
        (tmp_path / 'config.json').write_text('{}')
        (tmp_path / 'ranges.txt').write_text('10.0.0.0/24\n')
        _delete_previous_results(str(tmp_path))
        assert (tmp_path / 'config.json').exists()
        assert (tmp_path / 'ranges.txt').exists()

    def test_delete_is_idempotent(self, tmp_path):
        # Calling delete on a clean dir must not raise
        _delete_previous_results(str(tmp_path))
        _delete_previous_results(str(tmp_path))

    def test_false_after_delete(self, tmp_path):
        d = tmp_path / 'nmap_results'
        d.mkdir()
        (d / 'port22.xml').write_text('<nmaprun/>')
        (tmp_path / 'findings.txt').write_text('x')
        _delete_previous_results(str(tmp_path))
        assert _previous_results_exist(str(tmp_path)) is False


# ── SERVICE_CATEGORIES docker ports ───────────────────────────────────────────

class TestServiceCategoriesDockerPorts:
    def test_specialized_includes_port_9100(self):
        assert '9100' in SERVICE_CATEGORIES['Specialized']

    def test_specialized_includes_docker_port_2375(self):
        assert '2375' in SERVICE_CATEGORIES['Specialized']

    def test_specialized_includes_docker_port_4243(self):
        assert '4243' in SERVICE_CATEGORIES['Specialized']

    def test_remote_management_includes_winrm_5985(self):
        assert '5985' in SERVICE_CATEGORIES['Remote Management']

    def test_remote_management_includes_winrm_5986(self):
        assert '5986' in SERVICE_CATEGORIES['Remote Management']

    def test_web_includes_weblogic_7001(self):
        assert '7001' in SERVICE_CATEGORIES['Web']

    def test_web_includes_weblogic_7002(self):
        assert '7002' in SERVICE_CATEGORIES['Web']

    def test_weblogic_ports_in_external_sensitive(self):
        sensitive_ports = {p for p, _, _ in EXTERNAL_SENSITIVE_PORTS}
        assert '7001' in sensitive_ports
        assert '7002' in sensitive_ports


# ── Full Port Scan in mass_scan() ─────────────────────────────────────────────

class TestFullPortScan:
    def test_full_scan_skips_probe_and_calls_masscan_with_range(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'80': {'10.0.0.1'}, '443': {'10.0.0.2'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results) as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '20000',
                               '/fake/targets.txt', '')
        mock_batch.assert_called_once_with(
            ['1-65535'], '10000',   # capped from 20000 (External cap)
            str(tmp_path) + '/masscan_results/portFull.xml',
            '/fake/targets.txt', '53', '',
            wait_secs=2,
        )
        assert 'Hosts Found on Port 80' in result
        assert 'Hosts Found on Port 443' in result

    def test_full_scan_rate_capped_internal(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'22': {'10.0.0.1'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results) as mock_batch:
            mass_scan('Full', ['1-65535'], '88', '2000', '/fake/targets.txt', '')
        mock_batch.assert_called_once_with(
            ['1-65535'], '1000',   # capped from 2000 (Internal cap)
            str(tmp_path) + '/masscan_results/portFull.xml',
            '/fake/targets.txt', '88', '',
            wait_secs=2,
        )

    def test_full_scan_writes_live_hosts_files(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'22': {'10.0.0.5', '10.0.0.6'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results):
            mass_scan('Full', ['1-65535'], '53', '10000', '/fake/targets.txt', '')
        live_file = tmp_path / 'live_hosts' / 'port22.txt'
        assert live_file.exists()
        assert '10.0.0.5' in live_file.read_text()
        assert '10.0.0.6' in live_file.read_text()


# ── Config: Full scan_categories ──────────────────────────────────────────────

class TestConfigFullScanCategory:
    def _resolve(self, scan_categories):
        """Replicate the config-loading branch logic for scan_categories."""
        all_ports = []
        scan_type = ''
        if scan_categories == 'All' or scan_categories == ['All']:
            scan_type = 'All'
            all_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
        elif scan_categories in ('Full', ['Full']):
            scan_type = 'Full'
            all_ports = ['1-65535']
        elif isinstance(scan_categories, list):
            valid = [c for c in scan_categories if c in SERVICE_CATEGORIES]
            scan_type = ', '.join(valid)
            all_ports = [p for name in valid for p in SERVICE_CATEGORIES[name]]
        dest_ports = [p for p in all_ports if not p.startswith('U:')] + \
                     [p for p in all_ports if p.startswith('U:')]
        return scan_type, dest_ports

    def test_full_string_sets_scan_type_and_ports(self):
        scan_type, dest_ports = self._resolve('Full')
        assert scan_type == 'Full'
        assert dest_ports == ['1-65535']

    def test_full_list_sets_scan_type_and_ports(self):
        scan_type, dest_ports = self._resolve(['Full'])
        assert scan_type == 'Full'
        assert dest_ports == ['1-65535']

    def test_all_is_unaffected(self):
        scan_type, dest_ports = self._resolve('All')
        assert scan_type == 'All'
        assert '1-65535' not in dest_ports


# ── config source port derivation ────────────────────────────────────────────

class TestConfigSourcePort:
    """Config-file branch must derive source_port from target_scan."""

    def _source_port_for(self, target_scan_value):
        """Replicate the config-branch source_port logic."""
        return '53' if target_scan_value == 'External' else '88'

    def test_internal_scan_uses_source_port_88(self):
        assert self._source_port_for('Internal') == '88'

    def test_external_scan_uses_source_port_53(self):
        assert self._source_port_for('External') == '53'


# ── _cleanup_cmd ──────────────────────────────────────────────────────────────

class TestCleanupCmd:
    def _make_scan_data(self, tmp_path):
        """Populate tmp_path with representative scan output."""
        (tmp_path / 'nmap_results').mkdir()
        (tmp_path / 'nmap_results' / 'port445.xml').write_text('<nmaprun/>')
        (tmp_path / 'findings.txt').write_text('findings')
        (tmp_path / 'all_live_hosts.txt').write_text('10.0.0.1\n')

    def test_cleanup_with_explicit_path(self, tmp_path, capsys):
        self._make_scan_data(tmp_path)
        with patch('sys.argv', ['spoonmap.py', '--cleanup', str(tmp_path)]):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 0
        assert not (tmp_path / 'nmap_results').exists()
        assert not (tmp_path / 'findings.txt').exists()
        assert 'removed' in capsys.readouterr().out

    def test_cleanup_uses_config_json_path(self, tmp_path, capsys):
        out_dir = tmp_path / 'output'
        out_dir.mkdir()
        self._make_scan_data(out_dir)
        cfg = tmp_path / 'config.json'
        cfg.write_text(f'{{"output_path": "{out_dir}"}}')
        with patch('sys.argv', ['spoonmap.py', '--cleanup']):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 0
        assert not _previous_results_exist(str(out_dir))

    def test_cleanup_no_data_exits_cleanly(self, tmp_path, capsys):
        with patch('sys.argv', ['spoonmap.py', '--cleanup', str(tmp_path)]):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 0
        assert 'No scan data' in capsys.readouterr().out

    def test_cleanup_missing_dir_exits_error(self, tmp_path, capsys):
        missing = str(tmp_path / 'nonexistent')
        with patch('sys.argv', ['spoonmap.py', '--cleanup', missing]):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 1

    def test_cleanup_no_path_no_config_exits_error(self, tmp_path, capsys):
        with patch('sys.argv', ['spoonmap.py', '--cleanup']):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 1
        assert 'Usage' in capsys.readouterr().out

    def test_cleanup_removes_json_files(self, tmp_path, capsys):
        self._make_scan_data(tmp_path)
        (tmp_path / 'findings.json').write_text('[]')
        (tmp_path / 'spoonmap_output.json').write_text('[]')
        with patch('sys.argv', ['spoonmap.py', '--cleanup', str(tmp_path)]):
            with pytest.raises(SystemExit):
                _cleanup_cmd(str(tmp_path))
        assert not (tmp_path / 'findings.json').exists()
        assert not (tmp_path / 'spoonmap_output.json').exists()


# ── snmp-brute finding ────────────────────────────────────────────────────────

class TestSnmpBruteFinding:
    def test_snmp_brute_generates_finding_for_non_printer(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials\nprivate - Valid credentials'},
            service_attrs={'name': 'snmp', 'product': 'Net-SNMP'},
        )
        (nmap_dir / 'nmap_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' in content
        assert '10.0.0.5' in content

    def test_snmp_brute_community_strings_listed_in_detail(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials\nprivate - Valid credentials'},
        )
        (nmap_dir / 'nmap_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'public' in content
        assert 'private' in content

    def test_snmp_brute_suppressed_via_port_9100(self, nmap_dir):
        (nmap_dir / 'live_hosts').mkdir()
        (nmap_dir / 'live_hosts' / 'port9100.txt').write_text('10.0.0.12\n')
        xml = _nmap_xml('10.0.0.12', 'udp', '161',
                        scripts={'snmp-brute': 'public - Valid credentials'})
        (nmap_dir / 'nmap_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SNMP Default Community String' not in (nmap_dir / 'findings.txt').read_text()

    def test_snmp_brute_no_valid_creds_no_finding(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - No response\nprivate - No response'},
        )
        (nmap_dir / 'nmap_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' not in content

    def test_snmp_brute_tcp_port_161_also_checked(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.7', 'tcp', '161',
            scripts={'snmp-brute': 'public - Valid credentials'},
        )
        (nmap_dir / 'nmap_results' / 'port161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' in content


# ── INTERNAL_PORT_SCRIPTS includes snmp-brute ─────────────────────────────────

class TestInternalPortScriptsSnmp:
    def test_snmp_tcp_161_included(self):
        assert '161' in INTERNAL_PORT_SCRIPTS
        assert 'snmp-brute' in INTERNAL_PORT_SCRIPTS['161']

    def test_snmp_udp_161_included(self):
        assert 'U:161' in INTERNAL_PORT_SCRIPTS
        assert 'snmp-brute' in INTERNAL_PORT_SCRIPTS['U:161']


# ── _host_elem_to_dict ────────────────────────────────────────────────────────

class TestHostElemToDict:
    def _host_elem(self, ip, protocol='tcp', portid='80', state='open',
                   service_name='', product='', version='',
                   port_scripts=None, hostscripts=None):
        """Build a minimal <host> element for testing."""
        port_script_xml = ''.join(
            f'<script id="{sid}" output="{out}"/>'
            for sid, out in (port_scripts or {}).items()
        )
        hostscript_xml = ''
        if hostscripts:
            inner = ''.join(
                f'<script id="{sid}" output="{out}"/>'
                for sid, out in hostscripts.items()
            )
            hostscript_xml = f'<hostscript>{inner}</hostscript>'
        svc_xml = (f'<service name="{service_name}" product="{product}" version="{version}"/>'
                   if service_name or product or version else '')
        xml = (
            f'<host>'
            f'<address addr="{ip}" addrtype="ipv4"/>'
            f'<ports>'
            f'<port protocol="{protocol}" portid="{portid}">'
            f'<state state="{state}"/>'
            f'{svc_xml}'
            f'{port_script_xml}'
            f'</port>'
            f'</ports>'
            f'{hostscript_xml}'
            f'</host>'
        )
        return etree.fromstring(xml)

    def test_basic_port_parsed(self):
        elem = self._host_elem('10.0.0.1', protocol='tcp', portid='443', state='open')
        result = _host_elem_to_dict(elem)
        assert result['ip'] == '10.0.0.1'
        assert len(result['ports']) == 1
        p = result['ports'][0]
        assert p['protocol'] == 'tcp'
        assert p['portid'] == '443'
        assert p['state'] == 'open'

    def test_hostname_included_when_provided(self):
        elem = self._host_elem('10.0.0.2')
        result = _host_elem_to_dict(elem, ip_to_hostname={'10.0.0.2': 'host.example.com'})
        assert result['hostname'] == 'host.example.com'

    def test_hostname_omitted_when_not_in_map(self):
        elem = self._host_elem('10.0.0.3')
        result = _host_elem_to_dict(elem, ip_to_hostname={'10.0.0.99': 'other.example.com'})
        assert 'hostname' not in result

    def test_hostname_omitted_when_no_map(self):
        elem = self._host_elem('10.0.0.4')
        result = _host_elem_to_dict(elem)
        assert 'hostname' not in result

    def test_hostscripts_parsed(self):
        elem = self._host_elem('10.0.0.5', hostscripts={'smb2-security-mode': 'signing not required'})
        result = _host_elem_to_dict(elem)
        assert result['hostscripts'] == {'smb2-security-mode': 'signing not required'}

    def test_port_scripts_parsed(self):
        elem = self._host_elem('10.0.0.6', port_scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        result = _host_elem_to_dict(elem)
        assert result['ports'][0]['scripts'] == {'ftp-anon': 'Anonymous FTP login allowed'}

    def test_service_fields_parsed(self):
        elem = self._host_elem('10.0.0.7', service_name='http', product='Apache', version='2.4')
        result = _host_elem_to_dict(elem)
        p = result['ports'][0]
        assert p['service'] == 'http'
        assert p['product'] == 'Apache'
        assert p['version'] == '2.4'

    def test_missing_ports_element_returns_empty_list(self):
        xml = '<host><address addr="10.0.0.8" addrtype="ipv4"/></host>'
        elem = etree.fromstring(xml)
        result = _host_elem_to_dict(elem)
        assert result['ports'] == []
        assert result['hostscripts'] == {}


# ── TestMassScanProbe ─────────────────────────────────────────────────────────

class TestMassScanProbe:
    """Tests for the adaptive probe logic inside mass_scan()."""

    def _make_batch_side_effect(self, responses):
        """Return a side_effect callable that yields successive response dicts."""
        call_iter = iter(responses)
        def side_effect(*args, **kwargs):
            return next(call_iter)
        return side_effect

    # ── batch_size=1 cases ───────────────────────────────────────────────────

    def test_batch1_fast_finds_hosts_on_first_port(self, tmp_path):
        """fast call hits on first probe port → 1 probe call + 1 main batch, rate unchanged."""
        spoonmap.output_path = str(tmp_path)
        # External scan: EXTERNAL_PROBE_PORT_PRIORITY = ['443','80','8080','8443']
        # dest_ports=['443','3306'] → probe_ports=['443'], remaining=['3306']
        # (3306 is not in EXTERNAL_PROBE_PORT_PRIORITY so it stays in remaining)
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 — hit
            {},                       # main batch for port 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        # 2 calls: probe_fast_0 + 1 main batch
        assert mock_b.call_count == 2
        first_call_xml = mock_b.call_args_list[0][0][2]
        assert 'probe_fast_0' in first_call_xml
        assert 'Hosts Found on Port 443' in result

    def test_batch1_fast_zero_slow_finds_hosts(self, tmp_path):
        """fast=0, slow hits → effective_rate switched to half_rate."""
        spoonmap.output_path = str(tmp_path)
        # External: dest_ports=['443','3306'] → probe=['443'], remaining=['3306']
        responses = [
            {},                        # probe_fast_0 (443) — miss
            {'443': {'10.0.0.5'}},    # probe_slow_0 (443) — hit
            {},                        # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        assert mock_b.call_count == 3
        # probe_slow_0 must use half_rate (5000)
        slow_call = mock_b.call_args_list[1]
        assert slow_call[0][1] == '5000'
        assert 'probe_slow_0' in slow_call[0][2]
        assert 'Hosts Found on Port 443' in result

    def test_batch1_port1_miss_port2_fast_hits(self, tmp_path):
        """port1 fast+slow=0, port2 fast hits → 3 probe calls, rate unchanged."""
        spoonmap.output_path = str(tmp_path)
        # Internal scan: PROBE_PORT_PRIORITY starts with 443, 445
        # dest_ports=['443','445','3306'] → probe=['443','445'], remaining=['3306']
        # (3306 is not in PROBE_PORT_PRIORITY so it stays in remaining)
        responses = [
            {},                         # probe_fast_0 (443) — miss
            {},                         # probe_slow_0 (443) — miss
            {'445': {'10.0.0.3'}},     # probe_fast_1 (445) — hit
            {},                         # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            result = mass_scan('All', ['443', '445', '3306'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=1)

        assert mock_b.call_count == 4
        # Third call is probe_fast_1 at max_rate
        third_call = mock_b.call_args_list[2]
        assert third_call[0][1] == '1000'
        assert 'probe_fast_1' in third_call[0][2]
        assert 'Hosts Found on Port 445' in result

    def test_batch1_all_probe_ports_miss(self, tmp_path):
        """All probe ports return 0 hosts → for-else fires, rate unchanged."""
        spoonmap.output_path = str(tmp_path)
        # Internal: dest_ports=['443','3306'] → probe=['443'], remaining=['3306']
        # (3306 not in PROBE_PORT_PRIORITY)
        responses = [
            {},   # probe_fast_0 (443) — miss
            {},   # probe_slow_0 (443) — miss
            {},   # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', ['443', '3306'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=1)

        # 2 probe calls + 1 main batch call
        assert mock_b.call_count == 3
        # Main batch call must use max_rate (no rate reduction)
        main_batch_call = mock_b.call_args_list[2]
        assert main_batch_call[0][1] == '1000'

    # ── batch_size > 1 (legacy two-call probe) ───────────────────────────────

    def test_batch5_uses_legacy_two_call_probe(self, tmp_path):
        """batch_size=5: first 2 calls use probe_fast.xml / probe_slow.xml filenames."""
        spoonmap.output_path = str(tmp_path)
        # External: EXTERNAL_PROBE_PORT_PRIORITY=['443','80','8080','8443']
        # probe_ports=['443','80','8080'] (first 5 from priority intersect dest)
        # remaining_ports=['22','25','135'] (not in EXTERNAL_PROBE_PORT_PRIORITY)
        dest_ports = ['443', '80', '8080', '22', '25', '135']
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast
            {'443': {'10.0.0.1'}},   # probe_slow (same IPs → no new_ips)
            {},                       # main batch ['22', '25', '135']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', dest_ports, '53', '10000',
                      '/fake/targets.txt', '', batch_size=5)

        assert 'probe_fast.xml' in mock_b.call_args_list[0][0][2]
        assert 'probe_slow.xml' in mock_b.call_args_list[1][0][2]

    # ── scan-type-aware probe port selection ─────────────────────────────────

    def test_external_scan_uses_web_probe_ports_only(self, tmp_path):
        """source_port=53 (External) → probe ports drawn only from EXTERNAL_PROBE_PORT_PRIORITY."""
        spoonmap.output_path = str(tmp_path)
        # dest_ports: mix of external-priority ('443','80') and non-priority ('445','22')
        # probe_ports=['443','80'], remaining=['445','22']
        dest_ports = ['443', '80', '445', '22']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)

        probe_calls = [
            call for call in mock_b.call_args_list
            if 'probe_fast' in call[0][2] or 'probe_slow' in call[0][2]
        ]
        probed_ports = {p for call in probe_calls for p in call[0][0]}
        assert probed_ports <= set(EXTERNAL_PROBE_PORT_PRIORITY)

    def test_internal_scan_uses_full_probe_priority(self, tmp_path):
        """source_port=88 (Internal) → probe ports drawn from full PROBE_PORT_PRIORITY."""
        spoonmap.output_path = str(tmp_path)
        # 445 is in PROBE_PORT_PRIORITY but NOT in EXTERNAL_PROBE_PORT_PRIORITY
        # dest_ports=['443','445','3306'] → probe=['443','445'], remaining=['3306']
        # (3306 not in PROBE_PORT_PRIORITY)
        dest_ports = ['443', '445', '3306']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=1)

        probe_calls = [
            call for call in mock_b.call_args_list
            if 'probe_fast' in call[0][2] or 'probe_slow' in call[0][2]
        ]
        probed_ports = {p for call in probe_calls for p in call[0][0]}
        # 443 is first in PROBE_PORT_PRIORITY so it must be probed
        assert '443' in probed_ports
        # 445 is in PROBE_PORT_PRIORITY but not EXTERNAL_PROBE_PORT_PRIORITY
        assert '445' in probed_ports

    # ── wait_secs forwarding ──────────────────────────────────────────────────

    def test_wait_secs_forwarded_to_all_batch_calls(self, tmp_path):
        """_calc_scan_wait result is passed as wait_secs= to every _run_masscan_batch call."""
        spoonmap.output_path = str(tmp_path)
        # Write a real target file so _count_hosts_in_file returns a known count.
        # 256 hosts (/24) at 1000 pps → _calc_scan_wait returns 29.
        target_file = str(tmp_path / 'targets.txt')
        with open(target_file, 'w') as f:
            f.write('10.0.0.0/24\n')

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['443', '3306'], '88', '1000',
                      target_file, '', batch_size=1)

        # Every call must carry wait_secs=29
        for call in mock_b.call_args_list:
            assert call[1].get('wait_secs') == 29
