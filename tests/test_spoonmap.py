"""Tests for spoonmap.py"""
import datetime
import textwrap
from unittest.mock import patch

import pytest

import spoonmap
from spoonmap import (
    EXTERNAL_SENSITIVE_PORTS,
    INTERNAL_PORT_SCRIPTS,
    SERVICE_CATEGORIES,
    _cleanup_cmd,
    _delete_previous_results,
    _get_scripts_for_port,
    _is_printer,
    _previous_results_exist,
    _select_probe_ports,
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
        # 445 is first in PROBE_PORT_PRIORITY
        result = _select_probe_ports(['22', '443', '445'], max_ports=1)
        assert result == ['445']

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

    def test_anonymous_ftp_suppressed_for_printer(self, nmap_dir):
        xml = _nmap_xml('10.0.0.2', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'},
                        service_attrs={'name': 'ftp', 'product': 'HP JetDirect'})
        (nmap_dir / 'nmap_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' not in (nmap_dir / 'findings.txt').read_text()

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

    # ── MS12-020 RDP ──────────────────────────────────────────────────────────

    def test_ms12020_vulnerable_critical_finding(self, nmap_dir):
        # rdp-vuln-ms12-020 is a portrule script — appears under <port>
        xml = _nmap_xml('10.0.0.11', 'tcp', '3389',
                        scripts={'rdp-vuln-ms12-020': 'State: VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port3389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'MS12-020' in content
        assert 'CRITICAL' in content
        assert '10.0.0.11' in content

    def test_ms12020_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml('10.0.0.11', 'tcp', '3389',
                        scripts={'rdp-vuln-ms12-020': 'NOT VULNERABLE'})
        (nmap_dir / 'nmap_results' / 'port3389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'MS12-020' not in (nmap_dir / 'findings.txt').read_text()

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
            result = mass_scan('Full', ['1-65535'], '53', '10000',
                               '/fake/targets.txt', '')
        mock_batch.assert_called_once_with(
            ['1-65535'], '10000',
            str(tmp_path) + '/masscan_results/portFull.xml',
            '/fake/targets.txt', '53', '',
        )
        assert 'Hosts Found on Port 80' in result
        assert 'Hosts Found on Port 443' in result

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


# ── _is_printer ───────────────────────────────────────────────────────────────

import xml.etree.ElementTree as _etree


def _port_elem_with_service(**service_attrs):
    """Build a minimal <port> element with an optional <service> child."""
    attrs_str = ' '.join(f'{k}="{v}"' for k, v in service_attrs.items())
    xml_str = f'<port protocol="udp" portid="161"><service {attrs_str}/></port>'
    return _etree.fromstring(xml_str)


class TestIsPrinter:
    def test_devicetype_printer_detected(self):
        elem = _port_elem_with_service(name='snmp', devicetype='printer')
        assert _is_printer(elem) is True

    def test_printer_keyword_in_product(self):
        elem = _port_elem_with_service(name='snmp', product='HP JetDirect')
        assert _is_printer(elem) is True

    def test_laserjet_in_product(self):
        elem = _port_elem_with_service(name='snmp', product='HP LaserJet 4350')
        assert _is_printer(elem) is True

    def test_non_printer_not_flagged(self):
        elem = _port_elem_with_service(name='snmp', product='Net-SNMP', devicetype='')
        assert _is_printer(elem) is False

    def test_no_service_elem_not_flagged(self):
        elem = _etree.fromstring('<port protocol="udp" portid="161"/>')
        assert _is_printer(elem) is False


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

    def test_snmp_brute_suppressed_for_printer(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.10', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials'},
            service_attrs={'name': 'snmp', 'devicetype': 'printer'},
        )
        (nmap_dir / 'nmap_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' not in content

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
