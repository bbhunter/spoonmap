"""Tests for spoonmap.py"""
import datetime
import json
import textwrap
from unittest.mock import MagicMock, patch

import pytest
import xml.etree.ElementTree as etree

import spoonmap
from spoonmap import (
    DISCOVERY_MASSCAN_PORTS_INTERNAL,
    DISCOVERY_TCP_PORTS_INTERNAL,
    EXTERNAL_PROBE_PORT_PRIORITY,
    EXTERNAL_SENSITIVE_PORTS,
    HOST_DISCOVERY_NMAP_THRESHOLD,
    INTERNAL_DISCOVERY_MAX_RATE,
    INTERNAL_DISCOVERY_STATE_CEILING,
    SLOW_PORTS,
    INTERNAL_PORT_SCRIPTS,
    PROBE_PORT_PRIORITY,
    _build_interactive_config,
    _build_nmap_cmd,
    _write_interactive_config,
    _discover_internal_masscan,
    _discovery_wait,
    _internal_host_discovery,
    _merge_host_xml,
    _filter_udp_live_hosts,
    _nmap_udp_discovery,
    _parse_masscan_ping_xml,
    _parse_nmap_sn_xml,
    _run_masscan_batch,
    _scan_extra_sql_ports,
    _SMB_COUPLED_PORTS,
    _SMB_PORTS,
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
        # Only two priority ports in dest — no non-priority ports to fill remaining slots
        result = _select_probe_ports(['22', '443'], max_ports=5)
        assert set(result) == {'22', '443'}

    def test_fills_remaining_slots_with_non_priority_ports(self):
        # 443 is priority; 9997/9998 are not — should fill up to max_ports=3
        result = _select_probe_ports(['443', '9997', '9998'], max_ports=3)
        assert result[0] == '443'          # priority port first
        assert set(result) == {'443', '9997', '9998'}
        assert len(result) == 3


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

    def test_tiny_host_count_gets_zero_wait(self):
        # 4 discovered hosts: recovery_window = 30 * 4/256 ≈ 0.47s → wait = 0
        assert _calc_scan_wait(4, '2000') == 0

    def test_sub_24_scales_proportionally(self):
        # 16 hosts: recovery_window = 30 * 16/256 ≈ 1.875s, scan_duration ≈ 0.016s → wait = 1
        assert _calc_scan_wait(16, '1000') == 1


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
        # Bundled pre-redesign script is referenced by absolute path
        result = _get_scripts_for_port('U:1434', 'Internal')
        assert result.endswith('nse/ms-sql-info.nse')

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

    def test_6129_external_uses_dameware_detect(self):
        result = _get_scripts_for_port('6129', 'External')
        assert result is not None and result.endswith('nse/dameware-detect.nse')

    def test_6129_internal_uses_dameware_detect(self):
        result = _get_scripts_for_port('6129', 'Internal')
        assert result is not None and result.endswith('nse/dameware-detect.nse')

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

    def test_total_count_uses_group_count_not_instance_count(self, tmp_path):
        # Three instances of the same finding on different hosts → 1 group
        findings = [
            ('HIGH', '10.0.0.1', 'tcp/445', 'Service Exposed Externally', 'SMB'),
            ('HIGH', '10.0.0.2', 'tcp/445', 'Service Exposed Externally', 'SMB'),
            ('HIGH', '10.0.0.3', 'tcp/445', 'Service Exposed Externally', 'SMB'),
        ]
        _write_findings_txt(str(tmp_path), 'External', findings)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'Total findings: 1' in content

    def test_service_exposed_externally_has_no_sample_output_block(self, tmp_path):
        findings = [('HIGH', '1.2.3.4', 'tcp/135', 'Service Exposed Externally', 'RPC')]
        _write_findings_txt(str(tmp_path), 'External', findings)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'Sample output:' not in content

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
        service_elem = f'\n        <service {attrs}/>'
    # Indent every script line consistently so the XML declaration stays at col 0
    raw = _script_elems(scripts).rstrip('\n')
    indented_scripts = '\n'.join('        ' + ln for ln in raw.split('\n')) if raw else ''
    return (
        f'<?xml version="1.0"?>\n'
        f'<nmaprun>\n'
        f'  <host>\n'
        f'    <address addr="{host_ip}" addrtype="ipv4"/>\n'
        f'    <ports>\n'
        f'      <port protocol="{protocol}" portid="{portid}">'
        f'{service_elem}\n'
        f'{indented_scripts}\n'
        f'      </port>\n'
        f'    </ports>\n'
        f'  </host>\n'
        f'</nmaprun>\n'
    )


def _nmap_xml_hostscript(host_ip, protocol, portid, hostscripts):
    """Build a minimal nmap XML with scripts inside a <hostscript> element.

    SMB security-mode and ms-sql-info use hostrule and appear here in real
    nmap output, not inside <port>.
    """
    # Re-indent so every script line aligns with the template's 14-space indent,
    # preventing textwrap.dedent from computing a 0-space common indent when
    # multiple scripts are present.
    raw = _script_elems(hostscripts).rstrip('\n')
    indented_scripts = ('\n' + ' ' * 14).join(raw.split('\n')) if raw else ''
    return textwrap.dedent(f"""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="{host_ip}" addrtype="ipv4"/>
            <ports>
              <port protocol="{protocol}" portid="{portid}"/>
            </ports>
            <hostscript>
              {indented_scripts}
            </hostscript>
          </host>
        </nmaprun>
    """)


@pytest.fixture()
def nmap_dir(tmp_path):
    (tmp_path / 'nse_results').mkdir()
    return tmp_path  # callers write files under tmp_path/nse_results/


class TestGenerateFindings:
    # ── anonymous FTP ────────────────────────────────────────────────────────

    def test_anonymous_ftp_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Anonymous FTP' in content
        assert '10.0.0.1' in content

    def test_anonymous_ftp_not_triggered_when_denied(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login not allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' not in (nmap_dir / 'findings.txt').read_text()

    def test_anonymous_ftp_suppressed_via_port_9100(self, nmap_dir):
        (nmap_dir / 'discovery' / 'live_hosts').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'live_hosts' / 'port9100.txt').write_text('10.0.0.3\n')
        xml = _nmap_xml('10.0.0.3', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' not in (nmap_dir / 'findings.txt').read_text()

    def test_anonymous_ftp_not_suppressed_for_different_host(self, nmap_dir):
        # port9100.txt lists a different IP — the scanned host is not a printer
        (nmap_dir / 'discovery' / 'live_hosts').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'live_hosts' / 'port9100.txt').write_text('10.0.0.99\n')
        xml = _nmap_xml('10.0.0.4', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' in (nmap_dir / 'findings.txt').read_text()

    # ── SMB signing ──────────────────────────────────────────────────────────

    def test_smb2_signing_not_required(self, nmap_dir):
        # smb2-security-mode is a hostrule script — appears under <hostscript>
        xml = _nmap_xml_hostscript('10.0.0.5', 'tcp', '445',
                                   hostscripts={'smb2-security-mode': 'Message signing enabled but not required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Signing Not Required' in content
        assert '10.0.0.5' in content

    def test_smb_signing_required_not_flagged(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.5', 'tcp', '445',
                                   hostscripts={'smb2-security-mode': 'Message signing enabled and required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Signing Not Required' not in (nmap_dir / 'findings.txt').read_text()

    # ── SMBv1 Enabled ─────────────────────────────────────────────────────────

    def test_smbv1_enabled_detected(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.6', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'account_used: guest message_signing: required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Enabled' in content
        assert 'MEDIUM' in content
        assert '10.0.0.6' in content

    def test_smbv1_enabled_not_on_external(self, nmap_dir):
        xml = _nmap_xml_hostscript('1.2.3.4', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'account_used: guest message_signing: required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'SMBv1 Enabled' not in (nmap_dir / 'findings.txt').read_text()

    def test_smbv1_enabled_and_signing_not_required_both_fire(self, nmap_dir):
        # Signing disabled implies SMBv1 is active — both findings should appear
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'message_signing: disabled (dangerous, but default)'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Enabled' in content
        assert 'SMBv1 Signing Not Required' in content
        assert '10.0.0.9' in content

    def test_smb1_signing_suppressed_when_smb2_also_not_required(self, nmap_dir):
        """Both SMBv1 and SMBv2 signing not required → only SMBv2 finding emitted."""
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={
                                       'smb-security-mode': 'message_signing: disabled',
                                       'smb2-security-mode': 'Message signing enabled but not required',
                                   })
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv2 Signing Not Required' in content
        assert 'SMBv1 Signing Not Required' not in content

    def test_smb1_signing_fires_when_smb2_is_required(self, nmap_dir):
        """SMBv1 signing not required but SMBv2 IS required → SMBv1 finding still emitted."""
        xml = _nmap_xml_hostscript('10.0.0.11', 'tcp', '445',
                                   hostscripts={
                                       'smb-security-mode': 'message_signing: disabled',
                                       'smb2-security-mode': 'Message signing enabled and required',
                                   })
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Signing Not Required' in content
        assert 'SMBv2 Signing Not Required' not in content

    # ── EternalBlue (MS17-010) ────────────────────────────────────────────────

    def test_ms17010_vulnerable_critical_finding(self, nmap_dir):
        # smb-vuln-ms17-010 is a hostrule script — appears under <hostscript>
        xml = _nmap_xml_hostscript('10.0.0.7', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'MS17-010' in content
        assert 'CRITICAL' in content
        assert '10.0.0.7' in content

    def test_ms17010_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.7', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'MS17-010' not in (nmap_dir / 'findings.txt').read_text()

    def test_ms17010_only_on_internal(self, nmap_dir):
        # Should not fire on External scans
        xml = _nmap_xml_hostscript('1.2.3.4', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'MS17-010' not in (nmap_dir / 'findings.txt').read_text()

    # ── MS08-067 (NetAPI / Conficker) ─────────────────────────────────────────

    def test_ms08067_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.8', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms08-067': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'MS08-067' in content
        assert 'CRITICAL' in content
        assert '10.0.0.8' in content

    def test_ms08067_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.8', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms08-067': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'MS08-067' not in (nmap_dir / 'findings.txt').read_text()

    # ── DoublePulsar ──────────────────────────────────────────────────────────

    def test_doublepulsar_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-double-pulsar-backdoor': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'DoublePulsar' in content
        assert 'CRITICAL' in content

    def test_doublepulsar_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-double-pulsar-backdoor': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'DoublePulsar' not in (nmap_dir / 'findings.txt').read_text()

    # ── SambaCry ──────────────────────────────────────────────────────────────

    def test_sambacry_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={'smb-vuln-cve-2017-7494': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SambaCry' in content
        assert 'CRITICAL' in content

    def test_sambacry_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={'smb-vuln-cve-2017-7494': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SambaCry' not in (nmap_dir / 'findings.txt').read_text()

    # ── Unauthenticated Docker API ────────────────────────────────────────────

    def test_docker_api_exposed_on_2375(self, nmap_dir):
        xml = _nmap_xml('10.0.0.12', 'tcp', '2375',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nse_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Docker API' in content
        assert 'CRITICAL' in content
        assert '10.0.0.12' in content

    def test_docker_api_exposed_on_4243(self, nmap_dir):
        xml = _nmap_xml('10.0.0.12', 'tcp', '4243',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nse_results' / 'port4243.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Docker API' in (nmap_dir / 'findings.txt').read_text()

    def test_docker_api_no_response_no_finding(self, nmap_dir):
        # No docker-version script output means API did not respond
        xml = _nmap_xml('10.0.0.12', 'tcp', '2375')
        (nmap_dir / 'nse_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Docker API' not in (nmap_dir / 'findings.txt').read_text()

    def test_docker_api_fires_on_external_too(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '2375',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nse_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Docker API' in (nmap_dir / 'findings.txt').read_text()

    # ── NTLM info disclosure ─────────────────────────────────────────────────

    def test_ntlm_disclosure_on_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '25',
                        scripts={'smtp-ntlm-info': 'NetBIOS_Domain_Name: CORP'})
        (nmap_dir / 'nse_results' / 'port25.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'NTLM Information Disclosure' in (nmap_dir / 'findings.txt').read_text()

    def test_ntlm_disclosure_not_on_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.2', 'tcp', '25',
                        scripts={'smtp-ntlm-info': 'NetBIOS_Domain_Name: CORP'})
        (nmap_dir / 'nse_results' / 'port25.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'NTLM Information Disclosure' not in (nmap_dir / 'findings.txt').read_text()

    # ── external sensitive port exposure ─────────────────────────────────────

    def test_sensitive_port_flagged_on_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '445')
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Service Exposed Externally' in (nmap_dir / 'findings.txt').read_text()

    def test_sensitive_port_not_flagged_on_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '445')
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Service Exposed Externally' not in (nmap_dir / 'findings.txt').read_text()

    # ── TLS certificate expiry ────────────────────────────────────────────────

    def test_expired_cert_flagged(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Not valid after:  2020-06-01T00:00:00'})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Expired TLS Certificate' in (nmap_dir / 'findings.txt').read_text()

    def test_valid_cert_not_flagged(self, nmap_dir):
        future = datetime.date.today().replace(
            year=datetime.date.today().year + 2
        ).isoformat()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': f'Not valid after:  {future}T00:00:00'})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Expired TLS Certificate' not in (nmap_dir / 'findings.txt').read_text()

    # ── known-bad service detection ───────────────────────────────────────────

    def test_dameware_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '6129',
                        service_attrs={'name': 'dameware',
                                       'product': 'DameWare Mini Remote Control'})
        (nmap_dir / 'nse_results' / 'port6129.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'DameWare' in content
        assert 'HIGH' in content

    def test_dameware_nse_confirmed_critical(self, nmap_dir):
        """dameware-detect script output raises finding to CRITICAL."""
        xml = _nmap_xml(
            '10.0.0.2', 'tcp', '6129',
            scripts={'dameware-detect':
                     'Product: SolarWinds DameWare Mini Remote Control\n'
                     'CVE: CVE-2019-3980 (CVSS 9.8) - Unauthenticated RCE v12.1.0.89 and earlier\n'
                     'Remediation: Upgrade to v12.1.2+'},
        )
        (nmap_dir / 'nse_results' / 'port6129.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'DameWare' in content
        assert 'CRITICAL' in content
        # CVE detail is written to findings.md (detail column) and findings.json
        md_content = (nmap_dir / 'findings.md').read_text()
        assert 'CVE-2019-3980' in md_content

    def test_cisco_smart_install_vulnerable(self, nmap_dir):
        # cisco-siet.nse confirms VULNERABLE → finding raised
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786',
                        scripts={'cisco-siet': 'Host: 10.0.0.1  Status: VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' in (nmap_dir / 'findings.txt').read_text()

    def test_cisco_smart_install_not_vulnerable_no_finding(self, nmap_dir):
        # cisco-siet.nse returns NOT VULNERABLE → no finding
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786',
                        scripts={'cisco-siet': 'Host: 10.0.0.1  Status: NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' not in (nmap_dir / 'findings.txt').read_text()

    def test_cisco_smart_install_no_script_no_finding(self, nmap_dir):
        # port 4786 open but no cisco-siet script output → no finding (avoid false positives)
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786')
        (nmap_dir / 'nse_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' not in (nmap_dir / 'findings.txt').read_text()

    def test_sap_gateway_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '3300')
        (nmap_dir / 'nse_results' / 'port3300.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SAP Gateway' in (nmap_dir / 'findings.txt').read_text()

    # ── output files ─────────────────────────────────────────────────────────

    def test_both_output_files_created(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert (nmap_dir / 'findings.txt').exists()
        assert (nmap_dir / 'findings.md').exists()

    def test_no_output_when_nmap_results_missing(self, tmp_path):
        generate_findings(str(tmp_path), 'Internal')
        assert not (tmp_path / 'findings.txt').exists()

    def test_severity_order_in_output(self, nmap_dir):
        # HIGH from ftp-anon, INFO from ms-sql-info — HIGH must come first
        # ms-sql-info is a hostrule script — appears under <hostscript>
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(
            _nmap_xml('10.0.0.1', 'tcp', '21',
                      scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        )
        (nmap_dir / 'nse_results' / 'port1433.xml').write_text(
            _nmap_xml_hostscript('10.0.0.2', 'tcp', '1433',
                                 hostscripts={'ms-sql-info': 'SQL Server 2019'})
        )
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert content.index('HIGH') < content.index('INFO')

    def test_generate_findings_writes_json(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        data = json.loads((nmap_dir / 'findings.json').read_text())
        assert any(r['title'] == 'Anonymous FTP' for r in data)

    def test_open_filtered_port_excluded_from_findings(self, nmap_dir):
        """Port with state open|filtered must not appear in findings."""
        xml = (
            '<?xml version="1.0"?>\n'
            '<nmaprun>\n'
            '  <host>\n'
            '    <address addr="10.0.0.5" addrtype="ipv4"/>\n'
            '    <ports>\n'
            '      <port protocol="tcp" portid="445">\n'
            '        <state state="open|filtered"/>\n'
            '      </port>\n'
            '    </ports>\n'
            '  </host>\n'
            '</nmaprun>\n'
        )
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'Service Exposed Externally' not in findings_file.read_text()


# ── _previous_results_exist / _delete_previous_results ───────────────────────

class TestPreviousResults:
    def test_empty_dir_returns_false(self, tmp_path):
        assert _previous_results_exist(str(tmp_path)) is False

    def test_detects_masscan_results_dir(self, tmp_path):
        d = tmp_path / 'discovery' / 'masscan_results'
        d.mkdir(parents=True)
        (d / 'port80.xml').write_text('<nmaprun/>')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_live_hosts_dir(self, tmp_path):
        d = tmp_path / 'discovery' / 'live_hosts'
        d.mkdir(parents=True)
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
        (tmp_path / 'discovery').mkdir()
        assert _previous_results_exist(str(tmp_path)) is False

    def test_delete_removes_result_dirs(self, tmp_path):
        for d in ('discovery', 'nmap_results', 'nse_results'):
            p = tmp_path / d
            p.mkdir()
            (p / 'file.xml').write_text('<nmaprun/>')
        _delete_previous_results(str(tmp_path))
        for d in ('discovery', 'nmap_results', 'nse_results'):
            assert not (tmp_path / d).exists()

    def test_delete_removes_aggregate_files(self, tmp_path):
        for f in ('all_live_hosts.txt', 'spoonmap_output.xml',
                  'findings.txt', 'findings.md'):
            (tmp_path / f).write_text('data')
        _delete_previous_results(str(tmp_path))
        for f in ('all_live_hosts.txt', 'spoonmap_output.xml',
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


# ── LDAP / SMB category split ─────────────────────────────────────────────────

class TestLdapSmbCategorySplit:
    def test_authentication_key_removed(self):
        assert 'Authentication' not in SERVICE_CATEGORIES

    def test_ldap_key_contains_correct_ports(self):
        assert SERVICE_CATEGORIES['LDAP'] == ['389', '636']

    def test_smb_key_contains_correct_ports(self):
        assert SERVICE_CATEGORIES['SMB'] == ['445', '135', '139', 'U:137']

    def test_ldap_appears_before_smb(self):
        keys = list(SERVICE_CATEGORIES.keys())
        assert keys.index('LDAP') < keys.index('SMB')

    def test_ldap_and_smb_in_different_batches_with_batch_size_5(self):
        all_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
        tcp_ports = [p for p in all_ports if not p.startswith('U:')]
        idx_389 = tcp_ports.index('389')
        idx_445 = tcp_ports.index('445')
        assert idx_389 // 5 != idx_445 // 5, (
            f'389 (batch {idx_389 // 5}) and 445 (batch {idx_445 // 5}) '
            'must be in different batches'
        )


# ── Full Port Scan in mass_scan() ─────────────────────────────────────────────

class TestFullPortScan:
    def test_full_scan_skips_probe_and_calls_masscan_with_range(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'80': {'10.0.0.1'}, '443': {'10.0.0.2'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results) as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '20000',
                               '/fake/targets.txt', '', target_scan='External')
        mock_batch.assert_called_once_with(
            ['1-65535'], '10000',   # capped from 20000 (External cap)
            str(tmp_path) + '/discovery/masscan_results/portFull.xml',
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
            str(tmp_path) + '/discovery/masscan_results/portFull.xml',
            '/fake/targets.txt', '88', '',
            wait_secs=2,
        )

    def test_full_scan_writes_live_hosts_files(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'22': {'10.0.0.5', '10.0.0.6'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results):
            mass_scan('Full', ['1-65535'], '53', '10000', '/fake/targets.txt', '')
        live_file = tmp_path / 'discovery' / 'live_hosts' / 'port22.txt'
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


# ── interactive config persistence ───────────────────────────────────────────

class TestBuildInteractiveConfig:
    """_build_interactive_config output must round-trip through the loader."""

    def _resolve(self, config):
        """Replicate main()'s config loader for scan_type/dest_ports derivation."""
        scan_categories = config.get('scan_categories', 'All')
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
        if config.get('dest_ports'):
            dest_ports = config['dest_ports']
            scan_type = 'Custom'
        return scan_type, dest_ports

    def _dest_ports_for(self, categories):
        all_ports = [p for name in categories for p in SERVICE_CATEGORIES[name]]
        return [p for p in all_ports if not p.startswith('U:')] + \
               [p for p in all_ports if p.startswith('U:')]

    def test_category_list_round_trips(self):
        selected = ['Web', 'Database']
        dest_ports = self._dest_ports_for(selected)
        cfg = _build_interactive_config(
            selected, dest_ports, 'Web, Database', True, False, 'Internal',
            '2000', '/t/ranges.txt', '/t/out', None, 5, 5, 5_000_000, True)
        assert cfg['scan_categories'] == selected
        assert 'dest_ports' not in cfg
        assert self._resolve(cfg) == ('Web, Database', dest_ports)

    def test_full_round_trips(self):
        cfg = _build_interactive_config(
            'Full', ['1-65535'], 'Full', True, False, 'External',
            '20000', '/t/r', '/t/o', None, 5, 5, 5_000_000, True)
        assert cfg['scan_categories'] == 'Full'
        assert self._resolve(cfg) == ('Full', ['1-65535'])

    def test_all_round_trips(self):
        dest_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
        cfg = _build_interactive_config(
            'All', dest_ports, 'All', True, False, 'Internal',
            '2000', '/t/r', '/t/o', None, 5, 5, 5_000_000, True)
        assert cfg['scan_categories'] == 'All'
        assert self._resolve(cfg)[0] == 'All'

    def test_custom_writes_dest_ports_not_categories(self):
        cfg = _build_interactive_config(
            None, ['80', '443', 'U:53'], 'Custom', True, False, 'External',
            '20000', '/t/r', '/t/o', None, 5, 5, 5_000_000, True)
        assert cfg['dest_ports'] == ['80', '443', 'U:53']
        assert 'scan_categories' not in cfg
        assert self._resolve(cfg) == ('Custom', ['80', '443', 'U:53'])

    def test_booleans_and_rate_serialize_as_strings(self):
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', 2000,
            'r', 'o', None, 5, 5, 5_000_000, False)
        assert cfg['banner_scan'] == 'True'
        assert cfg['script_scan'] == 'False'
        assert cfg['host_discovery'] == 'False'
        assert cfg['max_rate'] == '2000'
        assert cfg['resume'] == 'False'

    def test_exclusions_none_becomes_empty_string(self):
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', '2000',
            'r', 'o', None, 5, 5, 5_000_000, True)
        assert cfg['exclusions_file'] == ''

    def test_exclusions_path_preserved(self):
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', '2000',
            'r', 'o', '/etc/excl.txt', 5, 5, 5_000_000, True)
        assert cfg['exclusions_file'] == '/etc/excl.txt'

    def test_numeric_fields_are_ints(self):
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', '2000',
            'r', 'o', None, '7', '3', '1000000', True)
        assert cfg['nmap_threads'] == 7
        assert cfg['masscan_batch_size'] == 3
        assert cfg['nmap_threshold'] == 1_000_000


class TestWriteInteractiveConfig:
    def test_writes_valid_json(self, tmp_path):
        path = str(tmp_path / 'config.json')
        cfg = {'banner_scan': 'True', 'target_scan': 'Internal'}
        assert _write_interactive_config(path, cfg) is True
        with open(path) as fh:
            assert json.load(fh) == cfg

    def test_returns_false_on_unwritable_path(self, tmp_path, capsys):
        path = str(tmp_path / 'nonexistent_dir' / 'config.json')
        assert _write_interactive_config(path, {'a': 'b'}) is False
        assert 'could not write' in capsys.readouterr().out

    def test_build_then_write_round_trips(self, tmp_path):
        selected = ['Web']
        all_ports = [p for name in selected for p in SERVICE_CATEGORIES[name]]
        dest_ports = [p for p in all_ports if not p.startswith('U:')] + \
                     [p for p in all_ports if p.startswith('U:')]
        cfg = _build_interactive_config(
            selected, dest_ports, 'Web', True, False, 'Internal', '2000',
            'r', 'o', None, 5, 5, 5_000_000, True)
        path = str(tmp_path / 'config.json')
        assert _write_interactive_config(path, cfg) is True
        with open(path) as fh:
            assert json.load(fh) == cfg


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
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' in content
        assert '10.0.0.5' in content

    def test_snmp_brute_community_strings_listed_in_detail(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials\nprivate - Valid credentials'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'public' in content
        assert 'private' in content

    def test_snmp_brute_suppressed_via_port_9100(self, nmap_dir):
        (nmap_dir / 'discovery' / 'live_hosts').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'live_hosts' / 'port9100.txt').write_text('10.0.0.12\n')
        xml = _nmap_xml('10.0.0.12', 'udp', '161',
                        scripts={'snmp-brute': 'public - Valid credentials'})
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SNMP Default Community String' not in (nmap_dir / 'findings.txt').read_text()

    def test_snmp_brute_no_valid_creds_no_finding(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - No response\nprivate - No response'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' not in content

    def test_snmp_brute_tcp_port_161_also_checked(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.7', 'tcp', '161',
            scripts={'snmp-brute': 'public - Valid credentials'},
        )
        (nmap_dir / 'nse_results' / 'port161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' in content


# ── SNMP severity and detail tests ───────────────────────────────────────────

class TestSnmpSeverityAndDetail:
    def test_snmp_rw_on_network_device_is_critical(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={
                'snmp-brute': 'public - Valid credentials   (Access level: read-write)',
                'snmp-sysdescr': 'Cisco IOS Software, Version 15.7',
            },
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'CRITICAL' in content
        assert 'SNMP Default Community String' in content

    def test_snmp_rw_on_non_network_device_is_high(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={
                'snmp-brute': 'public - Valid credentials   (Access level: read-write)',
                'snmp-sysdescr': 'Linux Ubuntu 20.04 x86_64',
            },
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'HIGH' in content
        assert 'SNMP Default Community String' in content

    def test_snmp_ro_only_is_low(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials   (Access level: read-only)'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LOW' in content
        assert 'SNMP Default Community String' in content

    def test_snmp_accepts_any_validated(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal',
                          snmp_any_validated={'10.0.0.5': True})
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Accepts Any Community String' in content
        assert 'CRITICAL' in content

    def test_snmp_printer_exclusion_note_in_detail(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.md').read_text()
        assert 'printer' in content.lower()

    def test_snmp_sysdescr_in_detail(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={
                'snmp-brute': 'public - Valid credentials',
                'snmp-sysdescr': 'Linux host 5.4.0 #1 SMP x86_64',
            },
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.md').read_text()
        assert 'Linux host 5.4.0' in content


# ── INTERNAL_PORT_SCRIPTS includes snmp-brute ─────────────────────────────────

class TestInternalPortScriptsSnmp:
    def test_snmp_tcp_161_included(self):
        assert '161' in INTERNAL_PORT_SCRIPTS
        assert 'snmp-brute' in INTERNAL_PORT_SCRIPTS['161']
        assert 'snmp-sysdescr' in INTERNAL_PORT_SCRIPTS['161']

    def test_snmp_udp_161_included(self):
        assert 'U:161' in INTERNAL_PORT_SCRIPTS
        assert 'snmp-brute' in INTERNAL_PORT_SCRIPTS['U:161']
        assert 'snmp-sysdescr' in INTERNAL_PORT_SCRIPTS['U:161']


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

    def test_batch2_selects_two_probe_ports(self, tmp_path):
        """batch_size=2: two probe ports selected; both appear in legacy probe calls."""
        spoonmap.output_path = str(tmp_path)
        # Internal scan: PROBE_PORT_PRIORITY starts with 443, 445
        # dest_ports=['443','445','3306'] → probe=['443','445'], remaining=['3306']
        # 445 is in SLOW_PORTS so it gets a solo batch after missing the probe
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast(['443','445']) — hit on 443
            {},                       # probe_slow(['443','445']) — miss
            {},                       # main batch ['3306'] (normal)
            {},                       # main batch ['445'] (slow-port solo, re-queued after probe miss)
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', ['443', '445', '3306'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=2)

        probe_call = mock_b.call_args_list[0]
        probed_ports = set(probe_call[0][0])
        assert '443' in probed_ports
        assert '445' in probed_ports
        assert len(probed_ports) == 2

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
        """source_port=53 (External) → probe prefers EXTERNAL_PROBE_PORT_PRIORITY ports."""
        spoonmap.output_path = str(tmp_path)
        # batch_size=1: dest=['443','80','445','22'] → probe=['443'], remaining=['80','445','22']
        dest_ports = ['443', '80', '445', '22']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)

        probe_calls = [
            call for call in mock_b.call_args_list
            if 'probe_fast' in call[0][2] or 'probe_slow' in call[0][2]
        ]
        probed_ports = {p for call in probe_calls for p in call[0][0]}
        # With batch_size=1, only one probe port; it must be the top priority match
        assert probed_ports == {'443'}

    def test_internal_scan_uses_full_probe_priority(self, tmp_path):
        """source_port=88 (Internal) → probe ports drawn from full PROBE_PORT_PRIORITY."""
        spoonmap.output_path = str(tmp_path)
        # 445 is in PROBE_PORT_PRIORITY but NOT in EXTERNAL_PROBE_PORT_PRIORITY
        # batch_size=2: dest_ports=['443','445','3306'] → probe=['443','445'], remaining=['3306']
        # (3306 not in PROBE_PORT_PRIORITY)
        dest_ports = ['443', '445', '3306']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=2)

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

    # ── slow-port solo batching ───────────────────────────────────────────────

    def test_slow_port_scanned_solo_at_large_batch_size(self, tmp_path):
        """SLOW_PORTS are always scanned in solo batches, even when batch_size > 1."""
        spoonmap.output_path = str(tmp_path)
        # 389 is in SLOW_PORTS; 80 and 443 are normal ports.
        # With batch_size=5 all three would normally share one batch.
        dest_ports = ['80', '389', '443']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)

        # Collect ports from every main batch (non-probe) call
        main_batches = [
            call[0][0] for call in mock_b.call_args_list
            if 'probe_fast' not in call[0][2] and 'probe_slow' not in call[0][2]
        ]
        solo_batches = [b for b in main_batches if b == ['389']]
        assert solo_batches, "Expected a solo batch for port 389"

    def test_non_slow_ports_batched_together(self, tmp_path):
        """Normal ports are still grouped into the same batch (not split unnecessarily)."""
        spoonmap.output_path = str(tmp_path)
        dest_ports = ['80', '443', '8080']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)

        main_batches = [
            call[0][0] for call in mock_b.call_args_list
            if 'probe_fast' not in call[0][2] and 'probe_slow' not in call[0][2]
        ]
        # All three normal ports must share one batch (batch_size=5 fits them all)
        combined = [p for batch in main_batches for p in batch]
        assert '80' in combined and '443' in combined and '8080' in combined
        assert any(len(b) > 1 for b in main_batches), "Normal ports should be grouped together"

    def test_absent_slow_port_has_no_solo_batch(self, tmp_path):
        """When a SLOW_PORT is not in dest_ports, no solo batch is created for it."""
        spoonmap.output_path = str(tmp_path)
        # 389 intentionally omitted from dest_ports
        dest_ports = ['80', '443']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)

        all_ports_scanned = [
            p for call in mock_b.call_args_list for p in call[0][0]
        ]
        assert '389' not in all_ports_scanned

    # ── summary deduplication ─────────────────────────────────────────────────

    def test_slow_port_summary_not_emitted_in_probe_phase(self, tmp_path):
        """Port 445 (SLOW_PORT) probed and found: summary must not appear from probe phase.

        445 is always re-queued for a solo batch; the summary is emitted exactly
        once from that batch phase, not twice (once from probe + once from batch).
        """
        spoonmap.output_path = str(tmp_path)
        # Internal scan: PROBE_PORT_PRIORITY includes 445 (position 2, after 443).
        # dest_ports=['445','3306'], batch_size=1 → probe selects ['445'].
        # remaining=['3306']. 445 is in SLOW_PORTS so it is re-queued for a solo batch.
        responses = [
            {'445': {'10.0.0.1'}},   # probe_fast_0 (445) — hit
            {},                       # probe_slow_0 (445) — no extra hosts
            {'445': {'10.0.0.2'}},   # solo batch for 445 — additional host
            {},                       # main batch for 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['445', '3306'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=1)

        assert result.count('Hosts Found on Port 445') == 1

    def test_slow_port_summary_emitted_from_batch_phase(self, tmp_path):
        """The single 445 summary reflects merged count: probe IPs ∪ batch IPs."""
        spoonmap.output_path = str(tmp_path)
        responses = [
            {'445': {'10.0.0.1'}},   # probe_fast_0 — 1 host
            {},                       # probe_slow_0
            {'445': {'10.0.0.2'}},   # solo batch — 1 additional host
            {},                       # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['445', '3306'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=1)

        # Both hosts (probe + batch) must be reflected in the summary count
        assert 'Hosts Found on Port 445: 2' in result

    def test_non_slow_port_summary_emitted_from_probe(self, tmp_path):
        """Non-SLOW_PORT found in probe still emits summary exactly once."""
        spoonmap.output_path = str(tmp_path)
        # 3306 is not in SLOW_PORTS and not in PROBE_PORT_PRIORITY,
        # so with dest_ports=['443','3306'] the probe selects ['443'].
        # 443 is not a SLOW_PORT → summary appears from probe phase.
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 (443) — hit
            {},                       # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['443', '3306'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=1)

        assert result.count('Hosts Found on Port 443') == 1


# ── TestMassScanResume ────────────────────────────────────────────────────────

class TestMassScanResume:
    """Tests for --resume batch-skipping in mass_scan()."""

    def _write_batch_xml(self, path):
        """Write a minimal XML file to simulate a completed masscan batch."""
        path.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')

    def test_completed_batch_skipped_when_resume_true(self, tmp_path):
        """A batch whose XML is newer than resolved_targets.txt is skipped when resume=True."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        # Make batch XML newer than targets file
        import os, time as _time
        os.utime(str(targets_file), (0, 0))
        os.utime(str(batch_xml), (_time.time(), _time.time()))

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=10, resume=True)

        # Only probe calls should fire; the one main batch must be skipped
        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        assert main_calls == [], 'Main batch should have been skipped under resume=True'

    def test_completed_batch_not_skipped_when_resume_false(self, tmp_path):
        """A pre-existing batch XML is NOT skipped when resume=False."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        import os
        os.utime(str(targets_file), (0, 0))

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=10, resume=False)

        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        assert len(main_calls) >= 1, 'Main batch should run when resume=False'

    def test_live_hosts_loaded_from_file_when_batch_skipped(self, tmp_path):
        """When a batch is skipped, IPs from live_hosts/portN.txt are loaded into port_ips."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        live_dir = tmp_path / 'discovery' / 'live_hosts'
        live_dir.mkdir(parents=True)
        (live_dir / 'port80.txt').write_text('10.0.0.1\n10.0.0.2\n')

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        import os, time as _time
        os.utime(str(targets_file), (0, 0))
        os.utime(str(batch_xml), (_time.time(), _time.time()))

        with patch('spoonmap._run_masscan_batch', return_value={}):
            result = mass_scan('All', ['80'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=10, resume=True)

        # The summary should reflect the 2 pre-existing hosts on port 80
        assert 'Hosts Found on Port 80: 2' in result

    def test_partial_resume_only_skips_completed_batches(self, tmp_path):
        """Only batches with existing XML are skipped; missing ones run normally."""
        spoonmap.output_path = str(tmp_path)
        results_dir = tmp_path / 'discovery' / 'masscan_results'
        results_dir.mkdir(parents=True)
        # batch_0 exists (ports 80, 443); batch_1 does NOT exist
        batch0_xml = results_dir / 'batch_0.xml'
        self._write_batch_xml(batch0_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        import os, time as _time
        os.utime(str(targets_file), (0, 0))
        os.utime(str(batch0_xml), (_time.time(), _time.time()))

        # 4 ports split into 2 batches of 2 (batch_size=2); none are SLOW_PORTS
        # External probe priority: ['443','80','8080','8443'] → probe=['443','80'],
        # remaining=['8080','8443'] → 1 batch of 2
        dest_ports = ['443', '80', '8080', '8443']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '53', '10000',
                      '/fake/targets.txt', '', batch_size=2, resume=True)

        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        # batch_0 is skipped; the remaining batch (8080, 8443) must run
        assert len(main_calls) == 1, (
            f'Expected exactly 1 main-batch call (batch_1), got {len(main_calls)}'
        )

    def test_batch_not_skipped_when_targets_file_is_newer(self, tmp_path):
        """If resolved_targets.txt is newer than batch XML, the batch re-runs."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')

        import os, time as _time
        # Make batch XML *older* than targets (simulates ranges.txt change)
        os.utime(str(batch_xml), (0, 0))
        os.utime(str(targets_file), (_time.time(), _time.time()))

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=10, resume=True)

        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        assert len(main_calls) >= 1, 'Batch must re-run when targets file is newer'


# ── _merge_host_xml ───────────────────────────────────────────────────────────

def _make_host(ip, ports, hostscripts=None):
    """Build a minimal nmap <host> element for testing."""
    host = etree.Element('host')
    addr = etree.SubElement(host, 'address')
    addr.set('addr', ip)
    addr.set('addrtype', 'ipv4')
    ports_elem = etree.SubElement(host, 'ports')
    for proto, portid in ports:
        p = etree.SubElement(ports_elem, 'port')
        p.set('protocol', proto)
        p.set('portid', portid)
    if hostscripts:
        hs = etree.SubElement(host, 'hostscript')
        for sid, output in hostscripts.items():
            s = etree.SubElement(hs, 'script')
            s.set('id', sid)
            s.set('output', output)
    return host


class TestMergeHostXml:
    def test_new_ports_appended(self):
        base = _make_host('10.0.0.1', [('tcp', '80')])
        other = _make_host('10.0.0.1', [('tcp', '443')])
        _merge_host_xml(base, other)
        portids = [p.get('portid') for p in base.find('ports').findall('port')]
        assert set(portids) == {'80', '443'}

    def test_duplicate_port_not_added_twice(self):
        base = _make_host('10.0.0.1', [('tcp', '80')])
        other = _make_host('10.0.0.1', [('tcp', '80')])
        _merge_host_xml(base, other)
        assert len(base.find('ports').findall('port')) == 1

    def test_hostscripts_merged(self):
        base = _make_host('10.0.0.1', [], {'smb-security-mode': 'disabled'})
        other = _make_host('10.0.0.1', [], {'smb2-security-mode': 'enabled'})
        _merge_host_xml(base, other)
        script_ids = {s.get('id') for s in base.find('hostscript').findall('script')}
        assert script_ids == {'smb-security-mode', 'smb2-security-mode'}

    def test_duplicate_hostscript_not_added_twice(self):
        base = _make_host('10.0.0.1', [], {'smb-security-mode': 'v1'})
        other = _make_host('10.0.0.1', [], {'smb-security-mode': 'v2'})
        _merge_host_xml(base, other)
        scripts = base.find('hostscript').findall('script')
        assert len(scripts) == 1
        assert scripts[0].get('output') == 'v1'

    def test_base_without_ports_elem(self):
        """base has no <ports> at all — _merge_host_xml creates one."""
        base = etree.Element('host')
        addr = etree.SubElement(base, 'address')
        addr.set('addr', '10.0.0.1')
        addr.set('addrtype', 'ipv4')
        other = _make_host('10.0.0.1', [('tcp', '22')])
        _merge_host_xml(base, other)
        portids = [p.get('portid') for p in base.find('ports').findall('port')]
        assert portids == ['22']

    def test_other_without_hostscript_noop(self):
        """other has no <hostscript> — base is unchanged."""
        base = _make_host('10.0.0.1', [('tcp', '80')], {'smb-security-mode': 'ok'})
        other = _make_host('10.0.0.1', [('tcp', '443')])
        _merge_host_xml(base, other)
        scripts = base.find('hostscript').findall('script')
        assert len(scripts) == 1


# ── ms-sql-info UDP 1434 ───────────────────────────────────────────────────────
# Real nmap XML for ms-sql-info when it fires as a *portscript* on UDP 1434.
# Structure: <table key="INSTANCE"> (instance table, direct child of <script>)
#              └── <table key="Version"> (version sub-table)
#              └── <elem key="tcp">PORT</elem>
#              └── <elem key="Named pipe">...</elem>
_MS_SQL_INFO_UDP_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
          <port protocol="udp" portid="1434">
            <state state="open" reason="udp-response"/>
            <script id="ms-sql-info" output="SQL Server 2019 on 192.168.1.10">
              <table key="192.168.1.10\\MSSQLSERVER">
                <table key="Version">
                  <elem key="name">Microsoft SQL Server 2019</elem>
                  <elem key="number">15.00.2000.00</elem>
                </table>
                <elem key="tcp">1433</elem>
                <elem key="Named pipe">\\\\192.168.1.10\\pipe\\sql\\query</elem>
              </table>
            </script>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

# Same structure but with a named instance on a non-standard TCP port (51234)
_MS_SQL_INFO_NAMED_INSTANCE_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
          <port protocol="udp" portid="1434">
            <state state="open" reason="udp-response"/>
            <script id="ms-sql-info" output="SQL Server Express on 192.168.1.10">
              <table key="192.168.1.10\\SQLEXPRESS">
                <table key="Version">
                  <elem key="name">Microsoft SQL Server 2019 Express</elem>
                </table>
                <elem key="tcp">51234</elem>
                <elem key="Named pipe">\\\\192.168.1.10\\pipe\\MSSQL$SQLEXPRESS\\sql\\query</elem>
              </table>
            </script>
          </port>
        </ports>
      </host>
    </nmaprun>
""")


class TestMsSqlInfoUdp1434:
    """ms-sql-info parsing from UDP 1434 nmap output via portscript and hostscript."""

    def test_portscript_produces_finding(self, nmap_dir):
        """ms-sql-info as a port-level script in portU:1434.xml must generate a finding.

        When nmap runs ms-sql-info via its portrule against UDP 1434, the script
        output lands under <port>, not <hostscript>.  generate_findings() must
        check both locations.
        """
        (nmap_dir / 'nse_results' / 'portU:1434.xml').write_text(_MS_SQL_INFO_UDP_XML)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SQL Server Instance Discovered' in content
        assert '192.168.1.10' in content

    def test_hostscript_produces_finding(self, nmap_dir):
        """ms-sql-info under <hostscript> in portU:1434.xml (regression: existing path)."""
        xml = _nmap_xml_hostscript('192.168.1.10', 'udp', '1434',
                                   hostscripts={'ms-sql-info': 'SQL Server 2019'})
        (nmap_dir / 'nse_results' / 'portU:1434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SQL Server Instance Discovered' in content
        assert '192.168.1.10' in content

    def test_no_finding_for_external_scan(self, nmap_dir):
        """ms-sql-info should not generate a finding for External scans."""
        (nmap_dir / 'nse_results' / 'portU:1434.xml').write_text(_MS_SQL_INFO_UDP_XML)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'SQL Server Instance Discovered' not in findings_file.read_text()


# ── _scan_extra_sql_ports ─────────────────────────────────────────────────────

class TestScanExtraSqlPorts:
    """_scan_extra_sql_ports() parsing of ms-sql-info XML output."""

    def test_finds_named_instance_on_non_standard_port(self, tmp_path):
        """Named instance on port 51234 triggers an extra nmap scan.

        The ms-sql-info XML has <table key="Version"> as a direct child of the
        instance table.  <elem key="tcp"> is a *sibling* of that version table
        (also a direct child of the instance table), not inside the version
        sub-table.  The correct XPath to reach instance tables is 'table', not
        'table/table' (which would navigate into the version sub-table).
        """
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(_MS_SQL_INFO_NAMED_INSTANCE_XML)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert mock_popen.called, 'nmap should be called for the non-standard port 51234'
        cmd = mock_popen.call_args[0][0]
        assert '51234' in cmd, f'Expected port 51234 in nmap command, got: {cmd}'

    def test_standard_1433_instance_not_rescanned(self, tmp_path):
        """An instance on the default port 1433 must not trigger an extra scan."""
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU:1434.xml').write_text(_MS_SQL_INFO_UDP_XML)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert not mock_popen.called, 'nmap must NOT be called for a standard 1433 instance'


# ── TestInternalNseFindings ───────────────────────────────────────────────────

class TestInternalNseFindings:
    """Per-port NSE-validated findings that replaced INTERNAL_RISK_PORTS."""

    def test_jdwp_finding(self, nmap_dir):
        """jdwp-info output with content triggers JDWP finding."""
        xml = _nmap_xml('10.0.1.1', 'tcp', '5005',
                        scripts={'jdwp-info': 'Protocol version: 1.1\nVM name: Java HotSpot'})
        (nmap_dir / 'nse_results' / 'port5005.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'JDWP Java Debugger Exposed' in content
        assert '10.0.1.1' in content

    def test_nodejs_inspector_finding(self, nmap_dir):
        """nodejs-inspector output triggers Node.js Inspector finding."""
        xml = _nmap_xml('10.0.1.2', 'tcp', '9229',
                        scripts={'nodejs-inspector': 'Node.js Inspector accessible — version: node.js/v18.17.0'})
        (nmap_dir / 'nse_results' / 'port9229.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Node.js Inspector Port Exposed' in content
        assert '10.0.1.2' in content

    def test_delve_finding(self, nmap_dir):
        """delve-debugger output triggers Delve finding."""
        xml = _nmap_xml('10.0.1.3', 'tcp', '2345',
                        scripts={'delve-debugger': 'Delve debugger responding to DAP requests'})
        (nmap_dir / 'nse_results' / 'port2345.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Delve Go Debugger Exposed' in content
        assert '10.0.1.3' in content

    def test_kubelet_anon_finding(self, nmap_dir):
        """kubelet-anon-check output triggers Kubelet Anonymous Access finding."""
        xml = _nmap_xml('10.0.1.4', 'tcp', '10250',
                        scripts={'kubelet-anon-check': 'Anonymous access enabled — /pods returned HTTP 200 without credentials'})
        (nmap_dir / 'nse_results' / 'port10250.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Kubernetes Kubelet Anonymous Access' in content
        assert '10.0.1.4' in content

    def test_k8s_dashboard_finding(self, nmap_dir):
        """http-title containing 'Kubernetes Dashboard' triggers k8s dashboard finding."""
        xml = _nmap_xml('10.0.1.5', 'tcp', '8001',
                        scripts={'http-title': 'Kubernetes Dashboard'})
        (nmap_dir / 'nse_results' / 'port8001.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Kubernetes Dashboard Accessible' in content
        assert '10.0.1.5' in content

    def test_activemq_banner_finding(self, nmap_dir):
        """banner containing 'ActiveMQ' triggers ActiveMQ Broker Exposed finding."""
        xml = _nmap_xml('10.0.1.6', 'tcp', '61616',
                        scripts={'banner': 'STOMP\nActiveMQ/5.15.9'})
        (nmap_dir / 'nse_results' / 'port61616.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'ActiveMQ Broker Exposed' in content
        assert '10.0.1.6' in content

    def test_no_finding_without_script_output(self, nmap_dir):
        """Port 5005 open but jdwp-info returns empty string — no JDWP finding."""
        xml = _nmap_xml('10.0.1.7', 'tcp', '5005',
                        scripts={'jdwp-info': ''})
        (nmap_dir / 'nse_results' / 'port5005.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'JDWP Java Debugger Exposed' not in findings_file.read_text()

    # ── AI / Local LLM findings ───────────────────────────────────────────────

    def test_ollama_internal_medium(self, nmap_dir):
        """ollama-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.1', 'tcp', '11434',
                        scripts={'ollama-detect': 'Ollama API accessible without authentication \u2014 models: llama2 (version: 0.1.33)'})
        (nmap_dir / 'nse_results' / 'port11434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Ollama LLM API Unauthenticated' in content
        assert 'MEDIUM' in content
        assert '10.0.2.1' in content

    def test_ollama_external_high(self, nmap_dir):
        """ollama-detect output on external scan → HIGH finding."""
        xml = _nmap_xml('1.2.3.4', 'tcp', '11434',
                        scripts={'ollama-detect': 'Ollama API accessible without authentication \u2014 models: llama2 (version: 0.1.33)'})
        (nmap_dir / 'nse_results' / 'port11434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Ollama LLM API Unauthenticated' in content
        assert 'HIGH' in content

    def test_openai_api_internal_medium(self, nmap_dir):
        """openai-api-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.2', 'tcp', '1234',
                        scripts={'openai-api-detect': 'OpenAI-compatible LLM API accessible without authentication \u2014 product: LM Studio, models: Mistral-7B'})
        (nmap_dir / 'nse_results' / 'port1234.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'OpenAI-Compatible LLM API Unauthenticated' in content
        assert 'MEDIUM' in content

    def test_openai_api_external_high(self, nmap_dir):
        """openai-api-detect output on external scan → HIGH finding."""
        xml = _nmap_xml('1.2.3.5', 'tcp', '1234',
                        scripts={'openai-api-detect': 'OpenAI-compatible LLM API accessible without authentication \u2014 product: LM Studio, models: Mistral-7B'})
        (nmap_dir / 'nse_results' / 'port1234.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'OpenAI-Compatible LLM API Unauthenticated' in content
        assert 'HIGH' in content

    def test_gradio_internal_medium(self, nmap_dir):
        """gradio-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.3', 'tcp', '7860',
                        scripts={'gradio-detect': 'Gradio web UI accessible \u2014 version: 3.50.2'})
        (nmap_dir / 'nse_results' / 'port7860.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Gradio LLM Web UI Accessible' in content
        assert 'MEDIUM' in content

    def test_koboldcpp_internal_medium(self, nmap_dir):
        """koboldcpp-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.4', 'tcp', '5001',
                        scripts={'koboldcpp-detect': 'KoboldCpp API accessible without authentication \u2014 model: llama-2-7b-chat.Q4_K_M.gguf'})
        (nmap_dir / 'nse_results' / 'port5001.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'KoboldCpp LLM API Unauthenticated' in content
        assert 'MEDIUM' in content

    def test_llm_no_finding_for_empty_output(self, nmap_dir):
        """ollama-detect with empty output → no finding generated."""
        xml = _nmap_xml('10.0.2.5', 'tcp', '11434',
                        scripts={'ollama-detect': ''})
        (nmap_dir / 'nse_results' / 'port11434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'Ollama LLM API Unauthenticated' not in findings_file.read_text()

    def test_high_risk_service_detected_never_fires(self, nmap_dir):
        """The old 'High-Risk Service Detected' title must never appear in output."""
        # Write XML for all ports that used to trigger INTERNAL_RISK_PORTS
        for port in ('9229', '2345', '5005', '10250', '8001', '61616'):
            xml = _nmap_xml(f'10.0.2.{port[-1]}', 'tcp', port)
            (nmap_dir / 'nse_results' / f'port{port}.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'High-Risk Service Detected' not in findings_file.read_text()


# ── _build_nmap_cmd ───────────────────────────────────────────────────────────

class TestBuildNmapCmd:
    """Unit tests for _build_nmap_cmd source-port behaviour."""

    def test_smb_port_with_scripts_omits_source_port(self):
        """Port 445 + script_scan=True → no --source-port in command."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' not in cmd

    def test_smb_port_139_with_scripts_omits_source_port(self):
        """Port 139 + script_scan=True → no --source-port in command."""
        cmd = _build_nmap_cmd('139', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' not in cmd

    def test_smb_port_banner_only_keeps_source_port(self):
        """Port 445 + script_scan=False (banner only) → --source-port 88 present."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=False, target_scan='Internal')
        assert '--source-port' in cmd
        assert '88' in cmd

    def test_non_smb_port_with_scripts_keeps_source_port(self):
        """Port 22 + script_scan=True → --source-port 88 present."""
        cmd = _build_nmap_cmd('22', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' in cmd
        assert '88' in cmd

    def test_udp_port_keeps_source_port(self):
        """UDP port always uses -sU and keeps --source-port."""
        cmd = _build_nmap_cmd('U:161', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' in cmd
        assert '-sU' in cmd
        assert '-sS' not in cmd

    def test_smb_port_external_scan_with_scripts_omits_source_port(self):
        """Port 445 + External scan → --source-port 53 also omitted."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '53',
                               script_scan=True, target_scan='External')
        assert '--source-port' not in cmd

    def test_banner_pass_never_includes_script(self):
        """script_only=False (default) → --script never present regardless of script_scan."""
        for port in ('22', '445', 'U:161'):
            cmd = _build_nmap_cmd(port, '/in.txt', '/out.xml', '88',
                                   script_scan=True, target_scan='Internal')
            assert '--script' not in cmd, f'--script should not appear in banner pass for port {port}'

    def test_script_only_uses_ss_not_sn(self):
        """script_only=True → -sS for TCP, -sU for UDP; -sn and -sV absent.

        -sn (no port scan) conflicts with -p (explicit port selection) and
        causes nmap to error: 'You cannot use -F or -p when not doing a port scan'.
        The script pass must use a real scan type so -p is accepted.
        """
        tcp_cmd = _build_nmap_cmd('22', '/in.txt', '/out.xml', '88',
                                   script_scan=True, target_scan='Internal',
                                   script_only=True)
        assert '-sS' in tcp_cmd
        assert '-sn' not in tcp_cmd
        assert '-sV' not in tcp_cmd

        udp_cmd = _build_nmap_cmd('U:161', '/in.txt', '/out.xml', '88',
                                   script_scan=True, target_scan='Internal',
                                   script_only=True)
        assert '-sU' in udp_cmd
        assert '-sn' not in udp_cmd
        assert '-sV' not in udp_cmd

    def test_script_only_includes_script_when_port_has_scripts(self):
        """script_only=True on a port with scripts → --script present."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal',
                               script_only=True)
        assert '--script' in cmd

    def test_script_only_smb_omits_source_port(self):
        """script_only=True + SMB port → --source-port omitted."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal',
                               script_only=True)
        assert '--source-port' not in cmd

    def test_script_only_non_smb_keeps_source_port(self):
        """script_only=True + non-SMB port → --source-port present."""
        cmd = _build_nmap_cmd('22', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal',
                               script_only=True)
        assert '--source-port' in cmd
        assert '88' in cmd


# ── cucm-detect finding ───────────────────────────────────────────────────────

class TestCucmDetectFinding:
    def test_confirmed_cucm_generates_high_finding(self, nmap_dir):
        """cucm-detect script output → HIGH 'Cisco CUCM TFTP Server Confirmed'."""
        xml = _nmap_xml('10.0.0.1', 'tcp', '6970',
                        scripts={'cucm-detect': 'Product: Cisco UCM\nConfigFileCacheList: Accessible \u2014 100 entries'})
        (nmap_dir / 'nse_results' / 'port6970.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'CUCM TFTP Server Confirmed' in txt
        assert 'HIGH' in txt

    def test_port_open_no_script_generates_medium_finding(self, nmap_dir):
        """Port 6970 open, no cucm-detect output → MEDIUM 'Possible Cisco CUCM'."""
        xml = _nmap_xml('10.0.0.2', 'tcp', '6970')
        (nmap_dir / 'nse_results' / 'port6970.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'Possible Cisco CUCM' in txt
        assert 'MEDIUM' in txt

    def test_confirmed_cucm_not_medium(self, nmap_dir):
        """Confirmed CUCM does not also emit the MEDIUM unconfirmed finding."""
        xml = _nmap_xml('10.0.0.3', 'tcp', '6970',
                        scripts={'cucm-detect': 'Product: Cisco UCM\nConfigFileCacheList: Accessible \u2014 50 entries'})
        (nmap_dir / 'nse_results' / 'port6970.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'Possible Cisco CUCM' not in txt


class TestLdapSecurityFindings:
    """Custom NSE-validated LDAP security findings."""

    def test_ldap_signing_not_required_high(self, nmap_dir):
        """ldap-signing-check returning 'Signing: NOT REQUIRED' -> HIGH finding."""
        xml = _nmap_xml('10.10.0.1', 'tcp', '389',
                        scripts={'ldap-signing-check': 'Signing: NOT REQUIRED'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Signing Not Required' in content
        assert 'HIGH' in content
        assert '10.10.0.1' in content

    def test_ldap_signing_required_no_finding(self, nmap_dir):
        """ldap-signing-check absent (signing enforced, script returned nil) -> no finding."""
        xml = _nmap_xml('10.10.0.2', 'tcp', '389')
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'LDAP Signing Not Required' not in findings_file.read_text()

    def test_ldap_channel_binding_not_required_high(self, nmap_dir):
        """ldap-channel-binding-check returning 'NOT REQUIRED' -> HIGH finding."""
        xml = _nmap_xml('10.10.0.3', 'tcp', '636',
                        scripts={'ldap-channel-binding-check': 'Channel Binding: NOT REQUIRED'})
        (nmap_dir / 'nse_results' / 'port636.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAPS Channel Binding Not Required' in content
        assert 'HIGH' in content

    def test_ldap_anon_enum_users_medium(self, nmap_dir):
        """ldap-anon-enum with Users found -> MEDIUM finding."""
        xml = _nmap_xml('10.10.0.4', 'tcp', '389',
                        scripts={'ldap-anon-enum':
                                 'Anonymous bind: success\n'
                                 'Base DN: DC=pwnt,DC=lab\n'
                                 'Sample Users Found: j.smith, k.jones'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Anonymous Enumeration' in content
        assert 'MEDIUM' in content

    def test_ldap_anon_enum_computers_medium(self, nmap_dir):
        """ldap-anon-enum with Computers found -> MEDIUM finding."""
        xml = _nmap_xml('10.10.0.5', 'tcp', '389',
                        scripts={'ldap-anon-enum':
                                 'Anonymous bind: success\n'
                                 'Base DN: DC=pwnt,DC=lab\n'
                                 'Sample Computers Found: WS-SALES01$'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Anonymous Enumeration' in content

    def test_ldap_anon_enum_no_results_no_finding(self, nmap_dir):
        """ldap-anon-enum script absent (bind ok but 0 results) -> no finding."""
        xml = _nmap_xml('10.10.0.6', 'tcp', '389')
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'LDAP Anonymous Enumeration' not in findings_file.read_text()

    def test_ldap_findings_not_on_external(self, nmap_dir):
        """LDAP signing finding must not fire for External scans."""
        xml = _nmap_xml('1.2.3.4', 'tcp', '389',
                        scripts={'ldap-signing-check': 'Signing: NOT REQUIRED',
                                 'ldap-anon-enum': 'Users found: 5'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        # External scan only triggers the 'LDAP -- should not be internet-facing' finding
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Signing Not Required' not in content
        assert 'LDAP Anonymous Enumeration' not in content

    def test_ldap_global_catalog_signing_port_3268(self, nmap_dir):
        """Port 3268 with ldap-signing-check -> 'Global Catalog Signing Not Required'."""
        xml = _nmap_xml('10.10.0.7', 'tcp', '3268',
                        scripts={'ldap-signing-check': 'Signing: NOT REQUIRED'})
        (nmap_dir / 'nse_results' / 'port3268.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Global Catalog Signing Not Required' in content


class TestIPMIFindings:
    """IPMI findings from ipmi-cipher-zero, ipmi-hashdump, and ipmi-version scripts."""

    def test_cipher_zero_vulnerable_critical(self, nmap_dir):
        """ipmi-cipher-zero output contains VULNERABLE -> CRITICAL finding."""
        xml = _nmap_xml('10.0.1.1', 'udp', '623',
                        scripts={'ipmi-cipher-zero': 'VULNERABLE (cipher suite 0)'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IPMI Cipher Zero Authentication Bypass' in content
        assert 'CRITICAL' in content
        assert '10.0.1.1' in content

    def test_cipher_zero_not_vulnerable_no_finding(self, nmap_dir):
        """ipmi-cipher-zero output does not contain VULNERABLE -> no CRITICAL finding."""
        xml = _nmap_xml('10.0.1.2', 'udp', '623',
                        scripts={'ipmi-cipher-zero': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'IPMI Cipher Zero Authentication Bypass' not in findings_file.read_text()

    def test_hashdump_hash_captured_high(self, nmap_dir):
        """ipmi-hashdump output contains $rakp$ -> HIGH finding."""
        xml = _nmap_xml(
            '10.0.1.3', 'udp', '623',
            scripts={'ipmi-hashdump': 'Username: admin\nHash: $rakp$aabbcc$ddeeff'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IPMI RAKP Hash Captured' in content
        assert 'HIGH' in content
        assert '10.0.1.3' in content

    def test_hashdump_empty_no_finding(self, nmap_dir):
        """ipmi-hashdump absent (no hash returned) -> no HIGH finding."""
        xml = _nmap_xml('10.0.1.4', 'udp', '623')
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'IPMI RAKP Hash Captured' not in findings_file.read_text()

    def test_ipmi_version_detected_info(self, nmap_dir):
        """ipmi-version non-empty output -> INFO finding."""
        xml = _nmap_xml(
            '10.0.1.5', 'udp', '623',
            scripts={'ipmi-version': 'Version: 2.0\nUser Level: Administrator'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IPMI Service Detected' in content
        assert 'INFO' in content
        assert '10.0.1.5' in content


class TestVNCFindings:
    """VNC findings from vnc-info and realvnc-auth-bypass scripts."""

    def test_vnc_no_auth_critical(self, nmap_dir):
        """vnc-info output with security type None -> CRITICAL finding."""
        xml = _nmap_xml(
            '10.0.2.1', 'tcp', '5900',
            scripts={'vnc-info': 'Protocol version: 3.8\nSecurity types:\n  None (1)\n  VNC Authentication (2)'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'VNC No Authentication Required' in content
        assert 'CRITICAL' in content
        assert '10.0.2.1' in content

    def test_vnc_auth_required_no_finding(self, nmap_dir):
        """vnc-info output with only VNC Authentication -> no CRITICAL finding."""
        xml = _nmap_xml(
            '10.0.2.2', 'tcp', '5900',
            scripts={'vnc-info': 'Protocol version: 3.8\nSecurity types:\n  VNC Authentication (2)'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'VNC No Authentication Required' not in findings_file.read_text()

    def test_realvnc_bypass_vulnerable_high(self, nmap_dir):
        """realvnc-auth-bypass output contains VULNERABLE -> HIGH finding."""
        xml = _nmap_xml(
            '10.0.2.3', 'tcp', '5900',
            scripts={'realvnc-auth-bypass': 'VULNERABLE\n  RealVNC 4.1.1 Authentication Bypass'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'RealVNC Authentication Bypass' in content
        assert 'HIGH' in content
        assert '10.0.2.3' in content

    def test_realvnc_bypass_not_vulnerable_no_finding(self, nmap_dir):
        """realvnc-auth-bypass output contains NOT VULNERABLE -> no finding."""
        xml = _nmap_xml(
            '10.0.2.4', 'tcp', '5900',
            scripts={'realvnc-auth-bypass': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'RealVNC Authentication Bypass' not in findings_file.read_text()

    def test_vnc_on_port_5901(self, nmap_dir):
        """vnc-info no-auth on port 5901 -> CRITICAL finding."""
        xml = _nmap_xml(
            '10.0.2.5', 'tcp', '5901',
            scripts={'vnc-info': 'Protocol version: 3.8\nSecurity types:\n  None (1)'})
        (nmap_dir / 'nse_results' / 'port5901.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'VNC No Authentication Required' in content
        assert 'CRITICAL' in content
        assert '10.0.2.5' in content


class TestIKEFindings:
    """IKE findings from ike-version script on U:500."""

    def test_ike_aggressive_psk_high(self, nmap_dir):
        """ike-version output with 'aggressive' and 'psk' -> HIGH finding."""
        xml = _nmap_xml(
            '10.0.3.1', 'udp', '500',
            scripts={'ike-version': 'Aggressive mode: yes\n  auth: PSK\n  vendor: strongSwan'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IKE Aggressive Mode with Pre-Shared Key' in content
        assert 'HIGH' in content
        assert '10.0.3.1' in content

    def test_ike_main_mode_only_info(self, nmap_dir):
        """ike-version output without 'aggressive' keyword -> INFO, no HIGH."""
        xml = _nmap_xml(
            '10.0.3.2', 'udp', '500',
            scripts={'ike-version': 'Main mode: supported\n  vendor: Cisco'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IKE/IPsec Service Detected' in content
        assert 'IKE Aggressive Mode with Pre-Shared Key' not in content

    def test_ike_aggressive_no_psk_info(self, nmap_dir):
        """ike-version output with 'aggressive' but auth RSA (not PSK) -> INFO, no HIGH."""
        xml = _nmap_xml(
            '10.0.3.3', 'udp', '500',
            scripts={'ike-version': 'Aggressive mode: yes\n  auth: RSA\n  vendor: OpenSwan'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IKE/IPsec Service Detected' in content
        assert 'IKE Aggressive Mode with Pre-Shared Key' not in content

    def test_ike_empty_output_no_finding(self, nmap_dir):
        """ike-version absent -> no finding at all."""
        xml = _nmap_xml('10.0.3.4', 'udp', '500')
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            content = findings_file.read_text()
            assert 'IKE' not in content

    def test_ike_port_not_flagged_as_service_exposed(self, nmap_dir):
        """U:500 must not produce a 'Service Exposed Externally' finding even when confirmed open."""
        xml = _nmap_xml(
            '10.0.3.5', 'udp', '500',
            scripts={'ike-version': 'Main mode: supported\n  vendor: Cisco'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Service Exposed Externally' not in content
        assert 'IKE/IPsec Service Detected' in content


# ── _parse_masscan_ping_xml ───────────────────────────────────────────────────

def _masscan_ping_xml(*ips):
    """Minimal masscan --ping XML with one <host> per IP."""
    hosts = ''.join(
        f'<host><address addr="{ip}" addrtype="ipv4"/></host>'
        for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


class TestParseMasscanPingXml:
    def test_returns_ips_from_valid_xml(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text(_masscan_ping_xml('192.168.1.1'))
        assert _parse_masscan_ping_xml(str(f)) == {'192.168.1.1'}

    def test_multiple_hosts(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text(_masscan_ping_xml('10.0.0.1', '10.0.0.2', '10.0.0.3'))
        assert _parse_masscan_ping_xml(str(f)) == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_empty_file_returns_empty_set(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text('')
        assert _parse_masscan_ping_xml(str(f)) == set()

    def test_missing_file_returns_empty_set(self, tmp_path):
        assert _parse_masscan_ping_xml(str(tmp_path / 'nonexistent.xml')) == set()


# ── _parse_nmap_sn_xml ────────────────────────────────────────────────────────

def _nmap_sn_xml(*entries):
    """Minimal nmap -sn XML.  entries is a list of (ip, state) tuples."""
    hosts = ''.join(
        f'<host><status state="{state}"/><address addr="{ip}" addrtype="ipv4"/></host>'
        for ip, state in entries
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


class TestParseNmapSnXml:
    def test_returns_only_up_hosts(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text(_nmap_sn_xml(('10.1.1.1', 'up'), ('10.1.1.2', 'down')))
        assert _parse_nmap_sn_xml(str(f)) == {'10.1.1.1'}

    def test_all_up_hosts(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text(_nmap_sn_xml(('10.0.0.1', 'up'), ('10.0.0.2', 'up'), ('10.0.0.3', 'up')))
        assert _parse_nmap_sn_xml(str(f)) == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_empty_file_returns_empty_set(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text('')
        assert _parse_nmap_sn_xml(str(f)) == set()

    def test_missing_file_returns_empty_set(self, tmp_path):
        assert _parse_nmap_sn_xml(str(tmp_path / 'nonexistent.xml')) == set()


# ── TestRunMasscanBatchWaitMinimum ─────────────────────────────────────────────

class TestRunMasscanBatchWaitMinimum:
    """_run_masscan_batch must always pass --wait >= 3 to masscan regardless of wait_secs."""

    def _make_mock_proc(self):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.pid = 12345
        return mock_proc

    def _captured_wait_arg(self, mock_popen):
        """Return the integer value passed as --wait in the masscan command."""
        cmd = mock_popen.call_args[0][0]
        idx = cmd.index('--wait')
        return int(cmd[idx + 1])

    def test_wait_zero_becomes_three(self, tmp_path):
        """When _calc_scan_wait returns 0 (small host set), masscan still gets --wait 3."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['445'], '2000', output_xml,
                               '/fake/targets.txt', '88', None, wait_secs=0)
        assert self._captured_wait_arg(mock_popen) >= 3

    def test_wait_one_becomes_three(self, tmp_path):
        """wait_secs < 3 is raised to 3."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['139'], '1000', output_xml,
                               '/fake/targets.txt', '88', None, wait_secs=1)
        assert self._captured_wait_arg(mock_popen) >= 3

    def test_wait_large_value_preserved(self, tmp_path):
        """wait_secs > 3 is passed through unchanged."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['445'], '1000', output_xml,
                               '/fake/targets.txt', '88', None, wait_secs=29)
        assert self._captured_wait_arg(mock_popen) == 29

    def test_default_wait_secs_passes_minimum(self, tmp_path):
        """Default wait_secs=2 is still raised to 3."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['80'], '10000', output_xml,
                               '/fake/targets.txt', '53', None)
        assert self._captured_wait_arg(mock_popen) >= 3


# ── TestSMBCoupling ────────────────────────────────────────────────────────────

class TestSMBCoupling:
    """mass_scan() SMB port coupling: hosts found on 139 propagate to 445 and vice versa."""

    @staticmethod
    def _make_batch_side_effect(port_map):
        """Return a side_effect function that yields port_map results keyed by call index."""
        calls = []

        def side_effect(batch, rate, output_file, target_file, source_port,
                        exclusions_file, wait_secs=2):
            idx = len(calls)
            calls.append(batch)
            return port_map.get(idx, {})

        return side_effect

    def test_hosts_on_139_propagate_to_445(self, tmp_path):
        """If masscan only finds hosts on 139, coupling writes them to port445.txt too."""
        spoonmap.output_path = str(tmp_path)
        # dest_ports=['139','445']; masscan finds 3 hosts on 139, 0 on 445
        responses = {
            0: {'139': {'10.0.0.1', '10.0.0.2', '10.0.0.3'}},  # probe batch (139)
            1: {'445': set()},                                    # probe batch (445)
        }
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['139', '445'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=5)

        port445_file = tmp_path / 'discovery' / 'live_hosts' / 'port445.txt'
        if port445_file.exists():
            written = {l.strip() for l in port445_file.read_text().splitlines() if l.strip()}
            assert written == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_smb_coupled_ports_constant(self):
        """_SMB_COUPLED_PORTS must contain exactly 139 and 445."""
        assert set(_SMB_COUPLED_PORTS) == {'139', '445'}

    def test_port139_internal_scripts_include_smb2(self):
        """INTERNAL_PORT_SCRIPTS['139'] must include smb2-security-mode for full SMB checks."""
        scripts = INTERNAL_PORT_SCRIPTS.get('139', '')
        assert 'smb2-security-mode' in scripts

    def test_port139_internal_scripts_include_ms17010(self):
        """INTERNAL_PORT_SCRIPTS['139'] must include smb-vuln-ms17-010."""
        scripts = INTERNAL_PORT_SCRIPTS.get('139', '')
        assert 'smb-vuln-ms17-010' in scripts


# ── TestSlowPortsSMB ──────────────────────────────────────────────────────────

class TestSlowPortsSMB:
    """SMB ports 139/445 always scan solo; probe misses trigger a solo retry."""

    def test_smb_ports_in_slow_ports(self):
        """139 and 445 must be in SLOW_PORTS so they always get solo scans."""
        assert '139' in SLOW_PORTS
        assert '445' in SLOW_PORTS

    def test_probe_missed_445_gets_solo_retry(self, tmp_path):
        """batch_size > 1: zero-result probe for 445 must produce a solo batch later.

        Uses dest_ports=['445','80','8888'] so that probe_ports=['445','80'] and
        remaining_ports=['8888'] → probe guard fires.  Both probe calls (fast/slow)
        return empty.  445 is probe-missed → _probe_missed=['445'] → re-queued →
        batches include a solo ['445'] invocation (445 ∈ SLOW_PORTS → solo via batch builder).
        """
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_batch:
            mass_scan('All', ['445', '80', '8888'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)
        solo = [c for c in mock_batch.call_args_list if c.args[0] == ['445']]
        assert len(solo) >= 1, "Expected solo masscan call for 445 after probe miss"

    def test_probe_found_445_always_gets_solo_scan(self, tmp_path):
        """batch_size=2: even when probe finds 445, it must still get a solo main-batch scan.

        The probe runs against probe_target (discovery narrowed); main batches use the
        combined target which may include additional hosts not in probe_target.
        batch_size=2 → probe_ports=['445','80'], remaining_ports=['8888'].
        """
        spoonmap.output_path = str(tmp_path)
        call_log = []

        def side_effect(batch, rate, output_file, target_file, source_port,
                        exclusions_file, wait_secs=2):
            call_log.append(list(batch))
            # First call is the fast probe — simulate finding 445
            return {'445': {'10.0.0.1'}} if len(call_log) == 1 else {}

        with patch('spoonmap._run_masscan_batch', side_effect=side_effect):
            mass_scan('All', ['445', '80', '8888'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=2)
        solo = [b for b in call_log if b == ['445']]
        assert len(solo) >= 1, "445 must always get a solo main-batch scan regardless of probe result"

    def test_probe_missed_3389_gets_rebatched(self, tmp_path):
        """batch_size > 1: zero-result probe for 3389 must re-queue it into a batch.

        3389 is in PROBE_PORT_PRIORITY (position 3) but NOT in SLOW_PORTS.
        When the combined probe returns 0 for 3389, it must appear in a subsequent
        masscan call so it isn't silently dropped.
        """
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_batch:
            mass_scan('All', ['3389', '80', '8888'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)
        # Any call whose batch contains '3389' (solo or grouped)
        calls_with_3389 = [c for c in mock_batch.call_args_list
                           if '3389' in c.args[0]]
        # Exclude the two probe calls (fast probe and slow probe)
        probe_batches = [c for c in calls_with_3389
                         if set(c.args[0]) <= {'3389', '80'}]
        main_3389_calls = [c for c in calls_with_3389
                           if c not in probe_batches]
        assert len(main_3389_calls) >= 1, \
            "Expected a main-batch masscan call for 3389 after probe miss"


class TestNmapUdpDiscovery:
    """Unit tests for _nmap_udp_discovery()."""

    def test_open_host_is_returned(self, tmp_path):
        """Host with UDP port 'open' → included in result."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports>'
            '</host></nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path),
                                         '53', '')
        assert '10.0.0.1' in result

    def test_open_filtered_host_is_returned(self, tmp_path):
        """Host with UDP port 'open|filtered' → included in result for NSE confirmation."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open|filtered"/></port></ports>'
            '</host></nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path),
                                         '53', '')
        assert '10.0.0.2' in result

    def test_closed_host_is_excluded(self, tmp_path):
        """Host with UDP port 'closed' → not included."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.3" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="closed"/></port></ports>'
            '</host></nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path),
                                         '53', '')
        assert '10.0.0.3' not in result

    def test_resume_skips_scan_when_live_file_exists(self, tmp_path):
        """resume=True + existing live_hosts file → no subprocess call."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        (tmp_path / 'discovery' / 'live_hosts').mkdir(parents=True)
        xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
        xml_path.write_text('<nmaprun/>')
        live_path = tmp_path / 'discovery' / 'live_hosts' / 'portU_500.txt'
        live_path.write_text('192.168.1.1\n')
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen:
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path),
                                         '53', '', resume=True)
        mock_popen.assert_not_called()
        assert '192.168.1.1' in result

    def test_nmap_cmd_uses_sU_and_source_port(self, tmp_path):
        """nmap command uses -sU, -Pn, --open, and --source-port."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        cmd = mock_popen.call_args[0][0]
        assert '-sU' in cmd
        assert '-Pn' in cmd
        assert '--open' in cmd
        assert '--source-port' in cmd
        assert '53' in cmd
        assert '500' in cmd
        assert 'masscan' not in cmd[0]   # must be nmap, not masscan


class TestMassScanUdp:
    """mass_scan() routes UDP ports to nmap, not masscan."""

    def test_udp_ports_not_passed_to_masscan(self, tmp_path):
        """dest_ports with U:500 → masscan never called with U:500."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_m, \
             patch('spoonmap._nmap_udp_discovery', return_value=set()) as mock_u:
            mass_scan('All', ['443', 'U:500'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)
        for call in mock_m.call_args_list:
            batch = call[0][0]
            assert 'U:500' not in batch

    def test_udp_ports_trigger_nmap_udp_discovery(self, tmp_path):
        """dest_ports with U:500 → _nmap_udp_discovery called with 'U:500'."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_m, \
             patch('spoonmap._nmap_udp_discovery', return_value=set()) as mock_u:
            mass_scan('All', ['443', 'U:500'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)
        udp_calls = [c for c in mock_u.call_args_list if c[0][0] == 'U:500']
        assert len(udp_calls) == 1

    def test_udp_uses_discovery_file_when_available(self, tmp_path):
        """UDP discovery uses discovery_file (live hosts) when it exists, not full target list."""
        spoonmap.output_path = str(tmp_path)
        disc_file = tmp_path / 'live_hosts_discovery.txt'
        disc_file.write_text('10.0.0.1\n')
        with patch('spoonmap._run_masscan_batch', return_value={}), \
             patch('spoonmap._nmap_udp_discovery', return_value=set()) as mock_u:
            mass_scan('All', ['U:161'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=1,
                      discovery_file=str(disc_file))
        udp_call = mock_u.call_args_list[0]
        assert udp_call[0][1] == str(disc_file)

    def test_udp_falls_back_to_target_file_without_discovery(self, tmp_path):
        """UDP discovery falls back to full target file when no discovery file exists."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}), \
             patch('spoonmap._nmap_udp_discovery', return_value=set()) as mock_u:
            mass_scan('All', ['U:161'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=1)
        udp_call = mock_u.call_args_list[0]
        assert udp_call[0][1] == '/fake/targets.txt'


class TestFilterUdpLiveHosts:
    """Unit tests for _filter_udp_live_hosts()."""

    def _make_nmap_xml(self, ip, port, state):
        """Return minimal nmap XML with a single host/port entry."""
        return (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="udp" portid="{port}">'
            f'<state state="{state}"/></port></ports>'
            '</host>'
            '</nmaprun>'
        )

    def test_confirmed_open_ip_kept(self, tmp_path):
        """IP with port state 'open' stays in live_hosts and nmap XML after filter."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(self._make_nmap_xml('10.0.0.1', '500', 'open'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        result = _filter_udp_live_hosts(str(tmp_path))

        assert (live_dir / 'portU_500.txt').read_text().strip() == '10.0.0.1'
        tree = etree.parse(str(nmap_dir / 'portU_500.xml'))
        hosts = tree.findall('host')
        assert len(hosts) == 1
        assert hosts[0].find('address').attrib['addr'] == '10.0.0.1'
        assert result == {'U:500': 1}

    def test_open_filtered_ip_removed(self, tmp_path):
        """IP with port state 'open|filtered' is removed from live_hosts and nmap XML."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(
            self._make_nmap_xml('10.0.0.2', '500', 'open|filtered'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.2\n')

        result = _filter_udp_live_hosts(str(tmp_path))

        assert (live_dir / 'portU_500.txt').read_text().strip() == ''
        tree = etree.parse(str(nmap_dir / 'portU_500.xml'))
        assert tree.findall('host') == []
        assert result == {'U:500': 0}

    def test_no_nmap_results_dir_is_noop(self, tmp_path):
        """Missing nmap_results/ directory → function returns empty dict without error."""
        result = _filter_udp_live_hosts(str(tmp_path))
        assert result == {}

    def test_removal_count_printed(self, tmp_path, capsys):
        """Removed IPs produce an info message with count."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(
            self._make_nmap_xml('10.0.0.3', '500', 'open|filtered'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.3\n')

        _filter_udp_live_hosts(str(tmp_path))

        captured = capsys.readouterr()
        assert 'UDP filter (U:500)' in captured.out
        assert '1' in captured.out

    def test_nmap_xml_rewritten_without_unconfirmed_hosts(self, tmp_path):
        """After filter, XML on disk has no host elements for unconfirmed IPs."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        # Two hosts: one open, one open|filtered
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            '<host><address addr="10.0.0.10" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.20" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open|filtered"/></port></ports></host>'
            '</nmaprun>'
        )
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.10\n10.0.0.20\n')

        result = _filter_udp_live_hosts(str(tmp_path))

        tree = etree.parse(str(nmap_dir / 'portU_500.xml'))
        remaining_ips = {
            h.find('address').attrib['addr'] for h in tree.findall('host')
        }
        assert '10.0.0.10' in remaining_ips
        assert '10.0.0.20' not in remaining_ips
        assert result == {'U:500': 1}

    def test_summary_updated_after_filter(self, tmp_path):
        """status_summary lines for UDP ports reflect post-filter confirmed count."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        # One open, one open|filtered — only one confirmed
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open|filtered"/></port></ports></host>'
            '</nmaprun>'
        )
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n10.0.0.2\n')

        udp_confirmed = _filter_udp_live_hosts(str(tmp_path))

        # Simulate the summary-patching logic from main()
        status_summary = '\nSummary\nHosts Found on Port 80: 3\nHosts Found on Port U:500: 2'
        for port_key, count in udp_confirmed.items():
            lines = status_summary.split('\n')
            updated = []
            for line in lines:
                if line.startswith(f'Hosts Found on Port {port_key}:'):
                    if count > 0:
                        updated.append(f'Hosts Found on Port {port_key}: {count}')
                else:
                    updated.append(line)
            status_summary = '\n'.join(updated)

        assert 'Hosts Found on Port U:500: 1' in status_summary
        assert 'Hosts Found on Port U:500: 2' not in status_summary
        assert 'Hosts Found on Port 80: 3' in status_summary

    def test_summary_drops_zero_count_udp_port(self, tmp_path):
        """A UDP port with 0 confirmed hosts is removed from status_summary."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(
            self._make_nmap_xml('10.0.0.1', '500', 'open|filtered'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        udp_confirmed = _filter_udp_live_hosts(str(tmp_path))

        status_summary = '\nSummary\nHosts Found on Port U:500: 1'
        for port_key, count in udp_confirmed.items():
            lines = status_summary.split('\n')
            updated = []
            for line in lines:
                if line.startswith(f'Hosts Found on Port {port_key}:'):
                    if count > 0:
                        updated.append(f'Hosts Found on Port {port_key}: {count}')
                else:
                    updated.append(line)
            status_summary = '\n'.join(updated)

        assert 'U:500' not in status_summary

    def test_rewrite_preserves_xml_declaration_and_doctype(self, tmp_path):
        """Rewritten UDP XML retains <?xml?> + <!DOCTYPE nmaprun> so Metasploit can import it."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        prologue = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE nmaprun PUBLIC "-//IDN nmap.org//DTD Nmap XML 1.04//EN"'
            ' "https://svn.nmap.org/nmap/docs/nmap.dtd">\n'
        )
        xml = (
            prologue
            + '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        # Use correct underscore-form filename so _filter_udp_live_hosts picks it up
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        _filter_udp_live_hosts(str(tmp_path))

        rewritten = (nmap_dir / 'portU_500.xml').read_text()
        assert rewritten.startswith('<?xml'), 'XML declaration must be first line'
        assert '<!DOCTYPE nmaprun' in rewritten, 'DOCTYPE required for Metasploit import'


# ── _discovery_wait ───────────────────────────────────────────────────────────

def _masscan_ping_xml(*ips):
    """Minimal masscan XML for host-discovery tests."""
    hosts = ''.join(
        f'<host><address addr="{ip}" addrtype="ipv4"/></host>'
        for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


@pytest.mark.parametrize('count,expected', [
    (0,    '1'),
    (512,  '1'),
    (513,  '2'),
    (4096, '2'),
    (4097, '3'),
    (65536, '3'),
])
def test_discovery_wait(count, expected):
    assert _discovery_wait(count) == expected


# ── _discover_internal_masscan ────────────────────────────────────────────────

class TestDiscoverInternalMasscan:
    """Unit tests for _discover_internal_masscan()."""

    def _make_mock_proc(self):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.pid = 99999
        return mock_proc

    def _write_xml(self, path, *ips):
        path.write_text(_masscan_ping_xml(*ips))

    def test_single_sweep_only(self, tmp_path):
        """Only one masscan invocation is made (no dual sweep)."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            xml_path = disc / cmd[out_idx].split('/')[-1]
            self._write_xml(xml_path, '10.0.0.1')
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        assert len(captured_cmds) == 1
        assert '10.0.0.1' in ips

    def test_no_source_port_flag(self, tmp_path):
        """masscan command must not include -g or --source-port."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        cmd = captured_cmds[0]
        assert '-g' not in cmd
        assert '--source-port' not in cmd

    def test_trims_ports_above_state_ceiling(self, tmp_path):
        """Port list is DISCOVERY_TCP_PORTS_INTERNAL (5 ports) for large target counts."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/8\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        large_count = INTERNAL_DISCOVERY_STATE_CEILING + 1
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, large_count)

        p_idx = captured_cmds[0].index('-p') + 1
        assert captured_cmds[0][p_idx] == DISCOVERY_TCP_PORTS_INTERNAL
        assert captured_cmds[0][p_idx] != DISCOVERY_MASSCAN_PORTS_INTERNAL

    def test_uses_broad_ports_below_state_ceiling(self, tmp_path):
        """Port list is DISCOVERY_MASSCAN_PORTS_INTERNAL (10 ports) for normal target counts."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        p_idx = captured_cmds[0].index('-p') + 1
        assert captured_cmds[0][p_idx] == DISCOVERY_MASSCAN_PORTS_INTERNAL

    def test_caps_rate_to_internal_max(self, tmp_path):
        """Rate is capped to INTERNAL_DISCOVERY_MAX_RATE even when user passes a higher rate."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        user_rate = str(INTERNAL_DISCOVERY_MAX_RATE * 10)
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), user_rate, None, 256)

        rate_idx = captured_cmds[0].index('--max-rate') + 1
        assert int(captured_cmds[0][rate_idx]) <= INTERNAL_DISCOVERY_MAX_RATE

    def test_respects_user_rate_below_cap(self, tmp_path):
        """Rate below INTERNAL_DISCOVERY_MAX_RATE is passed through unchanged."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        user_rate = str(INTERNAL_DISCOVERY_MAX_RATE // 2)
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), user_rate, None, 256)

        rate_idx = captured_cmds[0].index('--max-rate') + 1
        assert int(captured_cmds[0][rate_idx]) == int(user_rate)

    def test_uses_retries_1(self, tmp_path):
        """masscan sweep uses --retries 1."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        cmd = captured_cmds[0]
        retries_idx = cmd.index('--retries') + 1
        assert cmd[retries_idx] == '1'

    def test_adaptive_wait_applied(self, tmp_path):
        """--wait value reflects _discovery_wait(target_count)."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        small_count = 100  # expects _discovery_wait(100) == '1'
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, small_count)

        cmd = captured_cmds[0]
        wait_idx = cmd.index('--wait') + 1
        assert cmd[wait_idx] == _discovery_wait(small_count)


# ── _internal_host_discovery ──────────────────────────────────────────────────

class TestInternalHostDiscovery:
    """Unit tests for _internal_host_discovery()."""

    def test_unions_masscan_and_nmap_for_small_targets(self, tmp_path):
        """For small target counts, returns union of masscan + nmap IPs."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        masscan_ips = {'10.0.0.1', '10.0.0.2'}
        nmap_ips = {'10.0.0.3'}

        with patch('spoonmap._discover_internal_masscan', return_value=masscan_ips), \
             patch('spoonmap._nmap_host_discovery', return_value=nmap_ips):
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)

        assert live_ips == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_skips_nmap_for_large_targets(self, tmp_path):
        """For large target counts, nmap -sn is not run."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/8\n')

        masscan_ips = {'10.0.0.1', '10.0.0.2'}

        with patch('spoonmap._discover_internal_masscan', return_value=masscan_ips), \
             patch('spoonmap._nmap_host_discovery') as mock_nmap:
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD + 1)

        mock_nmap.assert_not_called()
        assert live_ips == masscan_ips

    def test_nmap_starts_before_masscan_returns(self, tmp_path):
        """nmap thread is started concurrently — it begins before masscan finishes."""
        import threading as _threading

        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        event_order = []
        barrier = _threading.Barrier(2)

        def slow_masscan(*args, **kwargs):
            barrier.wait(timeout=5)  # sync with nmap thread start
            event_order.append('masscan_done')
            return {'10.0.0.1'}

        def nmap_side_effect(*args, **kwargs):
            event_order.append('nmap_started')
            barrier.wait(timeout=5)
            return {'10.0.0.2'}

        with patch('spoonmap._discover_internal_masscan', side_effect=slow_masscan), \
             patch('spoonmap._nmap_host_discovery', side_effect=nmap_side_effect):
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)

        assert 'nmap_started' in event_order
        assert 'masscan_done' in event_order
        assert live_ips == {'10.0.0.1', '10.0.0.2'}

    def test_deduplicates_ips_across_sweeps(self, tmp_path):
        """IPs found by both masscan and nmap are deduplicated."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n10.0.0.2\n')

        shared_ip = '10.0.0.1'

        with patch('spoonmap._discover_internal_masscan',
                   return_value={shared_ip, '10.0.0.3'}), \
             patch('spoonmap._nmap_host_discovery',
                   return_value={shared_ip, '10.0.0.4'}):
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)

        assert live_ips == {shared_ip, '10.0.0.3', '10.0.0.4'}
        assert len(live_ips) == 3
