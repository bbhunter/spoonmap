# SpooNMAP

## Dependencies
This script is a wrapper for masscan (fast port discovery) and nmap (service banner grabbing / NSE scripts). Install both from your favourite package manager or from source.

Python 3.6+ is required (uses f-strings).

## Usage
Simply executing the script will prompt you for all required options.

```
# ./spoonmap.py

________                   _____   _______  _________________
__  ___/______________________  | / /__   |/  /__    |__  __ \
_____ \___  __ \  __ \  __ \_   |/ /__  /|_/ /__  /| |_  /_/ /
____/ /__  /_/ / /_/ / /_/ /  /|  / _  /  / / _  ___ |  ____/
/____/ _  .___/\____/\____//_/ |_/  /_/  /_/  /_/  |_/_/
       /_/


Service Categories (comma-separated numbers, default: All)
	(1) Web          [80, 443, 7001, 7002, 8000, 8080, 8081, 8443, 8888, 9090, 10443]
	(2) Database     [1433, U:1434, 1521, 3306, 5432, 6379, 9200, 27017]
	(3) Remote Management  [22, 23, 3389, 5900, 5901, 6129, 1723, 5985, 5986]
	(4) Email        [25, 110, 143, 465, 587, 993, 995]
	(5) Authentication     [389, 636, 445, 135, 139, U:137]
	(6) Network Infrastructure  [53, 179, 500, U:500, 161, U:161]
	(7) File Transfer      [21, 111]
	(8) Specialized  [1090, 3300, 4786, 6970, 2375, 4243, 9100]
	(9) Full Port Scan  [1-65535]
	(c) Custom Port Scan  [enter your own comma-separated ports]

Which categories would you like to scan (e.g. 1,3 — default: All)?

Would you like to enumerate service banners for any identified services (default: Yes)?

Would you like to run NSE security scripts on identified services (default: No)?

Target Scan
	(1) External
	(2) Internal

Is this an internal or external scan (default: External)?

How fast would you like to scan (default: 10000 packets/second)?

Please enter the full path for the file containing target hosts (default: /opt/spoonmap/ranges.txt):

Would you like to exclude any hosts? (default: No)
```

You can also create a `config.json` file (based on `config.json.sample`) to skip all prompts:

```json
{
    "scan_categories": ["Web", "Database", "Remote Management"],
    "banner_scan": "True",
    "script_scan": "False",
    "target_scan": "Internal",
    "max_rate": "1000",
    "target_file": "ranges.txt",
    "output_path": "./",
    "exclusions_file": "exclusions.txt",
    "nmap_threads": 5
}
```

To scan all categories, set `"scan_categories": "All"`.
To scan all 65535 ports, set `"scan_categories": "Full"`.
For a fully custom port list, omit `scan_categories` and use `"dest_ports": ["80","443","U:53"]` instead.
UDP ports are specified with a `U:` prefix (e.g. `"U:53"`).

If a previous scan's output is detected in `output_path`, the tool offers to delete it or resume where it left off.

To remove scan data non-interactively, use the `--cleanup` flag:

```
# Path taken from output_path in config.json
./spoonmap.py --cleanup

# Or specify the directory explicitly
./spoonmap.py --cleanup /path/to/output
```

## config.json Parameters

| Key | Values | Notes |
|-----|--------|-------|
| `scan_categories` | `"All"`, `"Full"`, or array of category names | `"Full"` scans all 65535 ports; e.g. `["Web","Database"]`; omit to use `dest_ports` |
| `dest_ports` | Array of port strings | Overrides `scan_categories`; use `U:` prefix for UDP |
| `banner_scan` | `"True"` / `"False"` | Runs nmap -sV against discovered hosts |
| `script_scan` | `"True"` / `"False"` | Runs NSE security scripts (implies `banner_scan`) |
| `target_scan` | `"External"` / `"Internal"` | External → source port 53; Internal → source port 88 |
| `max_rate` | Packets/second string | See rate guidance below |
| `target_file` | Path | One IP, CIDR, or hostname per line |
| `output_path` | Path | Directory for all output; relative paths resolve to script dir |
| `exclusions_file` | Path | IPs/CIDRs passed to masscan `--excludefile` |
| `nmap_threads` | Integer | Concurrent nmap processes (default: 5) |
| `masscan_batch_size` | Integer | Ports per masscan invocation (default: 5) |

### max_rate guidance
Rates that are too high can create a denial-of-service condition — use caution.

| Scan | Recommended rate |
|------|-----------------|
| External + category/custom scan | 10,000 pps |
| External + full port scan | 10,000 pps |
| Internal + category/custom scan | 1,000 pps |
| Internal + full port scan | 1,000 pps |

## Output Structure

```
<output_path>/
  masscan_targets.txt         # IPs-only target list for masscan
  ip_hostname_map.json        # hostname → resolved IP mapping
  masscan_results/portN.xml   # raw masscan XML per port
  live_hosts/portN.txt        # deduplicated IPs per port
  nmap_results/portN.xml      # nmap banner/script XML per port
  all_live_hosts.txt          # union of all live IPs
  spoonmap_output.xml         # merged nmap XML (or masscan if no banner scan)
  spoonmap_output.json        # same data as JSON — list of host objects by IP
  findings.txt                # severity-sorted findings report (script_scan only)
  findings.md                 # same report in Markdown table format
  findings.json               # same report as a JSON array (script_scan only)
```

`spoonmap_output.json` consolidates hosts across all per-port files, merging ports for the same IP:

```json
[
  {
    "ip": "10.0.0.1",
    "hostname": "host.example.com",
    "ports": [
      {"protocol": "tcp", "portid": "445", "state": "open",
       "service": "microsoft-ds", "product": "", "version": "", "scripts": {}}
    ],
    "hostscripts": {"smb2-security-mode": "Message signing enabled but not required"}
  }
]
```

`findings.json` is a flat array with one object per finding:

```json
[
  {"severity": "HIGH", "host": "10.0.0.1", "port": "tcp/22",
   "title": "Weak SSH Auth", "detail": "..."}
]
```

## NSE Script Scanning and Findings

When `script_scan` is enabled, nmap runs targeted NSE scripts against relevant ports. Scripts are chosen based on scan type (External vs Internal):

**External scans** run: `ftp-anon`, `ssh-auth-methods`, `ssh2-enum-algos`, `*-ntlm-info`, `ssl-cert`, `ms-sql-ntlm-info`, `rdp-ntlm-info`, `docker-version`, `snmp-brute`

**Internal scans** run: `ftp-anon`, `rpcinfo`, `nfs-showmount`, `nfs-ls`, `smb-security-mode`, `smb2-security-mode`, `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-double-pulsar-backdoor`, `smb-vuln-cve-2017-7494`, `rmi-dumpregistry`, `ms-sql-info`, `rdp-enum-encryption`, `rdp-vuln-ms12-020`, `docker-version`, `snmp-brute`

Port 9100 (JetDirect raw printing protocol) is included in the Specialized category. Hosts with port 9100 open are identified as printers; SNMP default community string and anonymous FTP findings are suppressed for these hosts to reduce noise.

After scanning, `generate_findings()` parses all nmap XML results and produces severity-sorted `findings.txt`, `findings.md`, and `findings.json` reports. Findings include:

| Severity | Finding |
|----------|---------|
| CRITICAL | MS17-010 EternalBlue (CVE-2017-0143) |
| CRITICAL | MS08-067 NetAPI / Conficker (CVE-2008-4250) |
| CRITICAL | DoublePulsar backdoor active |
| CRITICAL | SambaCry (CVE-2017-7494) |
| CRITICAL | MS12-020 RDP RCE/DoS (CVE-2012-0002) |
| CRITICAL | Unauthenticated Docker API (2375/4243) |
| CRITICAL | Service Exposed Externally (Docker ports) |
| HIGH | Anonymous FTP login |
| HIGH | Weak SSH authentication (password/keyboard-interactive externally) |
| HIGH | NTLM information disclosure (external) |
| HIGH | SMB/SMBv2 signing not required |
| HIGH | NFS shares exposed |
| HIGH | Dameware Remote Control detected |
| HIGH | SAP Gateway detected (3300) |
| HIGH | Cisco Smart Install detected (4786) |
| HIGH | Cisco CUCM TFTP detected (6970) |
| HIGH | SNMP default community string accepted (non-printer hosts only) |
| HIGH | Service Exposed Externally (databases, RDP, SMB, SNMP, WebLogic, etc.) |
| MEDIUM | SMBv1 protocol enabled |
| MEDIUM | Weak SSH algorithms (deprecated ciphers/MACs/KEX) |
| MEDIUM | Weak RDP encryption / NLA not enforced |
| MEDIUM | Java RMI registry exposed |
| MEDIUM | Expired TLS certificate |
| INFO | SQL Server instance discovered |

On Internal scans, if `ms-sql-info` discovers SQL Server named instances on non-standard ports, nmap is automatically re-run against those ports.

## Potential Hacks to Look For

1090
Java RMI (auto-detected by script_scan on port 1090)
https://www.rapid7.com/db/modules/exploit/multi/misc/java_rmi_server
https://medium.com/@afinepl/java-rmi-for-pentesters-structure-recon-and-communication-non-jmx-registries-a10d5c996a79

4786
Cisco Smart Install (auto-detected by script_scan)
https://www.rapid7.com/db/modules/auxiliary/scanner/misc/cisco_smart_install
https://github.com/Sab0tag3d/SIET

3300
SAP Gateway (auto-detected by script_scan)
https://github.com/chipik/SAP_GW_RCE_exploit

6129
Dameware (auto-detected by script_scan)
https://www.tenable.com/security/research/tra-2019-43
https://github.com/tenable/poc/blob/master/Solarwinds/Dameware/dwrcs_dwDrvInst_rce.py

6379
Redis
https://www.rapid7.com/db/modules/exploit/linux/redis/redis_replication_cmd_exec

6970
Cisco Unified Communications Manager TFTP (auto-detected by script_scan)
https://github.com/trustedsec/SeeYouCM-Thief
http://[CUCM IP Address]:6970/ConfigFileCacheList.txt

2375, 4243
Docker API (unauthenticated access auto-detected by script_scan)
https://www.rapid7.com/db/modules/exploit/linux/http/docker_daemon_tcp

7001, 7002
Oracle WebLogic Server
https://www.rapid7.com/db/modules/exploit/multi/http/oracle_weblogic_wsat_deserialization_rce
https://www.rapid7.com/db/modules/exploit/multi/http/oracle_weblogic_deserialize_asyncresponseservice

8080
Adobe ColdFusion BlazeDS
https://www.tenable.com/plugins/nessus/99731
