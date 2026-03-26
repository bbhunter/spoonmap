# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

SpooNMAP is a Python 3.6+ wrapper that orchestrates masscan (fast port discovery) followed by nmap (service banner grabbing). Both external tools must be installed separately.

## Running the Tool

```bash
# Interactive mode (prompts for all options)
./spoonmap.py

# Config file mode (skip all prompts)
cp config.json.sample config.json
# Edit config.json, then:
./spoonmap.py
```

Run the test suite with:

```bash
uv run pytest tests/
uv run pytest tests/test_spoonmap.py::TestGenerateFindings  # single class
```

## Architecture

The entire tool is a single script: `spoonmap.py`. Execution flow:

1. `main()` — loads `config.json` if present, otherwise runs interactive prompts to collect: scan type, banner scan flag, internal/external target, max rate, output path, target file, exclusions file
2. `preprocess_targets()` — reads the target file; resolves hostnames via DNS to IPs; writes `discovery/resolved_targets.txt` and `discovery/ip_hostname_map.json`
3. `mass_scan()` — iterates over each port, runs masscan as a subprocess, parses XML output, deduplicates IPs per port using in-memory sets, writes `discovery/live_hosts/port<N>.txt`
4. `nmap_scan()` — if banner scanning is enabled, uses a thread pool (`Queue` + worker threads, default 5 threads) to run nmap concurrently against each `discovery/live_hosts/port<N>.txt`; workers skip ports already present in `nmap_results/`
5. `main()` — aggregates all live hosts into `all_live_hosts.txt` and merges all per-port XML into `spoonmap_output.xml`; if `script_scan` is enabled, calls `generate_findings()` to produce `findings.txt` / `findings.md`

Pass `--cleanup [dir]` to remove prior scan output non-interactively (reads `output_path` from `config.json` if no directory is given).

## Output Structure

```
<output_path>/
  discovery/
    resolved_targets.txt      # resolved IPs/CIDRs (input to host discovery)
    ip_hostname_map.json      # hostname → IP mapping
    live_hosts_discovery.txt  # hosts found during host-discovery phase
    masscan_results/portN.xml # raw masscan XML per port
    live_hosts/portN.txt      # deduplicated IPs per port
  nmap_results/portN.xml      # nmap banner/script XML per port
  all_live_hosts.txt          # union of all live IPs
  spoonmap_output.xml         # merged XML (nmap if banner scan, masscan otherwise)
  findings.txt                # severity-sorted findings report (script_scan only)
  findings.md                 # same report in Markdown table format
```

## config.json Parameters

| Key | Values |
|-----|--------|
| `scan_categories` | `"All"`, `"Full"`, or array of category names (e.g. `["Web","Database"]`); omit to use `dest_ports` |
| `dest_ports` | Array of port strings; prefix `U:` for UDP (e.g. `"U:53"`); overrides `scan_categories` |
| `banner_scan` | `"True"` or `"False"` |
| `script_scan` | `"True"` or `"False"`; runs NSE security scripts (implies `banner_scan`) |
| `target_scan` | `"External"` (source port 53) or `"Internal"` (source port 88) |
| `max_rate` | Packets/second string; recommended: external=10000, internal=1000 |
| `target_file` | Path to file with one IP/CIDR/hostname per line |
| `output_path` | Directory for all output files |
| `exclusions_file` | Path to file with IPs/CIDRs to exclude (passed to masscan `--excludefile`) |
| `nmap_threads` | Integer, concurrent nmap processes (default: 5) |
| `masscan_batch_size` | Integer, ports per masscan invocation (default: 5) |

## Key Implementation Details

- **Shell injection prevention**: all subprocess calls use list form (`subprocess.Popen(cmd_list)`) not shell strings
- **IP deduplication**: uses Python `set()` in memory per port; also reads existing files on resume to avoid duplicates
- **Terminal state**: saves/restores `termios` state around each subprocess call; falls back to `stty sane`
- **Interrupt handling**: masscan raises `KeyboardInterrupt` and re-raises after cleanup; nmap uses `threading.Event` polling so all worker threads can be signaled cleanly
- **Resume behavior**: `nmap_scan()` skips ports where `nmap_results/portN.xml` already exists
- **Hostname support**: hostnames in the target file are resolved once at startup; nmap receives the original hostname (for SNI/vhost), masscan receives the resolved IP
