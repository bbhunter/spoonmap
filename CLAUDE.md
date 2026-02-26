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

There is no build step, test suite, or linter configured.

## Architecture

The entire tool is a single script: `spoonmap.py`. Execution flow:

1. `main()` — loads `config.json` if present, otherwise runs interactive prompts to collect: scan type, banner scan flag, internal/external target, max rate, output path, target file, exclusions file
2. `preprocess_targets()` — reads the target file; resolves hostnames via DNS to IPs (masscan requires IPs); writes `masscan_targets.txt` and `ip_hostname_map.json` to the output directory
3. `mass_scan()` — iterates over each port, runs masscan as a subprocess, parses XML output, deduplicates IPs per port using in-memory sets, writes `live_hosts/port<N>.txt`
4. `nmap_scan()` — if banner scanning is enabled, uses a thread pool (`Queue` + worker threads, default 5 threads) to run nmap concurrently against each `live_hosts/port<N>.txt`; workers skip ports already present in `nmap_results/`
5. `main()` — aggregates all live hosts into `all_live_hosts.txt` and merges all per-port XML into `spoonmap_output.xml`

## Output Structure

```
<output_path>/
  masscan_targets.txt       # IPs-only target list for masscan
  ip_hostname_map.json      # hostname → IP mapping
  masscan_results/portN.xml # raw masscan XML per port
  live_hosts/portN.txt      # deduplicated IPs per port
  nmap_results/portN.xml    # nmap banner scan XML per port
  all_live_hosts.txt        # union of all live IPs
  spoonmap_output.xml       # merged XML (nmap if banner scan, masscan otherwise)
```

## config.json Parameters

| Key | Values |
|-----|--------|
| `scan_type` | `Small Port Scan`, `Medium Port Scan`, `Large Port Scan`, `Extra Large Port Scan`, `Full Port Scan`, `Custom Port Scan` |
| `dest_ports` | Array of port strings; prefix `U:` for UDP (e.g. `"U:53"`); only used for `Custom Port Scan` |
| `banner_scan` | `"True"` or `"False"` |
| `target_scan` | `"External"` (source port 53) or `"Internal"` (source port 88) |
| `max_rate` | Packets/second string; recommended: external=20000, internal=2000, full scan halve these |
| `target_file` | Path to file with one IP/CIDR/hostname per line |
| `output_path` | Directory for all output files |
| `exclusions_file` | Path to file with IPs/CIDRs to exclude (passed to masscan `--excludefile`) |
| `nmap_threads` | Integer, concurrent nmap processes (default: 5) |

## Key Implementation Details

- **Shell injection prevention**: all subprocess calls use list form (`subprocess.Popen(cmd_list)`) not shell strings
- **IP deduplication**: uses Python `set()` in memory per port; also reads existing files on resume to avoid duplicates
- **Terminal state**: saves/restores `termios` state around each subprocess call; falls back to `stty sane`
- **Interrupt handling**: masscan raises `KeyboardInterrupt` and re-raises after cleanup; nmap uses `threading.Event` polling so all worker threads can be signaled cleanly
- **Resume behavior**: `nmap_scan()` skips ports where `nmap_results/portN.xml` already exists
- **Hostname support**: hostnames in the target file are resolved once at startup; nmap receives the original hostname (for SNI/vhost), masscan receives the resolved IP
