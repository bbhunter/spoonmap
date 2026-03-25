local http      = require "http"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects CUPS services potentially vulnerable to the remote code execution chain
disclosed in September 2024 (CVE-2024-47176, CVE-2024-47076, CVE-2024-47175,
CVE-2024-47177).

Attack summary:
  cups-browsed binds to UDP 0.0.0.0:631 and trusts printer-discovery packets
  from any source (CVE-2024-47176). An attacker sends a crafted packet
  containing a URL pointing to a malicious IPP server. cups-browsed fetches
  printer attributes from that server without sanitising the response
  (CVE-2024-47076 / CVE-2024-47175), writing shell commands into a temporary
  PPD file via FoomaticRIPCommandLine (CVE-2024-47177). The injected commands
  execute the next time any print job is submitted to the rogue printer.

Detection approach:
  * TCP 631 -- Issues an HTTP GET to retrieve the CUPS Server: response header
    and extract the daemon version. Versions <= 2.0.1 are in the vulnerable
    range.
  * UDP 631 -- If Nmap reports the port open or open|filtered (no ICMP
    port-unreachable returned), cups-browsed is likely accepting remote
    printer-discovery packets.
  * A host is flagged LIKELY VULNERABLE when EITHER the TCP version check or
    the UDP exposure check indicates a problem.

This script does NOT send malicious payloads and does NOT trigger the exploit.
]]

---
-- @usage
--   # Scan both TCP and UDP 631 for maximum coverage:
--   nmap -sS -sU -p T:631,U:631 --script spoonmap/nse/cups-browsed-rce.nse <target>
--
--   # TCP-only (version check only):
--   nmap -p 631 --script spoonmap/nse/cups-browsed-rce.nse <target>
--
-- @output
-- 631/tcp open  ipp
-- | cups-browsed-rce:
-- |   cups_version: 2.0.1
-- |   udp_631_state: open/filtered (cups-browsed likely listening)
-- |   verdict: LIKELY VULNERABLE
-- |   detail: CUPS 2.0.1 is <= 2.0.1. If cups-browsed is running and UDP 631
-- |           is reachable from untrusted networks this host is susceptible to
-- |           the CVE-2024-47176 RCE chain.
-- |   cves: CVE-2024-47176, CVE-2024-47076, CVE-2024-47175, CVE-2024-47177
-- |_  references: https://www.akamai.com/blog/security-research/guidance-on-critical-cups-rce

author     = "spoonmap"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

-- Match TCP or UDP port 631 (IPP / cups-browsed).
portrule = function(host, port)
  if port.number ~= 631 then return false end
  local s = port.state
  return (s == "open" or s == "open|filtered") and
         (port.protocol == "tcp" or port.protocol == "udp")
end

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Extract the version string from a "CUPS/x.y.z …" token.
local function parse_version(s)
  if not s then return nil end
  return s:match("CUPS/(%d+%.%d+%.?%d*)")
end

-- Return true when ver represents a release <= 2.0.1.
local function is_vulnerable(ver)
  local maj, min, pat = ver:match("^(%d+)%.(%d+)%.?(%d*)")
  maj = tonumber(maj) or 0
  min = tonumber(min) or 0
  pat = (pat ~= "" and tonumber(pat)) or 0
  if maj < 2 then return true end
  if maj == 2 and min == 0 and pat <= 1 then return true end
  return false
end

-- Attempt an HTTP GET on TCP 631 and return the raw Server header value (may
-- be nil if the port is closed or the request fails).
local function tcp_banner(host)
  local tcp_st = nmap.get_port_state(host, {number = 631, protocol = "tcp"})
  if not tcp_st then return nil end
  local s = tcp_st.state
  if s ~= "open" and s ~= "open|filtered" then return nil end
  local ok, resp = pcall(http.get, host, {number = 631, protocol = "tcp"}, "/")
  if not ok or not resp or not resp.header then return nil end
  return resp.header["server"] or ""
end

-- ---------------------------------------------------------------------------
-- Main action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local out = stdnse.output_table()

  -- 1. Determine CUPS version from the Server: response header.
  local version
  if port.protocol == "tcp" then
    local ok, resp = pcall(http.get, host, port, "/")
    if ok and resp and resp.header then
      version = parse_version(resp.header["server"] or "")
    end
  else
    -- Invoked for UDP 631; reach across to TCP 631 for the banner.
    version = parse_version(tcp_banner(host))
  end

  -- 2. Check whether Nmap found UDP 631 open (cups-browsed listening).
  local udp_st   = nmap.get_port_state(host, {number = 631, protocol = "udp"})
  local udp_open = udp_st and
                   (udp_st.state == "open" or udp_st.state == "open|filtered")

  -- Nothing actionable if we have neither a version nor an open UDP port.
  if not version and not udp_open then return nil end

  -- 3. Populate output fields.
  out["cups_version"] = version or "unknown"
  out["udp_631_state"] = udp_open
      and "open/filtered (cups-browsed likely listening)"
       or "closed/filtered or not scanned"

  if version then
    if is_vulnerable(version) then
      out["verdict"] = "LIKELY VULNERABLE"
      out["detail"]  = string.format(
        "CUPS %s is <= 2.0.1. If cups-browsed is running and UDP 631 is "..
        "reachable from untrusted networks this host is susceptible to the "..
        "CVE-2024-47176 RCE chain.", version)
    else
      out["verdict"] = "NOT VULNERABLE (version >= 2.0.2)"
    end
  else
    -- UDP is open but we could not determine the version.
    out["verdict"] = "LIKELY VULNERABLE (version unknown)"
    out["detail"]  = "UDP 631 is open/filtered. If cups-browsed is running it "..
                     "accepts remote printer-discovery packets. Verify the "..
                     "cups-browsed version manually (dpkg -l cups-filters or "..
                     "rpm -q cups-filters)."
  end

  out["cves"] = table.concat({
    "CVE-2024-47176",
    "CVE-2024-47076",
    "CVE-2024-47175",
    "CVE-2024-47177",
  }, ", ")
  out["references"] =
    "https://www.akamai.com/blog/security-research/guidance-on-critical-cups-rce"

  return out
end
