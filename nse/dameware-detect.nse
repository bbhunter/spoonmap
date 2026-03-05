local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects SolarWinds DameWare Mini Remote Control (DWRCS) on TCP port 6129.

Connects to the port and checks for the DameWare protocol handshake signature
(0x30 0x11 0x00 0x00) in the server's initial response. When confirmed, the
service may be vulnerable to unauthenticated remote code execution via smart
card authentication abuse.

References:
* CVE-2019-3980 (CVSS 9.8) - Unauthenticated RCE in DameWare Mini Remote
  Control <= 12.1.0.89 via DWRCS.exe smart card auth abuse.
* https://www.tenable.com/security/research/tra-2019-43
* https://nvd.nist.gov/vuln/detail/CVE-2019-3980
]]
---
-- @usage
-- nmap -p 6129 --script dameware-detect <host>
--
-- @output
-- 6129/tcp open  dameware
-- | dameware-detect:
-- |   Product: SolarWinds DameWare Mini Remote Control
-- |   CVE: CVE-2019-3980 (CVSS 9.8) - Unauthenticated RCE <= v12.1.0.89
-- |_  Remediation: Upgrade to v12.1.2+ or restrict TCP/6129 to authorised hosts

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(6129, {"dameware", "dwrcs"}, "tcp",
                                     {"open", "open|filtered"})

action = function(host, port)
  local TIMEOUT_MS   = 5000
  local DAMEWARE_SIG = "\x30\x11\x00\x00"

  local socket = nmap.new_socket()
  socket:set_timeout(TIMEOUT_MS)

  local status, err = socket:connect(host, port, "tcp")
  if not status then
    stdnse.debug1("Connect failed: %s", err)
    return nil
  end

  -- DameWare sends its banner immediately on connect; no probe required
  socket:send("")
  local response
  status, response = socket:receive_bytes(1024)
  socket:close()

  if not status or not response then
    stdnse.debug1("No response received")
    return nil
  end

  if not string.find(response, DAMEWARE_SIG, 1, true) then
    stdnse.debug1("DameWare signature not found in response")
    return nil
  end

  -- Annotate the port so nmap's version output reflects the service
  port.version.name    = "dameware"
  port.version.product = "SolarWinds DameWare Mini Remote Control"
  nmap.set_port_version(host, port)

  local output = stdnse.output_table()
  output["Product"]     = "SolarWinds DameWare Mini Remote Control"
  output["CVE"]         = "CVE-2019-3980 (CVSS 9.8) - Unauthenticated RCE <= v12.1.0.89"
  output["Remediation"] = "Upgrade to v12.1.2+ or restrict TCP/6129 to authorised hosts"
  return output
end
