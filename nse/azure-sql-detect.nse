local nmap     = require "nmap"
local sslcert  = require "sslcert"
local stdnse   = require "stdnse"
local string   = require "string"
local table    = require "table"

-- vim: set filetype=lua :

description = [[
Sends a raw TDS PRELOGIN packet to a Microsoft SQL Server instance and
inspects the response for signals distinguishing Azure SQL Database /
Managed Instance (behind the Azure SQL Gateway) from an on-premises SQL
Server.

Azure SQL Database freezes its reported TDS/SSNetLib protocol version at
12.0.x -- the same number SQL Server 2014 reports, which is long past
Microsoft's on-premises support lifecycle. But Azure SQL Database is itself a
managed, evergreen, continuously-patched service, so treating that frozen
12.0 as an end-of-life on-prem installation is a false positive.

nmap's own mssql.lua library cannot help here: it does not recognize the
FEDAUTHREQUIRED (0x06) PRELOGIN option at all (silently discarded as an
"unrecognized option"), and it flattens the server's ENCRYPTION response byte
to a plain 0/1, collapsing ENCRYPT_REQ (forced encryption -- what Azure
requires) into the same bucket as ENCRYPT_ON. Both signals require a
hand-built PRELOGIN exchange, which is what this script performs.

Detection signals reported (most reliable to least):
* The server's own TLS certificate SAN. Per MS-TDS, the TLS handshake that
  follows a negotiated-encryption PRELOGIN is itself carried wrapped inside
  TDS packet frames, so a normal TLS probe cannot reach it directly -- this
  script uses nmap's own sslcert.getCertificate(), which already knows how to
  drive that TDS-tunneled handshake far enough to read the Certificate
  message (no key exchange, no authentication). A SAN ending in
  *.database.windows.net (or another Azure SQL FQDN suffix) is presented by
  the server itself, so it is definitive regardless of how the target was
  reached -- unlike a hostname, it survives private endpoints, ExpressRoute/
  VPN access, and custom internal DNS, all of which hide the public FQDN from
  a bare-IP or internally-named target.
* FEDAUTHREQUIRED echoed back as 1 -- the client advertises federated-auth
  support in its request; Azure SQL Database/Managed Instance confirms it
  because federated/Entra auth is genuinely available for the connection. A
  correctly-configured on-prem server may echo the option back as 0 (not
  required) or omit it entirely, so this signal alone is corroborating, not
  conclusive -- treat it as the best available call only when neither the
  target hostname nor the certificate SAN confirms Azure.
* ENCRYPT_REQ (0x03) -- Azure forces TLS; on-prem is usually negotiable.
* The frozen 12.0.x version number itself.

A target hostname ending in *.database.windows.net (or another Azure SQL FQDN
suffix) also confirms Azure -- but a non-matching or missing hostname does NOT
rule Azure out, for the same private-endpoint/internal-DNS reasons above. The
certificate SAN check exists specifically to still catch those cases.

This script performs identification only. It does not complete the
subsequent TLS/login handshake, does not perform key exchange, and does not
authenticate.
]]
---
-- @usage
-- nmap -p 1433 --script azure-sql-detect <host>
-- nmap -p 3342 --script azure-sql-detect <host>   -- Azure SQL Managed Instance public endpoint
-- nmap -p 51234 --script azure-sql-detect <host>  -- named instance on a non-standard port
--
-- @output
-- 1433/tcp open  ms-sql-s
-- | azure-sql-detect: Azure SQL Database / Managed Instance detected (certificate SAN confirms Azure)
-- |   Certificate SAN : myserver.database.windows.net
-- |   Reported version: 12.0.2000.8 (frozen at "SQL Server 2014" -- expected for Azure, NOT end-of-life)
-- |   Raw signals:
-- |     FEDAUTHREQUIRED=1
-- |     ENCRYPT=REQUIRED
-- |_    CERT_SAN=myserver.database.windows.net

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

-- Matches the default instance port (1433), the Azure SQL Managed Instance
-- public/proxy endpoint (3342), and any other port explicitly targeted (e.g.
-- SpooNMAP's own follow-up scan against a named instance discovered by
-- ms-sql-info on a dynamically-assigned non-standard port). PRELOGIN is a
-- lightweight, safe probe, so we don't need to gate on a known port list for
-- correctness -- the action() function itself returns nil for anything that
-- doesn't look like a real PRELOGIN response.
portrule = function(host, port)
  return port.protocol == "tcp"
     and (port.state == "open" or port.state == "open|filtered")
end

local TIMEOUT_MS = 5000
local MAX_RESPONSE_BYTES = 4096

-- PRELOGIN option type tokens (MS-TDS 2.2.6.4). FEDAUTHREQUIRED (0x06) is the
-- one nmap's bundled mssql.lua does not recognize -- see description above.
local OPT = {
  VERSION         = 0x00,
  ENCRYPTION      = 0x01,
  INSTOPT         = 0x02,
  THREADID        = 0x03,
  FEDAUTHREQUIRED = 0x06,
  TERMINATOR      = 0xFF,
}

local ENCRYPT_LABEL = {
  [0x00] = "OFF",
  [0x01] = "ON",
  [0x02] = "NOT_SUPPORTED",
  [0x03] = "REQUIRED",
}

-- Build a raw TDS PRELOGIN request advertising FEDAUTHREQUIRED support.
--
-- Wire format (MS-TDS 2.2.6.4): an 8-byte TDS packet header, followed by a
-- list of 5-byte option tokens (type, big-endian offset, big-endian length)
-- terminated by a single 0xFF byte, followed by the concatenated option data
-- blocks in token order. Each PL_OFFSET is measured from the start of the
-- PRELOGIN payload (i.e. from the first token), so it equals the length of
-- the token list plus the length of every preceding data block.
local function build_prelogin_request()
  local version_data  = string.pack(">BBBBI2", 0, 0, 0, 0, 0)  -- major,minor,buildHi,buildLo,subbuild
  local encrypt_data  = string.pack("B", 0x00)                  -- ENCRYPT_OFF: we never complete the TLS handshake
  local instopt_data  = string.pack("B", 0x00)                  -- no named instance requested
  local threadid_data = string.pack(">I4", 0)
  local fedauth_data  = string.pack("B", 0x01)                  -- advertise federated-auth support

  local options = {
    {type = OPT.VERSION,         data = version_data},
    {type = OPT.ENCRYPTION,      data = encrypt_data},
    {type = OPT.INSTOPT,         data = instopt_data},
    {type = OPT.THREADID,        data = threadid_data},
    {type = OPT.FEDAUTHREQUIRED, data = fedauth_data},
  }

  local token_list_len = #options * 5 + 1  -- 5 bytes/token + 1-byte terminator
  local tokens, blobs = {}, {}
  local offset = token_list_len
  for _, opt in ipairs(options) do
    tokens[#tokens + 1] = string.pack(">BI2I2", opt.type, offset, #opt.data)
    blobs[#blobs + 1] = opt.data
    offset = offset + #opt.data
  end
  tokens[#tokens + 1] = string.pack("B", OPT.TERMINATOR)

  local payload = table.concat(tokens) .. table.concat(blobs)
  local packet_len = 8 + #payload
  -- Type=0x12 (PRE_LOGIN), Status=0x01 (EOM), Length, SPID=0, PacketID=1, Window=0
  local header = string.pack(">BBI2I2BB", 0x12, 0x01, packet_len, 0x0000, 0x01, 0x00)
  return header .. payload
end

-- Parse a PRELOGIN response payload (everything after the 8-byte TDS
-- header). Returns {version = "12.0.2000.8" or nil, encryption = byte or
-- nil, fedauthrequired = byte or nil}.
local function parse_prelogin_response(payload)
  local result = {}
  local tokens = {}
  local pos = 1
  while pos + 4 <= #payload do
    local opt_type, offset, length, next_pos = string.unpack(">BI2I2", payload, pos)
    if opt_type == OPT.TERMINATOR then break end
    tokens[#tokens + 1] = {type = opt_type, offset = offset, length = length}
    pos = next_pos
  end

  for _, tok in ipairs(tokens) do
    local start = tok.offset + 1  -- Lua strings are 1-indexed
    if start >= 1 and start + tok.length - 1 <= #payload then
      local data = payload:sub(start, start + tok.length - 1)
      if tok.type == OPT.VERSION and tok.length >= 6 then
        local major, minor, buildHi, buildLo, subbuild = string.unpack(">BBBBI2", data)
        result.version = string.format("%d.%d.%d.%d", major, minor,
                                        (buildHi * 256) + buildLo, subbuild)
      elseif tok.type == OPT.ENCRYPTION and tok.length >= 1 then
        result.encryption = string.unpack("B", data)
      elseif tok.type == OPT.FEDAUTHREQUIRED and tok.length >= 1 then
        result.fedauthrequired = string.unpack("B", data)
      end
    end
  end
  return result
end

-- Azure SQL FQDN suffixes -- keep in sync with AZURE_SQL_DOMAIN_SUFFIXES in
-- spoonmap.py. Duplicated here only to build the human-readable one-line
-- verdict for operators reading raw nmap output; spoonmap.py's
-- _classify_sql() re-derives the actual finding classification independently
-- from the CERT_SAN= token, so this copy is advisory, not load-bearing.
local CERT_SAN_AZURE_SUFFIXES = {
  "%.database%.windows%.net$",
  "%.database%.chinacloudapi%.cn$",
  "%.database%.usgovcloudapi%.net$",
}

local function cert_san_looks_azure(name)
  local lname = name:lower()
  for _, pattern in ipairs(CERT_SAN_AZURE_SUFFIXES) do
    if lname:match(pattern) then return true end
  end
  return false
end

-- Retrieve the server's TLS certificate over the TDS-tunneled handshake and
-- return (san_list, san_str, azure_match):
--   san_list    - array of DNS SAN entries (possibly empty)
--   san_str     - "unavailable" (couldn't get/parse a cert), "none" (got a
--                 cert, no SAN DNS entries), or a comma-joined SAN list
--   azure_match - true if any SAN entry matches an Azure SQL FQDN suffix
local function get_cert_san(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if not status or not cert then
    stdnse.debug1("Could not retrieve certificate: %s", cert or "unknown error")
    return {}, "unavailable", false
  end

  local san_list = {}
  if cert.extensions then
    for _, ext in ipairs(cert.extensions) do
      if ext.name == "X509v3 Subject Alternative Name" and ext.value then
        for dns_name in ext.value:gmatch("DNS:%s*([^,]+)") do
          san_list[#san_list + 1] = dns_name
        end
      end
    end
  end

  if #san_list == 0 then
    return san_list, "none", false
  end

  local azure_match = false
  for _, name in ipairs(san_list) do
    if cert_san_looks_azure(name) then
      azure_match = true
      break
    end
  end
  return san_list, table.concat(san_list, ","), azure_match
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(TIMEOUT_MS)
  local ok, err = socket:connect(host, port, "tcp")
  if not ok then
    stdnse.debug1("connect failed: %s", err)
    socket:close()
    return nil
  end

  local sent, sendErr = socket:send(build_prelogin_request())
  if not sent then
    stdnse.debug1("send failed: %s", sendErr)
    socket:close()
    return nil
  end

  -- Accumulate until we have the full declared packet length, the socket
  -- closes, or we hit the size safety cap.
  local chunks = {}
  local total = 0
  while total < MAX_RESPONSE_BYTES do
    local recvOk, chunk = socket:receive()
    if not recvOk then break end
    chunks[#chunks + 1] = chunk
    total = total + #chunk
    if total >= 8 then
      local declaredLen = string.unpack(">I2", table.concat(chunks), 3)
      if total >= declaredLen then break end
    end
  end
  socket:close()

  local raw = table.concat(chunks)
  if #raw < 8 then return nil end

  local payload = raw:sub(9)
  local info = parse_prelogin_response(payload)
  if not info.version and info.encryption == nil and info.fedauthrequired == nil then
    return nil  -- doesn't look like a PRELOGIN response; not SQL Server
  end

  port.version.name    = "ms-sql-s"
  port.version.product = "Microsoft SQL Server (PRELOGIN)"
  nmap.set_port_version(host, port)

  -- sslcert.getCertificate() only knows to drive the TDS-tunneled TLS
  -- handshake (via its internal tds_prepare_tls_without_reconnect wrapper)
  -- when port.service == "ms-sql-s". That name comes from nmap-services,
  -- which maps ONLY 1433 to it -- port 3342 (Azure SQL Managed Instance's
  -- public endpoint) defaults to "webtie", and a dynamically-assigned named
  -- instance port defaults to "unknown". On either, sslcert would silently
  -- fall through to a raw-TLS attempt that can't work over TDS framing and
  -- CERT_SAN would read "unavailable" even though a cert-fetch was possible.
  -- We've already confirmed this is a real PRELOGIN responder above, so it's
  -- safe to force the service name before the cert-fetch call below.
  port.service = "ms-sql-s"

  local fed_str    = (info.fedauthrequired ~= nil) and tostring(info.fedauthrequired) or "not offered"
  local enc_label  = ENCRYPT_LABEL[info.encryption] or "unknown"
  local ver_str    = info.version or "unknown"

  -- The certificate is presented by the server itself, so a matching SAN is
  -- definitive regardless of hostname/DNS -- this is what still works on a
  -- bare-IP internal target or one reached via a private endpoint/custom DNS.
  local _san_list, cert_san_str, cert_confirms_azure = get_cert_san(host, port)
  local fedauth_like = (info.fedauthrequired == 1)

  -- Each raw signal token keeps its exact original KEY=value form
  -- (FEDAUTHREQUIRED=/ENCRYPT=/CERT_SAN=) unchanged, just one per line, so
  -- spoonmap.py's regex-based parsing (_classify_sql, _cert_san_azure_match)
  -- and any other consumer never needs updating when this layout changes --
  -- only the headline/detail lines above it are for human/screenshot
  -- readability. The version isn't repeated here since "Reported version"
  -- above already carries it, and _sql_version_year() matches on either line.
  local raw_signal_lines = {
    "    FEDAUTHREQUIRED=" .. fed_str,
    "    ENCRYPT=" .. enc_label,
    "    CERT_SAN=" .. cert_san_str,
  }

  local headline, detail_lines
  if cert_confirms_azure then
    headline = "Azure SQL Database / Managed Instance detected (certificate SAN confirms Azure)"
    detail_lines = {
      "  Certificate SAN : " .. cert_san_str,
      "  Reported version: " .. ver_str .. ' (frozen at "SQL Server 2014" -- expected for Azure, NOT end-of-life)',
    }
  elseif fedauth_like then
    headline = "Possible Azure SQL Database (FEDAUTHREQUIRED confirms federated-auth support; not conclusive alone)"
    detail_lines = {
      "  Reported version: " .. ver_str .. ' (if this is Azure, the frozen "SQL Server 2014" version is expected and NOT end-of-life)',
      "  Note            : pair with the target hostname (*.database.windows.net) or certificate SAN for a definitive call",
    }
  else
    headline = "No Azure SQL Gateway signals detected"
    detail_lines = { "  Reported version: " .. ver_str }
  end

  local lines = { headline }
  for _, l in ipairs(detail_lines) do lines[#lines + 1] = l end
  lines[#lines + 1] = "  Raw signals:"
  for _, l in ipairs(raw_signal_lines) do lines[#lines + 1] = l end

  return table.concat(lines, "\n")
end
