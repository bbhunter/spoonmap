local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Attempts an anonymous LDAP bind and, if successful, searches for AD user and
computer objects to quantify the information disclosure risk.

A finding is only reported when the anonymous bind succeeds AND at least one
user or computer object is returned.  Domains that permit the bind but block
enumeration (dsHeuristics bit 7) will not generate a finding.
]]
---
-- @usage nmap -p 389 --script ldap-anon-enum <host>
-- @output
-- 389/tcp open  ldap
-- | ldap-anon-enum:
-- |   Base DN: DC=pwnt,DC=lab
-- |   Sample Users Found: j.smith, m.carter, r.johnson, t.williams, k.brown
-- |_  Sample Computers Found: WS-SALES01$, WS-DEV03$, SRV-FILE02$

author  = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

portrule = shortport.port_or_service(389, {"ldap"}, "tcp",
                                     {"open", "open|filtered"})

-- ── ASN.1 BER helpers ────────────────────────────────────────────────────────

local function ber_len(n)
  if n < 0x80 then
    return string.char(n)
  elseif n < 0x100 then
    return "\x81" .. string.char(n)
  else
    return "\x82" .. string.char(math.floor(n / 256)) .. string.char(n % 256)
  end
end

local function tlv(tag, value)
  return string.char(tag) .. ber_len(#value) .. value
end

-- ── LDAP message builders ────────────────────────────────────────────────────

local function ldap_simple_bind(msg_id)
  return tlv(0x30,
    tlv(0x02, string.char(msg_id)) ..
    tlv(0x60,                           -- APPLICATION [0] BindRequest
      tlv(0x02, "\x03") ..              -- INTEGER 3 (LDAPv3)
      tlv(0x04, "") ..                  -- LDAPDN "" (empty name)
      tlv(0x80, "")))                   -- [0] PRIMITIVE "" (simple empty password)
end

local function ldap_search(msg_id, base_dn, scope, filter_bytes, size_limit, attrs_bytes)
  attrs_bytes = attrs_bytes or ""
  return tlv(0x30,
    tlv(0x02, string.char(msg_id)) ..
    tlv(0x63,                           -- APPLICATION [3] SearchRequest
      tlv(0x04, base_dn) ..             -- baseObject
      tlv(0x0a, string.char(scope)) ..  -- scope ENUMERATED
      tlv(0x0a, "\x00") ..              -- derefAliases = neverDerefAliases
      tlv(0x02, string.char(size_limit)) .. -- sizeLimit
      tlv(0x02, "\x0a") ..              -- timeLimit = 10s
      tlv(0x01, "\x00") ..              -- typesOnly = FALSE
      filter_bytes ..                    -- Filter
      tlv(0x30, attrs_bytes)))          -- attributes (empty = return all)
end

-- ── Helpers ──────────────────────────────────────────────────────────────────

local function parse_result_code(data)
  for i = 1, #data - 2 do
    if data:byte(i) == 0x0a and data:byte(i + 1) == 0x01 then
      return data:byte(i + 2)
    end
  end
  return nil
end

-- Extract defaultNamingContext value from a rootDSE SearchResultEntry response.
-- Finds the attribute name string then reads the following OCTET STRING value.
local function extract_base_dn(data)
  local _, ep = data:find("defaultNamingContext", 1, true)
  if not ep then return nil end
  -- Attribute values appear as SET OF OCTET STRING after the attribute name.
  -- Scan forward for 0x04 (OCTET STRING) within 50 bytes.
  for i = ep + 1, math.min(ep + 50, #data - 2) do
    if data:byte(i) == 0x04 then
      local vlen = data:byte(i + 1)
      if vlen > 0 and vlen < 200 and i + 1 + vlen <= #data then
        return data:sub(i + 2, i + 1 + vlen)
      end
    end
  end
  return nil
end

-- Count APPLICATION[4] (0x64 = SearchResultEntry) tags in data.
-- Stop and return count when APPLICATION[5] (0x65 = SearchResultDone) is seen.
local function count_entries_in_chunk(data)
  local count = 0
  local done  = false
  for i = 1, #data do
    local b = data:byte(i)
    if b == 0x65 then done = true; break end
    if b == 0x64 then count = count + 1 end
  end
  return count, done
end

-- Drain search results, counting entries and extracting string attribute values.
-- After the literal attribute name in raw bytes, expect: 31 <setlen> 04 <vallen> <value>
local function collect_names(socket)
  local total = 0
  local names = {}
  for _ = 1, 30 do
    local ok, data = socket:receive()
    if not ok then break end
    local n, done = count_entries_in_chunk(data)
    total = total + n
    local pos = 1
    while true do
      local _, ep = data:find("sAMAccountName", pos, true)
      if not ep then break end
      for i = ep + 1, math.min(ep + 6, #data - 2) do
        if data:byte(i) == 0x31 then
          -- Decode BER length of the SET (may be long-form: 0x81/0x82/0x83/0x84 + N bytes)
          local lb = data:byte(i + 1)
          local extra = lb >= 0x80 and (lb - 0x80) or 0
          local inner = i + 2 + extra   -- skip tag, length field
          if inner <= #data and data:byte(inner) == 0x04 then
            local vlen = data:byte(inner + 1)
            if vlen > 0 and vlen < 64 and inner + 1 + vlen <= #data then
              names[#names + 1] = data:sub(inner + 2, inner + 1 + vlen)
            end
          end
          break
        end
      end
      pos = ep + 1
    end
    if done then break end
  end
  return #names, names
end

-- ── Action ───────────────────────────────────────────────────────────────────

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(8000)

  local ok, err = socket:connect(host, port, "tcp")
  if not ok then stdnse.debug1("Connect failed: %s", err); socket:close(); return nil end

  -- 1. Anonymous simple bind
  ok, err = socket:send(ldap_simple_bind(1))
  if not ok then socket:close(); return nil end

  local resp
  ok, resp = socket:receive()
  if not ok or parse_result_code(resp) ~= 0 then
    stdnse.debug1("Anonymous bind failed")
    socket:close()
    return nil
  end

  -- 2. Search rootDSE for defaultNamingContext (scope=baseObject, filter=objectClass=*)
  local filter_present = tlv(0x87, "objectClass")   -- [7] PRIMITIVE present filter
  ok, err = socket:send(ldap_search(2, "", 0, filter_present, 1))
  if not ok then socket:close(); return nil end

  ok, resp = socket:receive()
  if not ok then socket:close(); return nil end

  local base_dn = extract_base_dn(resp)
  if not base_dn or #base_dn == 0 then
    stdnse.debug1("Could not extract defaultNamingContext")
    socket:close()
    return nil
  end

  -- 3. Search for user objects; request only sAMAccountName (sizeLimit=5, wholeSubtree)
  local filter_user = tlv(0xa3,           -- [3] equalityMatch
    tlv(0x04, "objectClass") ..
    tlv(0x04, "user"))
  local sam_attr = tlv(0x04, "sAMAccountName")
  ok, err = socket:send(ldap_search(3, base_dn, 2, filter_user, 5, sam_attr))
  if not ok then socket:close(); return nil end
  local user_count, user_names = collect_names(socket)

  -- 4. Search for computer objects; request sAMAccountName (ends with $)
  local filter_comp = tlv(0xa3,
    tlv(0x04, "objectClass") ..
    tlv(0x04, "computer"))
  ok, err = socket:send(ldap_search(4, base_dn, 2, filter_comp, 5, sam_attr))
  if not ok then socket:close(); return nil end
  local computer_count, computer_names = collect_names(socket)

  socket:close()

  if user_count == 0 and computer_count == 0 then
    return nil
  end

  local lines = { "Anonymous bind: success", "Base DN: " .. base_dn }
  if user_count > 0 then
    lines[#lines + 1] = "Sample Users Found: " .. table.concat(user_names, ", ")
  end
  if computer_count > 0 then
    lines[#lines + 1] = "Sample Computers Found: " .. table.concat(computer_names, ", ")
  end
  return table.concat(lines, "\n")
end
