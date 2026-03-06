local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Checks whether LDAP message signing (LDAPServerIntegrity) is enforced on a
Windows domain controller via an unauthenticated GSS-SPNEGO/NTLM SASL bind.

A SPNEGO NegTokenInit wrapping an NTLM Type 1 (NEGOTIATE) with no signing
flags is sent; after receiving the Type 2 challenge wrapped in a NegTokenResp,
a SPNEGO NegTokenResp wrapping a null NTLM Type 3 (AUTHENTICATE) follows.
resultCode 49 (invalidCredentials) means the DC accepted the unsigned negotiate
-- signing is not required.  resultCode 8 (strongAuthRequired) means enforced.

References:
* https://msrc.microsoft.com/update-guide/vulnerability/ADV190023
* https://support.microsoft.com/kb/4520412
]]
---
-- @usage nmap -p 389 --script ldap-signing-check <host>
-- @output
-- 389/tcp open  ldap
-- |_ldap-signing-check: Signing: NOT REQUIRED

author  = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

portrule = shortport.port_or_service({389, 3268}, {"ldap"}, "tcp",
                                     {"open", "open|filtered"})

-- NTLM Type 1 NEGOTIATE_MESSAGE (32 bytes)
local NTLM_NEGOTIATE =
  "\x4e\x54\x4c\x4d\x53\x53\x50\x00"  -- "NTLMSSP\0"
  .. "\x01\x00\x00\x00"                 -- MessageType = 1
  .. "\x07\x82\x08\xa2"                 -- NegotiateFlags (no signing bit)
  .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- DomainNameFields (empty)
  .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- WorkstationFields (empty)

-- NTLM Type 3 AUTHENTICATE_MESSAGE (64 bytes, all fields null)
local NTLM_AUTH_NULL =
  "\x4e\x54\x4c\x4d\x53\x53\x50\x00"  -- "NTLMSSP\0"
  .. "\x03\x00\x00\x00"                 -- MessageType = 3
  .. "\x00\x00\x00\x00\x40\x00\x00\x00" -- LmChallengeResponse  (len=0, off=64)
  .. "\x00\x00\x00\x00\x40\x00\x00\x00" -- NtChallengeResponse  (len=0, off=64)
  .. "\x00\x00\x00\x00\x40\x00\x00\x00" -- DomainName           (len=0, off=64)
  .. "\x00\x00\x00\x00\x40\x00\x00\x00" -- UserName             (len=0, off=64)
  .. "\x00\x00\x00\x00\x40\x00\x00\x00" -- Workstation          (len=0, off=64)
  .. "\x00\x00\x00\x00\x40\x00\x00\x00" -- EncryptedRandomSessionKey (len=0, off=64)
  .. "\x00\x00\x00\x00"                  -- NegotiateFlags

-- SPNEGO OID 1.3.6.1.5.5.2 and NTLM OID 1.3.6.1.4.1.311.2.2.10 (DER TLV form)
local SPNEGO_OID = "\x06\x06\x2b\x06\x01\x05\x05\x02"
local NTLM_OID   = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"

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

-- Build SPNEGO InitialContextToken wrapping an NTLM Type 1 token.
-- Structure: APPLICATION[0] { SPNEGO_OID, [0] { SEQUENCE { [0]{NTLM_OID}, [2]{token} } } }
local function spnego_init(ntlm_token)
  local mech_types = tlv(0xa0, tlv(0x30, NTLM_OID))
  local mech_token = tlv(0xa2, tlv(0x04, ntlm_token))
  return tlv(0x60, SPNEGO_OID .. tlv(0xa0, tlv(0x30, mech_types .. mech_token)))
end

-- Build SPNEGO NegTokenResp wrapping an NTLM Type 3 token.
-- Structure: [1] { SEQUENCE { [2] { token } } }
local function spnego_resp(ntlm_token)
  return tlv(0xa1, tlv(0x30, tlv(0xa2, tlv(0x04, ntlm_token))))
end

local function ldap_sasl_bind(msg_id, token)
  local sasl = tlv(0xa3,              -- [3] CONSTRUCTED (SaslCredentials)
    tlv(0x04, "GSS-SPNEGO") ..        -- LDAPString mechanism
    tlv(0x04, token))                 -- OCTET STRING credentials
  local bind_req = tlv(0x60,          -- APPLICATION [0] BindRequest
    tlv(0x02, "\x03") ..              -- INTEGER 3 (LDAPv3)
    tlv(0x04, "") ..                  -- LDAPDN "" (anonymous name)
    sasl)
  return tlv(0x30,                    -- LDAPMessage SEQUENCE
    tlv(0x02, string.char(msg_id)) ..
    bind_req)
end

local function parse_result_code(data)
  -- Find ENUMERATED 0x0a 0x01 <code> anywhere in the response
  for i = 1, #data - 2 do
    if data:byte(i) == 0x0a and data:byte(i + 1) == 0x01 then
      return data:byte(i + 2)
    end
  end
  return nil
end

action = function(host, port)
  local RC_INVALID_CREDENTIALS = 49
  local socket = nmap.new_socket()
  socket:set_timeout(8000)

  local ok, err = socket:connect(host, port, "tcp")
  if not ok then stdnse.debug1("Connect failed: %s", err); return nil end

  ok, err = socket:send(ldap_sasl_bind(1, spnego_init(NTLM_NEGOTIATE)))
  if not ok then socket:close(); return nil end

  local resp
  ok, resp = socket:receive_bytes(4096)
  if not ok then socket:close(); return nil end

  ok, err = socket:send(ldap_sasl_bind(2, spnego_resp(NTLM_AUTH_NULL)))
  if not ok then socket:close(); return nil end

  ok, resp = socket:receive_bytes(4096)
  socket:close()
  if not ok then return nil end

  local code = parse_result_code(resp)
  stdnse.debug1("Result code: %s", tostring(code))
  if code == RC_INVALID_CREDENTIALS then
    return "Signing: NOT REQUIRED"
  end
  return nil
end
