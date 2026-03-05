local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Checks whether the Kubernetes Kubelet API on TCP port 10250 allows anonymous
(unauthenticated) access.

Connects with TLS and issues a GET /pods request.  An HTTP 200 response without
supplying credentials confirms anonymous access is enabled.  An attacker with
network access can list pods, exec into containers, and read Kubernetes secrets.

References:
* CVE-2018-1002105 (CVSS 9.8) — privilege escalation via Kubelet API
* https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/
]]
---
-- @usage
-- nmap -p 10250 --script kubelet-anon-check <host>
--
-- @output
-- 10250/tcp open  ssl/kubernetes-kubelet
-- | kubelet-anon-check:
-- |_  Anonymous access enabled — /pods returned HTTP 200 without credentials

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

portrule = shortport.port_or_service(10250, {"ssl/kubernetes-kubelet", "unknown"}, "tcp",
                                     {"open", "open|filtered"})

action = function(host, port)
  local TIMEOUT_MS = 5000

  local socket = nmap.new_socket()
  socket:set_timeout(TIMEOUT_MS)

  -- Kubelet listens on TLS; connect with ssl wrapper
  local status, err = socket:connect(host, port, "ssl")
  if not status then
    -- TLS failed — discard the socket and retry with plain TCP
    -- (nsock sockets cannot be reconnected after a failed connect)
    socket:close()
    socket = nmap.new_socket()
    socket:set_timeout(TIMEOUT_MS)
    status, err = socket:connect(host, port, "tcp")
    if not status then
      stdnse.debug1("Connect failed: %s", err)
      return nil
    end
  end

  local probe = table.concat({
    "GET /pods HTTP/1.0\r\n",
    "Host: " .. host.ip .. "\r\n",
    "Connection: close\r\n",
    "\r\n",
  })

  status, err = socket:send(probe)
  if not status then
    stdnse.debug1("Send failed: %s", err)
    socket:close()
    return nil
  end

  local response
  status, response = socket:receive_bytes(4096)
  socket:close()

  if not status or not response then
    stdnse.debug1("No response received")
    return nil
  end

  -- Confirm anonymous access: HTTP 200 response
  if not (response:find("^HTTP/1") and response:find("200")) then
    stdnse.debug1("Did not receive HTTP 200 — anonymous access not confirmed")
    return nil
  end

  port.version.name    = "ssl/kubernetes-kubelet"
  port.version.product = "Kubernetes Kubelet"
  nmap.set_port_version(host, port)

  return "Anonymous access enabled — /pods returned HTTP 200 without credentials"
end
