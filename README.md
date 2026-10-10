# Linksys E5600 v1.1.0.26 — Vulnerability Disclosure Package

Five security vulnerabilities discovered in Linksys E5600 firmware v1.1.0.26
via firmware rehosting (Greenhouse/QEMU), static reverse engineering (Ghidra),
and dynamic PoC verification in an isolated, authorized research environment.

Each subdirectory is a standalone disclosure document ready to be published
as a public GitHub repository reference for a CVE request (VulDB CNA or
MITRE CNA-LR Vulnogram portal). CVE IDs are placeholders until assigned.

| Dir | Vulnerability | Type | CWE | CVSS 3.1 (proposed) |
|-----|---------------|------|-----|---------------------|
| 01-alcgi-auth-bypass | al.cgi unconditional admin session creation | Auth Bypass | CWE-306 | 8.8 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 02-mesh-login-auth-bypass | mesh_login.cgi empty-credential logic bypass | Auth Bypass | CWE-287 | 8.8 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 03-mesh-login-global-overflow | mesh_login.cgi six unbounded strcpy() into global buffers | Buffer Overflow | CWE-787 | 3.5 AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N (conservative) |
| 04-upload-fw-multipart-overflow | upload_fw.cgi multipart header strcat overflow (crash verified) | Buffer Overflow | CWE-787 | 6.5 AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| 05-fqc-info-disclosure | fqc.cgi pre-auth disclosure of serial/MAC/default WiFi password/WPS PIN | Info Disclosure | CWE-200 | 6.5 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |

## Submission checklist (per vulnerability)

1. Create a **public** GitHub repo (descriptive name is fine — the CVE ID is
   NOT needed in the repo name; GitHub redirects old URLs after renaming).
2. Copy the subdirectory's README.md into the repo.
3. VulDB: https://vuldb.com/?submit — paste Description, CWE, CVSS, references.
   MITRE CNA-LR: https://mitre.github.io/mitre-cve-roles/cve-id-request/ —
   login → "Reserve One CAN" → fill Problem types / Vendor / Product /
   Version / Description / References URL → Submit Request.
4. After the CVE ID is assigned, add it to the README title and notify the
   CNA ("Notify about a Publication" / VulDB entry update).
5. Do not reference the CAN tracking number publicly before assignment.

## Notes

- Replace `<ROUTER_IP>` placeholders with the target address when reproducing.
- All PoCs are non-destructive (marker files under /tmp only; no
  configuration changes, no flashing, no persistence).
- Discovery date: 2026-10-10. Vendor notification: pending (recommended
  before or in parallel with CNA submission).
