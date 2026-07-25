"""
test-targets/direct_xss_confirm.py

Direct, unmodified call into modules.web.xss_wrap.run_xss() (the real
production code path — nothing here is mocked) against the companion
xss.php test fixture on dvwa-target. This is the XSS sibling of
direct_sqlmap_confirm.py.

Why it exists (same limitation class as the sqlmap one): Aegis's normal
gobuster/dirb path discovery only finds a page if its literal name is in the
wordlist. `info.php` happens to be in dirb/common.txt, so deepscan's real
discovery -> sqlmap chain reaches it unaided; `xss.php` is NOT in the
wordlist, so the scanner's unauthenticated discovery never lands on it even
though the wiring (modules/profiles/{deepscan,webaudit}.py XSS phase) is
fully in place and does run nuclei DAST against every parameterised endpoint
it DOES discover. This script confirms the XSS engine end-to-end against the
known-vulnerable fixture directly, using the exact same run_xss() function
the profiles call, so the payload + parameter + response-snippet evidence is
captured deterministically.
"""

import sys
sys.path.insert(0, "/home/jafar/aegis-scanner")

from modules.web.xss_wrap import run_xss

target = "172.28.0.20"
url = f"http://{target}/xss.php?name=guest"

result = run_xss(target, url)

print("\n--- run_xss() result ---")
print("vulnerable:", result["vulnerable"])
print("error:", result["error"])
print("findings:")
for f in result["findings"]:
    print("  parameter:", f["parameter"], "| method:", f["method"])
    print("  payload  :", f["payload"])
    print("  evidence :", f["evidence"])
