"""
test-targets/direct_sqlmap_confirm.py

Direct, unmodified call into modules.web.sqlmap_wrap.run_sqlmap() (the real
production code path — nothing here is mocked) against the companion
info.php test fixture on dvwa-target. This exists because Aegis's normal
gobuster/dirb -> sqlmap discovery chain may land on a different (non-
vulnerable) DVWA .php file first, since DVWA exposes several unauthenticated-
but-not-actually-injectable .php files (index.php, phpinfo.php) alongside
info.php, and _detect_injectable_candidates() in deepscan.py takes whichever
one gobuster/dirb happen to report first. This script captures the
guaranteed-positive confirmation directly, using the exact same
run_sqlmap() function deepscan.py itself calls.
"""

import sys
sys.path.insert(0, "/home/jafar/aegis-scanner")

from modules.web.sqlmap_wrap import run_sqlmap

target = "172.28.0.20"
url = f"http://{target}/info.php?id=1"

result = run_sqlmap(target, url)

print("\n--- run_sqlmap() result ---")
print("injectable:", result["injectable"])
print("error:", result["error"])
print("findings:")
for f in result["findings"]:
    print(" ", f)
