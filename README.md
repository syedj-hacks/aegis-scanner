# Aegis Scanner
Kali Linux vulnerability assessment framework — Cyber404 Academy 2026.

## Setup
```bash
git clone https://github.com/syedj-hacks/aegis-scanner.git
cd aegis-scanner
chmod +x install.sh
./install.sh
source venv/bin/activate
```

## Usage
```bash
python3 aegis.py <target> [--profile PROFILE] [-v]
```

| Profile | Description |
|---|---|
| `quickscan` (default) | Fast overview — DNS, top-port nmap scan, service detection. |
| `stealthscan` | Slow-timing, full-port sweep — minimal footprint, no service probing. |
| `webaudit` | Web-focused audit — headers, Nikto, gobuster + CVE enrichment on web ports. |
| `deepscan` | Full assessment — recon, all ports, web audit, CVE/severity/remediation, TXT+PDF reports. |
| `compliance` | TLS cipher + HTTP header nmap scripts for a compliance-oriented baseline. |

Example:
```bash
python3 aegis.py 192.168.56.101 --profile deepscan
```

Run from the repo root (paths for `output/`, `database/aegis.db`, and `.env`
are all resolved relative to it). Each scan is recorded in
`database/aegis.db`; reports are written to `output/<target>/`.

`aegis.py --help` lists all flags, and `aegis.py --version` prints the
current version.
