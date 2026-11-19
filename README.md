# Net Recon Scanner v2.0

A lightweight Bash network reconnaissance tool that discovers live hosts on a subnet and fingerprints them as **Linux**, **Windows**, or **Active Directory Domain Controllers** — no Nmap required.

Built by [The Husky Hacker](https://thehuskyhacker.com)

---

## Features

- **Ping sweep** with TTL-based OS fingerprinting (Linux / Windows / Network device)
- **Active Directory detection** — scores Windows hosts on DC indicators (Kerberos, LDAP, Global Catalog, DNS, kpasswd, ADWS) and flags confirmed or likely Domain Controllers
- **Domain name extraction** via LDAP null bind or DNS reverse lookup (when `ldapsearch` or `nslookup` are available)
- **Port fingerprinting** for common services on Linux and Windows hosts
- **File output** with stripped ANSI colors for clean logs
- **Zero dependencies** — pure Bash, runs on any Linux distro out of the box

---

## Usage

```bash
chmod +x net-recon.sh
./net-recon.sh <subnet> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p` | Run port fingerprint on all discovered hosts | Off |
| `-t <sec>` | Ping timeout in seconds | `1` |
| `-o <file>` | Save results to a file | None |
| `-h` | Show help | — |

### Examples

```bash
# Basic sweep — TTL fingerprint + auto DC detection
./net-recon.sh 192.168.1.0/24

# Full port scan on all hosts
./net-recon.sh -p 10.10.10.0/24

# Slower scan for unstable networks, save output
./net-recon.sh -p -t 2 -o results.txt 172.16.0.0/24
```

---

## How It Works

### OS Fingerprinting (TTL)

| TTL Range | OS Guess |
|-----------|----------|
| 1–64 | Linux |
| 65–128 | Windows |
| 129–255 | Network Device / Other |

### Domain Controller Scoring

Windows hosts (TTL 65–128) are automatically checked for AD indicators:

| Port | Service | Score |
|------|---------|-------|
| 88 | Kerberos | +3 |
| 389 | LDAP | +3 |
| 3268 | Global Catalog | +3 |
| 636 | LDAPS | +2 |
| 53 | DNS | +2 |
| 464 | kpasswd | +2 |
| 9389 | AD Web Services | +2 |
| 445 | SMB | +1 |

- **Score ≥ 8** → Confirmed Domain Controller
- **Score 4–7** → Possible Domain Controller

### Port Lists

**Linux ports:** 22, 80, 111, 443, 2049, 3306, 5432, 8080, 8443, 9090

**Windows ports:** 135, 139, 445, 3389, 5985, 5986, 47001

**AD ports:** 53, 88, 389, 636, 3268, 3269, 464, 9389

---

## Sample Output

```
╔══════════════════════════════════════════════╗
║          Net Recon Scanner v2.0              ║
║          by The Husky Hacker                 ║
║                                              ║
║   Linux  |  Windows  |  Active Directory     ║
╚══════════════════════════════════════════════╝

[*] Target:    10.10.10.0/24
[*] Scanning 254 hosts...

[★] 10.10.10.5  — TTL=128 → DOMAIN CONTROLLER
    AD Services: Kerberos(88) LDAP(389) DNS(53) GC(3268) SMB(445)
    Domain: corp.local
[+] 10.10.10.20 — TTL=128 → Windows
    Services: RDP(3389) SMB(445) WinRM(5985)
[+] 10.10.10.50 — TTL=64  → Linux
    Services: 22 80 3306

══════════════════════════════════════════════════
 Scan Complete
══════════════════════════════════════════════════

 ★ Domain Controllers:  1
 ■ Windows hosts:       1
 ■ Linux hosts:         1
 Total alive:           3
```

---

## Use Cases

- **OSCP / PEN-200** — Quickly scope a lab network before diving in
- **CTF / HTB** — Find your targets without firing up Nmap first
- **AD labs** — Identify DCs fast so you can go straight to BloodHound
- **Pentest engagements** — Lightweight initial recon with no install required

---

## Limitations

- TTL fingerprinting is a best guess — custom TTL values or VPNs/firewalls can throw it off
- Port checks use `/dev/tcp` (Bash built-in) — no banner grabbing
- Domain name extraction requires `ldapsearch` or `nslookup` to be installed
- Runs sequentially — large subnets will take time

---

## License

MIT — do whatever you want with it.
