# netexecspray

A modern, multi-protocol password sprayer that wraps **NetExec (`nxc`)** and adds
native Python sprayers for mail/db services. It sprays usernames + passwords (or an
NTLM hash, or a `user:pass` list) across many protocols and targets with a slick,
minimal live UI, lockout-aware pacing, and ready-to-use loot output.

Anyone is welcome to improve it 🙂

---

## Features

- **Protocols**
  - nxc-backed: `smb ldap winrm ssh ftp mssql rdp wmi vnc nfs`
  - native (pure Python): `smtp smtps imap imaps pop3 pop3s mysql`
  - **bundles**: `ad` (smb,ldap,winrm,wmi,mssql,rdp) · `mail` (smtp,smtps,imap,imaps,pop3,pop3s) · `db` (mssql,mysql) · `remote` (ssh,rdp,winrm,vnc) · `all`
  - `--list-protocols` prints the full catalogue with default ports.
- **Credentials** — four ways to supply them:
  - `-u/-U` + `-p` — user & password **files** or inline comma-lists → every user × every password (multi-round spray).
  - `-H` — NTLM **hash** (pass-the-hash).
  - `-c` / `--combo FILE` — `user:pass` per line, **paired**: each user tries only its own password (credential stuffing).
  - `-S` / `--spray-file FILE` — mixed file of `user:pass` **and** bare `user` lines, **pooled**: all users × all discovered passwords.
- **Targets**: IP, hostname, domain, **CIDR** (expanded to hosts), or a file of targets;
  optional DNS `--resolve`.
- **Lockout safety**
  - `--max-attempts N` caps attempts per account across the whole run.
  - `--pass-pol` / `--safe` reads the domain lockout policy first and auto-caps.
  - `--lockout-delay`, `--rate`, `--jitter` for pacing; clean **Ctrl-C** writes partial results.
  - `--resume <log>` skips attempts already present in a previous run's log.
- **Validation** (`--validate`): secondary nxc check to confirm real access, not just auth.
- **Live UI** — minimal by design. A thin framed banner, then a slim gradient progress
  bar + spinner with a live **rate sparkline** and a running `valid/admin` count that
  updates in place. **Only valid credentials are printed** — one clean, aligned line each
  (`✦` admin/access, `›` valid). Fails and connection errors are hidden (show them with
  `-v/--verbose`), and there is no noisy end-of-run summary: you already saw the hits. It
  updates the terminal **title** with progress, prints **clickable** output paths (OSC 8),
  and `--bell` rings on confirmed access. `--no-color` strips all styling.
- **Output — nothing is written to disk unless you ask for it.** Each flag is opt-in:
  - `--output FILE` — write a clean, aligned, framed **log file** (and loot/csv next to it)
  - `--out-dir DIR` — write `valid.txt` / `pwned.txt` / `results.csv` into `DIR`
  - `--report FILE.md` — Markdown engagement report (findings + per-protocol tables)
  - `--json FILE` — structured JSON (summary, per-protocol rollup, every attempt)
  - loot files: `valid.txt` = `user:pass` deduped, `pwned.txt` = confirmed-access only,
    CSV = every attempt. Full per-cred / per-protocol detail lives in these files.
- **Pre-flight**: `--null` / `--guest` probe anonymous/guest sessions before spraying.
- **Proxy**: `--proxychains` routes nxc through `proxychains -q` (native protocols skipped).

---

## Requirements

- Python 3.8+ (standard library only — no required pip installs)
- **NetExec** (`nxc`) in `PATH`
- Optional: `pymysql` (mysql sprayer), `proxychains` (for `--proxychains`)

Tested on Kali Linux.

## Installation

```bash
git clone https://github.com/zingerw1/netexecsprayer.git
cd netexecspray
```

Run it straight from the clone, or install it:

```bash
# A) run in place — launcher shim or module
./netexecspray.py ad 10.10.10.1 -u users.txt -p 'Pass'
python3 -m netexecspray ad 10.10.10.1 -u users.txt -p 'Pass'

# B) pip install → provides a `netexecspray` command on PATH
pip install .                 # core (stdlib only)
pip install '.[mysql]'        # + PyMySQL for the native mysql sprayer
```

## Project layout

The logic lives in the `netexecspray/` package; `netexecspray.py` is a thin
launcher. Each module has one job, so the tool is easy to read and extend:

```
netexecspray.py        launcher shim (./netexecspray.py & PATH symlink)
netexecspray/
  state.py       shared runtime state + locks (one place for concurrency)
  theme.py       palette, glyphs, colour/gradient primitives
  protocols.py   protocol catalogue, default ports + bundle expansion
  parsing.py     classify / explain nxc & native output
  runners.py     talk to targets: nxc, validation, lockout policy, native sprayers
  results.py     record pipeline + log / loot / csv / report / json sinks
  ui.py          all terminal output (banner, status bar, hits); the only stdout writer
  loaders.py     targets (CIDR/DNS), credential / combo / spray-file lists, resume parsing
  worker.py      per-attempt spray logic, rate gate, pre-flight probes
  cli.py         argument parsing + orchestration
```

Dependencies flow one way (`cli → worker → {ui, runners, results, parsing}`),
and `--no-color` is handled in one spot (`ui` strips ANSI at write time), so
adding a protocol, an output format, or a UI tweak touches a single module.

---

## Usage

Spray one protocol:
```bash
netexecspray smb 192.168.1.10 -u Alan -p 'Sup3rS3cretPass!'
```

Inline comma-lists — no files needed (works for users, passwords, and targets):
```bash
netexecspray smb 10.10.10.1 -u user1,user2 -p pass1,pass2
netexecspray smb 10.0.0.1,10.0.0.2 -u admin -p 'Winter2025!'
```
(If a password itself contains a comma, put it in a file instead.)

Spray the AD bundle across a subnet, pacing to the domain lockout policy:
```bash
netexecspray ad 10.129.0.0/24 -u users.txt -p 'Winter2025!' --safe
```

Multi-round password spray with an explicit per-account cap and a delay between rounds:
```bash
netexecspray ad corp.local -u users.txt -p passwords.txt --max-attempts 3 --lockout-delay 60
```

Pass-the-hash across everything:
```bash
netexecspray all dc01.corp.local -u users.txt -H :32ed87bdb5fdc5e9cba88547376818d4
```

Paired credential stuffing from a `user:pass` list:
```bash
netexecspray smb 10.10.10.1 -c creds.txt
```

Pooled spray from one mixed file (`user:pass` and bare `user` lines → all users × all passwords):
```bash
# creds.txt:
#   alice:Password1
#   bob
netexecspray smb 10.10.10.1 -S creds.txt      # tries alice:Password1 AND bob:Password1
```

Confirm real access and collect loot + a report:
```bash
netexecspray ad targets.txt -u users.txt -p 'Pass' --validate --out-dir loot/ --report engagement.md
```

Resume a previous run (skip already-tried creds) and rate-limit:
```bash
netexecspray ad targets.txt -u users.txt -p p.txt --resume spray_prev.log --rate 5
```

---

## Reading results

Only valid credentials print to the terminal, one line each:

- `✦ admin` = confirmed execution / real access (`Pwn3d!`, ADMIN$/WRITE, command exec) — likely lateral movement.
- `› valid` = credentials are good, access may be restricted.
- `⊘ locked` = account locked out; that user is skipped for the rest of the run (shown inline as it happens).
- LDAP valid → good for BloodHound; RDP/WMI may be blocked by policy or lack execution.

Hits are also dropped into `<log>.valid.txt` (ready to feed back into other tools) and
`<log>.pwned.txt`, with the full audit trail in `<log>.csv`, the log file, and the JSON/report.

---

## Notes

- CIDRs are expanded to hosts (so native sprayers work and counts are accurate). Use
  `--no-expand-cidr` to hand the CIDR to nxc directly, or `--force` for very large ranges.
- `--resume` matches on `proto:target:user:secret`; hashes are truncated in logs, so resume
  is most reliable for password sprays.
- `--proxychains` only covers nxc-backed protocols; native sprayers are skipped under it.
