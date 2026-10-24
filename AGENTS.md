# sshgate

sshgate opens a firewall port (SSH, tcp/22 by default) for the visitor's current IP after a
secret HTTPS link plus a TOTP code. It targets one administrator of a self-hosted Linux server
who needs SSH from changing IPs, as a dependency-free alternative to port knocking. The code is
small and stable: a single initial commit (2026-07-31). See `README.md` for the user-facing
description and security model.

## Layout

- `app.py`: the web app (Python 3 stdlib only). Renders the code page, verifies TOTP (RFC 6238,
  ±30 s drift), rate-limits per IP, calls the helper through `sudo -n`. UI strings live in
  `TRANSLATIONS` (en, ru, es).
- `sbin/sshgate-open`: privileged helper. Validates an IPv4 address, inserts a `ufw` allow rule
  (deduplicated), writes the open time to the state dir, logs via `logger -t sshgate`.
- `sbin/sshgate-reap`: closes a rule only when it is at least `HOLD` seconds old and has no
  established connections on the port from that IP (checked with `ss`).
- `systemd/`: `sshgate.service` (runs `app.py` as user `sshgate`), `sshgate-reap.service` and
  `sshgate-reap.timer` (every 2 minutes).
- `nginx/sshgate.example.conf`: the `location` block that proxies the secret path to the app.
- `install.sh`: root installer; creates the user, dirs, sudoers entry, config with fresh secrets,
  enables the units and prints the link, the `otpauth://` URI and the nginx block.
- `config.example.json`: config template (placeholders only).

## Setup / Build / Run / Test

Target: Linux with `ufw`, `systemd`, `sudo`, `ss` (iproute2) and `python3`. Nothing to build.

```bash
sudo DOMAIN=example.com ./install.sh   # install on the server (run as root)
sudo SSHGATE_DRYRUN=1 /usr/local/sbin/sshgate-reap      # print keep/would-close, change nothing (invocation unverified)
```

Runtime paths set by `install.sh` and the code: `/opt/sshgate/app.py`, `/etc/sshgate/config.json`
(mode 640, owner `sshgate`), `/var/log/sshgate/access.log`, `/var/lib/sshgate/opens/<ip>`,
`/etc/sudoers.d/sshgate`.

The blocking `.github/workflows/security.yml` runs offline behavior tests, Python source security rules and source secret scanning. Run `python3 -m unittest discover -s tests -v` and `bash -n install.sh sbin/sshgate-open sbin/sshgate-reap`. Tests fake all privileged commands and temporary state; never use the real firewall or installer for validation. There is no third-party Python dependency inventory.
`app.py` reads `/etc/sshgate/config.json` at import time, so it cannot be imported or run on a
machine without that file.

## Conventions

- Python standard library only; do not add dependencies. Bash scripts use `set -euo pipefail`
  (the reaper uses `set -u`).
- Config keys (`config.example.json`, defaults in `app.py`): `totp_secret` (required),
  `url_secret`, `listen_host`, `listen_port` (8787), `open_helper`, `logfile`, `max_fails` (5),
  `fail_window` (900 s), `default_lang` (`en`), `hold_hours` (24, display only).
- Environment overrides for the shell scripts: `SSHGATE_PORT` (22), `SSHGATE_STATE_DIR`,
  `SSHGATE_MIN_AGE` (86400, reaper), `SSHGATE_DRYRUN` (reaper).
- Adding a UI language: add one entry with the same keys to `TRANSLATIONS` in `app.py`.
- Default branch `main`. Docs, comments and commit messages are in English.

## Gotchas and boundaries

- Never commit real secrets. `.gitignore` excludes `config.json`, `access.url`, `*.secret`,
  `secrets/` and `data/opens/`. Keep placeholders in `config.example.json`.
- The secret URL path is the first factor: keep `access_log off` in the nginx block and keep
  `log_message` silent in `app.py`, so the path never reaches logs.
- The app accepts one IPv4 `X-Real-Client` header only from a loopback peer. Keep it bound to localhost behind the proxy that replaces that header.
- Both the app and `sshgate-open` accept IPv4 only; IPv6 visitors receive a bad-request response. TOTP replay prevention and rate limits are in-process and reset at restart.
- The sudoers entry allows exactly `/usr/local/sbin/sshgate-open`; renaming or moving the helper
  requires changing `install.sh`, `config.example.json` and the sudoers line together.
- `install.sh` prints a nginx block with port 8787 hardcoded; it does not follow a changed
  `listen_port`.
- `sudo` normally resets the environment, so `SSHGATE_PORT` set for the app process is not
  expected to reach `sshgate-open` (unverified); the systemd units set no environment.
- The "hold" shown in the UI (`hold_hours`) is a label; the real policy is in `sshgate-reap`.
- Keep a break-glass path (provider console or IPMI) when testing on a real server: a broken gate
  can lock you out.
