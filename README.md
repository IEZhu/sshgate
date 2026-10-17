# sshgate

Open a firewall port for **your current IP** by visiting a **secret HTTPS link** and
entering a **TOTP** code. No VPN, no client, no agent — just a browser link plus a
one-time code from your authenticator app.

It is a tiny, dependency-free (Python standard library) alternative to port knocking /
single-packet authorization for **personal, on-demand SSH access** from changing IPs,
aimed at a single administrator of a self-hosted Linux server with `ufw`, systemd and
an nginx reverse proxy.

```
Browser ──HTTPS──▶ nginx (secret path)  ──▶  sshgate app (localhost, TOTP)
                                              │  valid code
                                              ▼
                                   sudo sshgate-open <your-ip>
                                              │
                                              ▼
                          ufw allow from <your-ip> to any port 22   (held ≥24h, then until idle)
```

## Why

Dynamic/rotating IPs make static firewall allow-lists and multi-packet port knocking
unreliable. `sshgate` gates SSH at the network layer with two factors you always have
in a browser: **a secret URL** (first factor) and **a TOTP code** (second factor). The
opened rule is scoped to the single IP you came from and expires on its own.

## How it works

1. nginx serves a long, unguessable secret path over HTTPS and proxies it to the app on
   `127.0.0.1:8787`. Anything else on that host returns `404` — the endpoint is invisible
   without the secret.
2. The app shows a one-field page and verifies a **TOTP** (RFC 6238) second factor,
   with per-IP rate limiting (5 tries / 15 min).
3. On success it calls a small **privileged helper** (`sudo`, tightly scoped) that runs
   `ufw allow from <ip> to any port 22` and records the open time.
4. A **reaper** (systemd timer, every 2 min) removes the rule only once it is **≥ 24 h old
   AND there are no active SSH sessions from that IP** — so a long-running session is never
   cut, and idle access still expires.

## Security model

- Two factors: **secret URL** (kept out of logs) + **TOTP**. Security relies on the
  secrets, not on hiding the code (Kerckhoffs's principle) — this repo is safe to publish.
- The web app runs **unprivileged**, bound to localhost, and can only run one exact
  command as root via a locked-down `sudoers` entry. The helper strictly validates the IP.
- The rule opens for **the IP the browser came from** — so open the link from the same
  network you will SSH from.
- **Break-glass:** always keep an out-of-band path (provider console / IPMI). A network
  gate can fail; you must never be able to lock yourself out permanently.
- This is single-secret / single-TOTP — **great for one person**. For a team, prefer a
  managed identity-aware proxy (Cloudflare Access, Teleport, Tailscale).

## Requirements

- Linux with `ufw`, `systemd`, `sudo`, `ss` (iproute2), `python3` (stdlib only).
- A reverse proxy in front (examples use **nginx**) with TLS for the host.

## Install

```bash
git clone https://github.com/IEZhu/sshgate
cd sshgate
sudo DOMAIN=example.com ./install.sh
```

`install.sh` creates the `sshgate` user, generates secrets, installs the app, helper,
reaper and systemd units, and prints:

- your **secret link** `https://DOMAIN/<url_secret>/`,
- an **otpauth://** URI (+ base32 key) to add to your authenticator app,
- the **nginx location block** to paste into your HTTPS server, then `nginx -t && systemctl reload nginx`.

## Configuration

`/etc/sshgate/config.json` (see [`config.example.json`](config.example.json)):

| key            | meaning                                            | default |
|----------------|----------------------------------------------------|---------|
| `totp_secret`  | base32 TOTP secret (required)                       | —       |
| `url_secret`   | the secret used in the nginx path                   | —       |
| `listen_port`  | localhost port the app binds                         | 8787    |
| `hold_hours`   | minimum hold before the reaper may close (label)     | 24      |
| `default_lang` | UI language when the browser doesn't ask for one     | en      |

The real close policy (≥24 h **and** idle) lives in `sshgate-reap`; port and hold are
overridable with `SSHGATE_PORT` / `SSHGATE_MIN_AGE`.

## Internationalization

The UI ships in **English, Russian, Spanish**. Language is chosen by `?lang=xx`, then the
browser `Accept-Language`, then `default_lang`. Add a language by adding one entry with the
same keys to `TRANSLATIONS` in [`app.py`](app.py) — nothing else changes.

## Limitations

- Opens for the browser's IP: knock and SSH must share one egress IP.
- One shared secret + one TOTP (personal use).
- Password-based root SSH is orthogonal — still harden `sshd` (keys, disable root password).

## License

[MIT](LICENSE)
