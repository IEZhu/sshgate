# sshgate

[![security](https://github.com/IEZhu/sshgate/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/IEZhu/sshgate/actions/workflows/security.yml)

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
   with per-IP rate limiting (5 tries / 15 min). Each accepted TOTP time step can be used once across all client IPs, including simultaneous requests.
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

## Security checks and local tests

The blocking `security` workflow runs on pull requests, pushes to `main`, daily, and on manual dispatch. It uses a read-only GitHub token, immutable action references, Semgrep 1.182.1 with every official Python security subtree at commit `16b9e6d45f10649f6a531ec4838ed9924372c3bc`, and Trivy 0.76.1. Every source finding, secret finding (including LOW and UNKNOWN), scanner error and test failure blocks the workflow. Repository suppression files and source `nosemgrep` comments cannot disable findings.

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh sbin/sshgate-open sbin/sshgate-reap
```

The dependency-free offline suite checks an RFC TOTP vector, clock drift, malformed codes, concurrent replay, per-IP lockout, trusted loopback proxy headers, request framing, helper argument construction, helper failures, rule deduplication, hold times, active sessions, dry-run behavior and failed session/deletion commands. All process and filesystem boundaries use temporary fakes; the suite never runs real `sudo`, `ufw`, `ss` or the installer. The reaper keeps a rule and its state when session inspection or deletion fails.

There is **no third-party Python SCA inventory**: production imports are standard-library-only and a test enforces that contract. A successful empty vulnerability report would not establish coverage. Trivy scans source secrets; Semgrep scans production Python and CI helpers. Shell syntax and mocked behavior are checked, while nginx, systemd, sudoers, the installed Python interpreter, Linux packages, the deployed host and a real firewall are outside this repository workflow's coverage. Keep those supplied runtimes updated through the host's package management.

The app accepts exactly one valid IPv4 `X-Real-Client` header only from a loopback peer; nginx must replace this header with the trusted visitor address. IPv6 visitors are rejected because the helper opens IPv4 rules. Successful TOTP use is remembered in-process until its accepted clock window expires, including when the helper fails; wait for the next code before retrying. Restarting the app clears replay and rate-limit memory, so those controls do not provide persistent or multi-process protection.

## License

[MIT](LICENSE)
