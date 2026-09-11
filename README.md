# HoneyPot â€” VoIP fraud honeypot and compliance panel

FreeSWITCH-based honeypot for prefix 3366 with a Python control panel that records the
A-leg, transcribes and analyses calls with Azure (Speech, Language, Content Safety,
Translator, OpenAI), classifies them the way carrier fraud desks report them
(fraud / illegal robocall / unwanted / review), attributes traffic to companies, and
serves per-company dashboards, compliance queues, daily reports, call reports,
simulations, API usage and cost reporting, and tenant users.

## Layout

| Path | What it is | Deploys to |
|---|---|---|
| `panel/app.py` | Control panel (HTTP server, UI, analysis pipeline, API) | `/opt/voip/app.py` |
| `panel/voip_intel.py` | Cross-call intelligence engine and exports | `/opt/voip/voip_intel.py` |
| `panel/test_scoring.py` | Legacy scoring test (needs updating to the current API) | `/opt/voip/test_scoring.py` |
| `scripts/update_voip_spam_reputation` | FTC Do-Not-Call complaint feed refresh | `/usr/local/sbin/` |
| `scripts/fs_cli.example` | fs_cli wrapper (ESL password redacted) | `/usr/local/bin/fs_cli` |
| `systemd/` | `voip-frontend.service` + hardening drop-in, `freeswitch.service`, `rtpengine.service` | `/etc/systemd/system/` |
| `cron/voip-spam-reputation` | Weekday FTC refresh at 17:30 UTC | `/etc/cron.d/` |
| `freeswitch/conf/` | Full FreeSWITCH configuration (passwords redacted to `CHANGE_ME`, TLS certs excluded) | `/etc/freeswitch/` |
| `freeswitch/scripts/` | Lua dialplan scripts (`record_and_bridge_3366.lua`, `spam_gate_3366.lua`, IVR prefixes) | `/var/lib/freeswitch/scripts/` |
| `rtpengine/rtpengine.conf` | rtpengine configuration (currently unused by the dialplan) | `/etc/rtpengine/` |
| `examples/` | `azure.env.example`, company/routing/pricing examples, spam gate config | see below |

Runtime data is **not** in this repository: recordings, transcripts, analyses, peaks,
usage logs, `companies.json`, `users.json`, `.credentials`, `.session_secret`, `.azure.env`.

## Latest interface update (September 11, 2026)

The panel includes the white / soft-sage minimalist interface, self-hosted Manrope
typography, responsive recording cards, and in-dashboard Call Reports. See
[deployment notes](docs/UI-DEPLOYMENT.md) before updating an installation.

## Install (Debian 11)

1. Install FreeSWITCH 1.10.x (modules under `/opt/voip/fs/mod` on the reference host) and
   `lua5.3` for script checks. Copy `freeswitch/conf/` to `/etc/freeswitch/` and set real
   values for every `CHANGE_ME` (ESL password in `autoload_configs/event_socket.conf.xml`,
   directory users, `vars.xml`). Copy `freeswitch/scripts/*.lua` to `/var/lib/freeswitch/scripts/`.
2. Create the panel user and directories:
   ```bash
   useradd -r -s /usr/sbin/nologin voip-panel
   mkdir -p /opt/voip/{recordings,transcripts,peaks,companies}
   chown -R voip-panel:voip-panel /opt/voip/{recordings,transcripts,peaks,companies}
   ```
3. Copy `panel/assets/` to `/opt/voip/assets/` (directories 755, files 644).
   Set `VOIP_WEB_ALLOWED_IPS` to your administrator public IPs plus `127.0.0.1,::1`
   in the service environment; the source defaults to loopback access only.
   Copy `panel/*.py` to `/opt/voip/`, `examples/azure.env.example` to `/opt/voip/.azure.env`
   (mode 660, group `voip-panel`), `examples/spam_filter.conf` and
   `examples/vendor_3366_prefix.conf` to `/opt/voip/`, and the vendor/customer examples
   to `/opt/voip/vendor_3366.conf` and `/opt/voip/customer_3366.conf`.
4. Install the systemd units (the hardening drop-in goes to
   `/etc/systemd/system/voip-frontend.service.d/hardening.conf`), the cron file and the
   updater script, then:
   ```bash
   systemctl daemon-reload && systemctl enable --now voip-frontend
   ```
5. Sign in at `http://<host>:8080` (bootstrap user `admin`, password from `VOIP_PASS` env
   or `changeme`; change it immediately), open **Settings**, add companies with their
   source IPs and vendor, enter Azure keys per company or as platform defaults, and
   create company users.

The server clock is expected to be **UTC**; FreeSWITCH names recordings with its local
time, so restart it after any timezone change.

## Security notes

* The panel listens on plain HTTP; put it behind TLS or a VPN.
* Source-IP admission control (Settings â†’ Platform defaults) rejects calls from IPs not
  listed under a company; it is off by default.
* `record_and_bridge_3366.lua` still contains the media-address pool logic reviewed in the
  September 2026 audit; `media_pool.txt` is intentionally not included.
* Never commit `.azure.env`, `companies.json`, `users.json` or `.credentials`.
