# VoIP HoneyPot

A honeypot for USA-prefix (3366) inbound VoIP traffic: it answers scam/robocall
traffic, records the caller audio, bridges to a configured upstream vendor, and
exposes a control panel that transcribes and scores each call for fraud and
regulatory-compliance signals.

## Components

| Path | Role |
|------|------|
| `panel/app.py` | Self-contained Python control panel (stdlib HTTP server, no framework). Recording browser, server-side waveform peaks, Azure Speech transcription, fraud/operational scoring, daily reporting, spam-filter admin. |
| `panel/test_scoring.py` | Scoring-engine tests. |
| `freeswitch/scripts/record_and_bridge_3366.lua` | FreeSWITCH capture core: records the A-leg, writes a `.meta` sidecar (ANI/DNI/SIP/STIR Identity header), bridges to the vendor read live from `vendor_3366.conf`. |
| `freeswitch/dialplan/public/3366.xml` | Inbound dialplan for `^3366(\d+)$` — ring simulation then hand off to the Lua. |
| `freeswitch/directory/3366.xml.example` | SIP account template (set your own password). |
| `deploy/voip-frontend.service` | systemd unit for the panel. |

## STIR/SHAKEN verification

The panel performs real RFC 8224/8225 PASSporT verification (not attest-claim
trust): it fetches the `x5u` signing cert (SSRF-guarded — https-only, public-IP
only, IP-pinned, size/time capped), verifies the ES256 signature over
`header.payload`, checks cert validity dates and the SHAKEN TN-Auth-List
extension, and confirms the signed orig/dest TNs match the call ANI/DNI. Verdict
feeds the caller-identity axis of the operational-risk score. Requires the
`cryptography` package.

## Setup

```bash
# panel
cp panel/azure.env.example        /opt/voip/.azure.env        # fill in, chmod 600
cp panel/vendor_3366.conf.example /opt/voip/vendor_3366.conf  # your upstream peer
sudo cp deploy/voip-frontend.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now voip-frontend

# freeswitch
cp freeswitch/scripts/record_and_bridge_3366.lua /var/lib/freeswitch/scripts/
cp freeswitch/dialplan/public/3366.xml           /etc/freeswitch/dialplan/public/
cp freeswitch/directory/3366.xml.example         /etc/freeswitch/directory/default/3366.xml  # set password
fs_cli -x reloadxml
```

Panel defaults to `:8080`; the first login credentials are seeded to
`/opt/voip/.credentials` on first run (override via `VOIP_USER`/`VOIP_PASS`).

## Not in this repo

Real-call recordings/transcripts (PII), vendored FreeSWITCH/ffmpeg binaries
(`lib/`, `bin/`, `fs/`), and all live secrets — see `.gitignore`.
