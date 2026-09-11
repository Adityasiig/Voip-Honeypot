# White / Manrope UI deployment

This update preserves existing application features and includes:

- A white background with soft sage and neutral surfaces.
- Self-hosted Manrope variable typography (SIL Open Font License).
- Responsive card grids, recording controls, company/settings forms and reports.
- Call Reports inside the existing dashboard, alongside Daily Reports.

## Files to deploy

| Repository file | Server destination |
| --- | --- |
| `panel/app.py` | `/opt/voip/app.py` |
| `panel/assets/manrope-variable.ttf` | `/opt/voip/assets/manrope-variable.ttf` |
| `panel/assets/Manrope-OFL.txt` | `/opt/voip/assets/Manrope-OFL.txt` |

Keep the font license alongside the font. The fixed `/assets/manrope-variable.ttf`
route serves the font locally; the existing web source-IP check still applies.
No external font service or additional Python dependency is required.

## Configure access before restarting

The public repository does not include the deployment's administrator IP allowlist.
Set `VOIP_WEB_ALLOWED_IPS` in a systemd service drop-in. For example, replace the
documentation-only address below with your actual administrator public IP:

```ini
[Service]
Environment="VOIP_WEB_ALLOWED_IPS=127.0.0.1,::1,192.0.2.10"
```

Without this variable the repository version allows loopback web access only.
This publication change has **not** been deployed to the existing VPS; its current
access configuration remains unchanged. Do not copy example company or user
configuration over a live installation's data.

Back up the running source and service configuration first. Wait for analysis jobs
to finish, validate Python syntax, install the source and assets with permissions
readable by `voip-panel`, reload systemd after environment changes, and restart only
`voip-frontend.service`. FreeSWITCH does not need a restart for this UI update.

## Checks performed

- Python parsing and JavaScript syntax checks.
- 63 fixture-based layout checks: nine views at seven widths (320–1920 pixels).
- No page-wide horizontal overflow or JavaScript errors in those checks.
- Live HTTP checks of the panel, font, recordings API and individual report route.

These are interface checks, not certification of fraud-detection accuracy.
Do not treat automated scores or classification labels as proof of fraud or legal
noncompliance; validate against reviewed calls before making enforcement decisions.

## Publication boundaries

Recordings, transcripts, analyses, customer data, production keys, session secrets,
password files and server backups were not copied into this update. Existing example
configuration in this repository is not a substitute for a secure server backup.
