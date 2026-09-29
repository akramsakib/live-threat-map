# Live Cyber Threat Map

A faithful rebuild of Check Point's live threat map — same dot-matrix world, same
three-colour legend, same dual-sidebar layout — running on the **real ThreatCloud
feed**, with a full filter engine on top.

```bash
cd threatmap
python3 server.py            # → http://0.0.0.0:3000
PORT=8080 python3 server.py  # different port
```

No dependencies. Python 3.8+ standard library only. Nothing to install, nothing
to rebuild after a restart.

---

## Understanding what you're seeing

Signature names from ThreatCloud are terse and vendor-specific — "Realtek Jungle
SDK Command Injection" means nothing to most people. So:

- **Click any attack in the live list** for a plain-English panel: what the
  attack actually does, whether it deserves attention, severity, repeat count,
  and a link to the NVD entry when the name carries a CVE.
- **The `?` button in the header** opens a glossary: what Malware / Phishing /
  Exploit mean, why most of this traffic is automated background noise, what
  "origin unknown" and "domestic" tags mean, why grey countries are unmeasured
  rather than safe, and why the country numbers are a *rate per organisation*
  rather than a total.

A 31-rule knowledge base classifies **98% of observed events** into families
(EternalBlue, config/secret hunting, SSRF, reverse shell, botnet, infostealer,
AI-agent tooling…). Anything unmatched falls back to an honest "this is a
vendor-internal label and the public feed carries no payload detail".

## Filters

Open with the **FILTERS** button (top right). Active filters appear as removable
chips over the map, and the badge counts how many are on.

| Filter | Behaviour |
|---|---|
| **Signature search** | Free text over the attack name — `ransom`, `CVE-2024`, `SMB`. Quick chips for common ones. |
| **Attack type** | Malware / Phishing / Exploit. Also togglable straight from the bottom legend. |
| **Country role** | `EITHER END` · `SOURCE ONLY` · `TARGET ONLY` — governs both country and region pickers. |
| **Region** | Africa, Asia, Europe, N. America, S. America, Oceania. |
| **Countries** | All 245, searchable, with flags. Each row shows its weekly rate, plus a live count of how many events it has in the current session. Countries with none are dimmed. |
| Presets | Select all · Clear · Only reporting (87) · Malaysia · SE Asia |
| **Skip circular** | Hides attacks whose source country equals the target. |
| **Hide unknown origins** | Drops events whose source is a geolocation placeholder. |
| **Shade blind spots** | Dims the 84 countries that report nothing. |
| **Minimum severity** | Each event carries a repeat count; keep only heavier bursts. |
| **Arc lifetime** | 0.6s – 5s. |
| **Rate stepper** | Left sidebar `− MAX +`: MAX, 1, 2, 4, 8, 15, 30 arcs/sec. |

Filters drive **everything**: which arcs are drawn, the live ticker, the
*Live session* panel, and the `Showing N of M events` readout. Clicking a country
opens its 31-day trend with one-click **Filter source / Filter target**.

---

## Layout

- **Header** — live-day counter, connection state, filter button.
- **Left** — Recent daily attacks (31-day bars), rate stepper, live attack ticker.
- **Centre** — dot-matrix map, animated arcs, source/target labels, clickable
  countries, type legend.
- **Right** — Live session (filtered), Top targeted countries, Top targeted
  industries, Top malware types.

---

## Honest by default

The original map hides three things. These are visible here, not in a footnote:

- **Unknown origins** are drawn as a **dashed arc from a hollow ring** and tagged
  `ORIGIN ?`. `37.751, -97.822` is MaxMind's documented US placeholder — the
  coordinate returned for `8.8.8.8` with a 1000 km accuracy radius. It means
  "somewhere in the US", not an attacker's location.
- **Domestic attacks** get a self-loop and a `DOMESTIC` tag instead of a
  dramatic cross-border swoop.
- **Blind spots**: only **87 of 171** countries return any data. Click Egypt,
  Iran or Cambodia and it says so plainly. Every ranking here ranks Check Point's
  customer base, not the internet.

Each event is classified `region` (subdivision resolved) / `city?` (approximate)
/ `country` (placeholder — origin genuinely unknown).

---

## Architecture

```
Check Point SSE ──┐  server.py
(one connection)  ├──▶ enrich → classify → fan-out ──▶ browser 1..N
                  └──▶ /api/country/<cc> cached to disk
```

The proxy isn't optional: Check Point sets
`Access-Control-Allow-Origin: https://threatmap.checkpoint.com`, so a browser
cannot read the feed directly.

| Route | Purpose |
|---|---|
| `GET /api/stream` | SSE — `attack`, `counter`, `stats`, `status` |
| `GET /api/stats` | rolling snapshot |
| `GET /api/country/<ISO2>` | 31-day trend + malware mix (404 = no coverage) |
| `GET /api/topstats` | daily leaderboard |
| `GET /static/…` | map data, 245-country table, 249 flags |

### Client internals

- **Dot matrix** — 17,938 dots on a 340 × 168 grid, run-length encoded into
  **23 KB**, each dot tagged with its owning country so filtered countries,
  hover and attack heat can light up individually.
- **Projection** — hand-rolled Miller cylindrical, cropped to 83°N / 58°S, with
  a working inverse so a click resolves to a country by point-in-polygon.
- **Rendering** — two canvases: static dots, animated arcs. Arcs take the short
  way round the antimeridian and are drawn twice with a map-width offset so they
  wrap the seam cleanly. Bow height scales with distance. Capped at 300 arcs.
- Everything is served locally — no CDN, no external fonts.

### Regenerating data

```bash
python3 probe.py   # re-probe all 171 countries → static/coverage.json
```

`HOME` near the top of the client script sets the pink home country (`MY`).

---

## Deploying

Two ways to run it, both free.

### 1. GitHub Pages (static, zero infrastructure)

Live at **https://akramsakib.github.io/live-threat-map/**

Pages cannot run Python, and Check Point's API is CORS-locked to their own
origin — so the browser can never read the feed directly. The way round it:
a GitHub Actions job captures a real slice of the feed **every 2 hours**,
bakes it into `docs/`, and publishes.

What that costs you is smaller than it sounds:

| Part of the UI | On Pages |
|---|---|
| Country 31-day trends | **Real, refreshed every 2h** — this is daily data anyway |
| Top countries / industries / malware types | **Real, refreshed every 2h** |
| Coverage + blind spots | **Real** |
| Day counter | Real at capture time, then ticks at the measured rate |
| Animated arcs | **Real captured events**, replayed on loop at original pacing |

Only the arc animation is time-shifted — and that is the part the original map
samples down to ~1% anyway. The UI labels itself `REPLAY` with the capture
timestamp rather than pretending.

```bash
python3 tools/capture.py --seconds 150 --out docs/data   # grab real data
python3 tools/build_static.py                            # assemble docs/
cd docs && python3 -m http.server 4100                   # preview locally
```

### 2. A real backend (genuinely live)

For a true live stream you need a host that runs Python. `fly.toml` is
preconfigured for Singapore with sleep disabled:

```bash
fly launch --copy-config --no-deploy && fly deploy
```

Then point the Pages build at it — no rebuild needed:

```
https://akramsakib.github.io/live-threat-map/?api=https://your-app.fly.dev/api
```

The `?api=` parameter switches the same page from replay to live. See
[DEPLOY.md](DEPLOY.md) for Render, Docker, the one-instance rule, and what to
consider before putting it on a public URL.

## Attribution

Live data comes from **Check Point ThreatCloud** via an undocumented public
endpoint. This project is an independent client — not affiliated with or
endorsed by Check Point Software Technologies.
