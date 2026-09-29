# Deploying

## Read this first: GitHub Pages will not work

This is **not a static site.** GitHub Pages, Netlify Drop, Cloudflare Pages and
friends serve files only — they cannot run `server.py`, and without it the map
is a blank world with no data.

The backend is mandatory, not a convenience:

1. **CORS.** Check Point sets
   `Access-Control-Allow-Origin: https://threatmap.checkpoint.com`. A browser on
   *your* domain is refused. Something server-side has to fetch the feed.
2. **Connection fan-out.** One upstream SSE connection is shared by every
   visitor. Without it, 50 visitors = 50 connections to Check Point.
3. **Warm state.** Rolling stats live server-side so a new tab isn't blank.

So: **GitHub for the code, a Python host for the running app.** Both are free.

---

## Recommended: Fly.io

Best fit here, for two specific reasons: it has a **Singapore region** (`sin`,
lowest latency from Johor) and it **does not scale to zero**, so the upstream
feed stays connected and your stats stay warm.

```bash
curl -L https://fly.io/install.sh | sh     # install flyctl
fly auth login
cd threatmap
fly launch --copy-config --no-deploy       # reuses the bundled fly.toml
fly deploy
fly open
```

`fly.toml` is already configured: Singapore, `auto_stop_machines = false`,
`max_machines_running = 1`, 256 MB.

---

## Alternative: Render

Simplest clicking path — it reads the bundled `render.yaml`.

1. Push to GitHub (below).
2. [render.com](https://render.com) → **New** → **Blueprint** → pick the repo.
3. Deploy.

**Free-tier caveat:** Render sleeps a free service after ~15 minutes idle. On
wake it takes ~30 s and the upstream feed reconnects from cold, so session
stats reset and the map is empty for a few seconds. Fine for a demo, annoying
for a wall display. The paid Starter tier removes it.

---

## Alternative: any VPS / Docker host

```bash
docker build -t threatmap .
docker run -d --restart=unless-stopped -p 80:8080 --name threatmap threatmap
```

Stdlib `ThreadingHTTPServer` is fine for tens of concurrent viewers. If you
expect hundreds, put nginx or Caddy in front as a TLS terminator — and make
sure you **disable proxy buffering**, or SSE will stall:

```nginx
location /api/stream {
    proxy_pass http://127.0.0.1:8080;
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 24h;
    chunked_transfer_encoding off;
}
```

The app already sends `X-Accel-Buffering: no`, which nginx honours by default.

---

## Keep it at ONE instance

Every instance opens its **own** connection to Check Point's feed. Two
instances = double the load on someone else's API for zero benefit, and
visitors see different event streams depending on which one they hit.

`fly.toml` and `render.yaml` both pin this to 1. If you move to another host,
set max instances to 1 and turn autoscaling off.

Not suitable: anything scale-to-zero and request-scoped — Vercel/Netlify
functions, AWS Lambda, Cloudflare Workers. Long-lived SSE and a persistent
upstream connection are exactly what those are designed not to do. Cloud Run
works only with `--min-instances=1 --no-cpu-throttling`.

---

## Before you deploy publicly

Worth five minutes of thought, since a public URL is different from localhost:

- **The data isn't yours.** `threatmap-api.checkpoint.com` is undocumented, has
  no published terms of use, and is CORS-locked to Check Point's own origin —
  a fairly clear signal it's meant for their page only. Running it privately is
  one thing; a public mirror that re-serves their live feed is another. If this
  is going anywhere visible, credit Check Point ThreatCloud prominently (the
  header already does) and consider emailing them first.
- **You become a traffic source.** One instance is one connection, roughly what
  a single open browser tab costs them. Keep it that way. Don't add polling
  loops or per-visitor upstream connections.
- **Don't rebrand it.** "Check Point" and "ThreatCloud" are their trademarks.
  The current header credits them as the data source, which is the right
  posture — keep it.
- **Rate-limit `/api/country/<cc>`** if the URL gets shared widely. Each miss is
  a live upstream call; the disk cache absorbs repeats, but a scraper hitting
  245 country codes in a loop would pass straight through.

None of this is legal advice — it's the practical version. A personal dashboard
or a portfolio piece is low risk. A public "live threat map" that ranks in
search results is where someone notices.
