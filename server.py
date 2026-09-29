#!/usr/bin/env python3
"""
Honest Threat Map - server
--------------------------
Dependency-free (Python stdlib only) backend for a live cyber-attack map.

It maintains ONE upstream Server-Sent-Events connection to Check Point's
ThreatCloud feed, enriches every event with provenance metadata, and fans the
result out to any number of browser clients.

Why the proxy exists:
  * Check Point's API sets Access-Control-Allow-Origin to its own origin only,
    so a browser cannot read the feed directly.
  * Enrichment (geolocation-confidence, circular detection, sampling ratio)
    has to happen somewhere. Doing it server-side means late-joining clients
    inherit warm statistics instead of an empty screen.
"""

import json
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

UPSTREAM = "https://threatmap-api.checkpoint.com/ThreatMap/api/"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Origin": "https://threatmap.checkpoint.com",
    "Referer": "https://threatmap.checkpoint.com/",
    "Accept": "text/event-stream",
}

# Verified IP-geolocation country-level centroids. When a source resolves to one
# of these, the provider is saying "this IP is in that country, exact location
# unknown" - it is NOT a real attack origin. 37.751/-97.822 is MaxMind's
# documented US default (the coordinate famously returned for 8.8.8.8 with a
# 1000 km accuracy radius).
COUNTRY_CENTROIDS = {
    (37.751, -97.822): "US",
}

PORT = int(os.environ.get("PORT", "3000"))


# --------------------------------------------------------------------------
# Rolling state shared by every connected browser
# --------------------------------------------------------------------------
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.clients = []                 # list[queue.Queue]
        self.seq = 0

        self.targets = Counter()
        self.sources = Counter()
        self.sigs = Counter()
        self.types = Counter()

        self.total_drawn = 0
        self.unresolved = 0
        self.circular = 0
        self.src_points = set()
        self.dst_points = set()

        self.recent = deque(maxlen=60)    # ticker
        self.draw_times = deque(maxlen=400)

        self.counter = None               # last counter payload
        self.counter_hist = deque(maxlen=200)  # (monotonic, today)
        self.started = time.time()
        self.upstream_ok = False
        self.reconnects = 0

    # -- fan-out ---------------------------------------------------------
    def subscribe(self):
        q = queue.Queue(maxsize=600)
        with self.lock:
            self.clients.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.clients:
                self.clients.remove(q)

    def broadcast(self, event, payload):
        msg = f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"
        with self.lock:
            dead = []
            for q in self.clients:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    try:            # drop the oldest frame, keep the stream live
                        q.get_nowait()
                        q.put_nowait(msg)
                    except Exception:
                        dead.append(q)
            for q in dead:
                self.clients.remove(q)

    # -- ingestion -------------------------------------------------------
    def on_attack(self, d):
        try:
            s_la, s_lo = float(d["s_la"]), float(d["s_lo"])
            d_la, d_lo = float(d["d_la"]), float(d["d_lo"])
        except (TypeError, ValueError, KeyError):
            return None

        src_co = d.get("s_co") or "??"
        dst_co = d.get("d_co") or "??"
        key = (round(s_la, 3), round(s_lo, 3))

        centroid_for = COUNTRY_CENTROIDS.get(key)
        if centroid_for:
            precision = "country"       # origin genuinely unknown
        elif d.get("s_s"):
            precision = "region"        # subdivision resolved
        else:
            precision = "city?"

        circular = src_co == dst_co

        with self.lock:
            self.seq += 1
            ev = {
                "id": self.seq,
                "name": d.get("a_n") or "Unknown",
                "type": (d.get("a_t") or "exploit").lower(),
                "count": d.get("a_c") or 1,
                "src": {"co": src_co, "la": s_la, "lo": s_lo, "s": d.get("s_s")},
                "dst": {"co": dst_co, "la": d_la, "lo": d_lo, "s": d.get("d_s")},
                "precision": precision,
                "circular": circular,
                "ts": time.time(),
            }
            self.total_drawn += 1
            self.targets[dst_co] += 1
            self.sources[src_co] += 1
            self.sigs[ev["name"]] += 1
            self.types[ev["type"]] += 1
            if precision == "country":
                self.unresolved += 1
            if circular:
                self.circular += 1
            self.src_points.add(key)
            self.dst_points.add((round(d_la, 3), round(d_lo, 3)))
            self.recent.appendleft({
                "id": ev["id"], "name": ev["name"], "type": ev["type"],
                "src": src_co, "dst": dst_co, "precision": precision,
                "circular": circular,
            })
            self.draw_times.append(time.monotonic())
        return ev

    def on_counter(self, d):
        with self.lock:
            self.counter = d
            self.counter_hist.append((time.monotonic(), d.get("today", 0)))

    # -- derived numbers -------------------------------------------------
    def _rates(self):
        """(drawn events/sec, upstream counted attacks/sec).

        The upstream counter advances in lumpy batches every ~30-60 s, so a
        short window makes the headline ratio jitter wildly. We only trust the
        live delta once we have a long enough baseline, and fall back to the
        31-day daily average until then.
        """
        drawn = 0.0
        if len(self.draw_times) >= 2:
            span = self.draw_times[-1] - self.draw_times[0]
            if span > 3:
                drawn = (len(self.draw_times) - 1) / span

        counted = 0.0
        h = list(self.counter_hist)
        if len(h) >= 2:
            t0, v0 = h[0]
            t1, v1 = h[-1]
            if t1 - t0 >= 180 and v1 >= v0:      # need >=3 min to be stable
                counted = (v1 - v0) / (t1 - t0)
        if counted <= 0 and self.counter:
            rp = self.counter.get("recentPeriod") or []
            if rp:
                counted = (sum(rp) / len(rp)) / 86400.0

        # exponential smoothing so the headline number doesn't flicker
        if counted > 0:
            prev = getattr(self, "_sm_counted", None)
            self._sm_counted = counted if prev is None else prev * 0.85 + counted * 0.15
            counted = self._sm_counted
        return drawn, counted

    def snapshot(self, full=False):
        with self.lock:
            drawn, counted = self._rates()
            tot = max(self.total_drawn, 1)
            rp = (self.counter or {}).get("recentPeriod") or []
            return {
                "uptime": round(time.time() - self.started),
                "upstream": self.upstream_ok,
                "reconnects": self.reconnects,
                "drawn": self.total_drawn,
                "rate_drawn": round(drawn, 2),
                "rate_counted": round(counted, 1),
                "visible_pct": round(100 * drawn / counted, 2) if counted > 0 else None,
                "unresolved_pct": round(100 * self.unresolved / tot, 1),
                "circular_pct": round(100 * self.circular / tot, 1),
                "n_src_points": len(self.src_points),
                "n_dst_points": len(self.dst_points),
                "types": self.types.most_common(),
                "targets": self.targets.most_common(10),
                "sources": self.sources.most_common(10),
                "sigs": self.sigs.most_common(10),
                "recent": list(self.recent)[:16],
                "today": (self.counter or {}).get("today"),
                # the 31-day series is static-ish; only ship it on connect
                "daily": rp if full else None,
                "daily_avg": round(sum(rp) / len(rp)) if rp else None,
            }


STATE = State()


# --------------------------------------------------------------------------
# Upstream reader
# --------------------------------------------------------------------------
def upstream_loop():
    backoff = 2
    while True:
        try:
            req = urllib.request.Request(UPSTREAM + "feed", headers=HEADERS)
            with urllib.request.urlopen(req, timeout=90) as r:
                STATE.upstream_ok = True
                backoff = 2
                fields = {}
                for raw in r:
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if line == "":                      # end of event block
                        if "data" in fields:
                            _dispatch(fields)
                        fields = {}
                        continue
                    if line.startswith(":"):            # keep-alive comment
                        continue
                    k, _, v = line.partition(":")
                    if v.startswith(" "):
                        v = v[1:]
                    fields[k] = fields.get(k, "") + v if k == "data" else v
        except Exception as e:
            STATE.upstream_ok = False
            STATE.reconnects += 1
            STATE.broadcast("status", {"upstream": False, "error": str(e)[:160]})
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


def _dispatch(fields):
    try:
        d = json.loads(fields["data"])
    except Exception:
        return
    kind = fields.get("event")
    if kind == "counter" or ("today" in d and "a_t" not in d):
        STATE.on_counter(d)
        STATE.broadcast("counter", d)
    else:
        ev = STATE.on_attack(d)
        if ev:
            STATE.broadcast("attack", ev)


def stats_loop():
    """Push a derived-stats frame once a second."""
    while True:
        time.sleep(1.0)
        try:
            STATE.broadcast("stats", STATE.snapshot())
        except Exception:
            pass


# --------------------------------------------------------------------------
# Country data (disk cache + lazy refresh)
# --------------------------------------------------------------------------
CACHE_PATH = os.path.join(HERE, "country_cache.json")
try:
    COUNTRY_CACHE = json.load(open(CACHE_PATH))
except Exception:
    COUNTRY_CACHE = {}
_cache_lock = threading.Lock()


def fetch_country(cc):
    cc = cc.upper()
    if not re.fullmatch(r"[A-Z]{2}", cc):
        return None
    try:
        req = urllib.request.Request(
            UPSTREAM + "countries/" + cc,
            headers={k: v for k, v in HEADERS.items() if k != "Accept"})
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read().decode())
        with _cache_lock:
            COUNTRY_CACHE[cc] = d
        return d
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return COUNTRY_CACHE.get(cc)
    except Exception:
        return COUNTRY_CACHE.get(cc)


def fetch_topstats():
    try:
        req = urllib.request.Request(
            UPSTREAM + "topStats",
            headers={k: v for k, v in HEADERS.items() if k != "Accept"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript",
        ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HonestThreatMap"

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"

        if path == "/" or path == "/index.html":
            return self._file(os.path.join(STATIC, "index.html"))

        if path == "/healthz":
            # Liveness for PaaS health checks. Reports upstream state but stays
            # 200 while reconnecting, so a brief upstream blip doesn't get the
            # container killed and restarted.
            return self._json({
                "ok": True,
                "upstream": STATE.upstream_ok,
                "reconnects": STATE.reconnects,
                "events": STATE.total_drawn,
                "uptime": round(time.time() - STATE.started),
            })

        if path == "/api/stream":
            return self.sse()

        if path == "/api/stats":
            return self._json(STATE.snapshot(full=True))

        if path == "/api/topstats":
            return self._json(fetch_topstats())

        if path.startswith("/api/country/"):
            cc = path.rsplit("/", 1)[-1]
            d = fetch_country(cc)
            if d is None:
                return self._json({"error": "no coverage", "code": cc.upper()}, 404)
            return self._json(d)

        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            # allow one level of nesting (flags/xx.svg) but never escape STATIC
            safe = os.path.normpath(os.path.join(STATIC, rel))
            if not safe.startswith(os.path.abspath(STATIC) + os.sep):
                return self._send(403, b"forbidden", "text/plain")
            return self._file(safe)

        self._send(404, b"not found", "text/plain")

    def _file(self, p):
        if not os.path.isfile(p):
            return self._send(404, b"not found", "text/plain")
        ext = os.path.splitext(p)[1]
        with open(p, "rb") as f:
            body = f.read()
        self._send(200, body, MIME.get(ext, "application/octet-stream"))

    # -- SSE to the browser ---------------------------------------------
    def sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = STATE.subscribe()
        try:
            warm = STATE.snapshot(full=True)
            self.wfile.write(
                f"event: stats\ndata: {json.dumps(warm, separators=(',', ':'))}\n\n"
                .encode())
            self.wfile.flush()
            last_ping = time.monotonic()
            while True:
                try:
                    msg = q.get(timeout=5)
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
                except queue.Empty:
                    if time.monotonic() - last_ping > 10:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        last_ping = time.monotonic()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            STATE.unsubscribe(q)


def main():
    threading.Thread(target=upstream_loop, daemon=True).start()
    threading.Thread(target=stats_loop, daemon=True).start()

    def persist():
        while True:
            time.sleep(120)
            try:
                with _cache_lock:
                    json.dump(COUNTRY_CACHE, open(CACHE_PATH, "w"),
                              separators=(",", ":"))
            except Exception:
                pass
    threading.Thread(target=persist, daemon=True).start()

    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    print(f"Honest Threat Map listening on 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
