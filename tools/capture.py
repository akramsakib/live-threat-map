#!/usr/bin/env python3
"""
Capture a real slice of the ThreatCloud feed for static hosting.

Writes everything the GitHub Pages build needs:
  data/feed.json       - enriched attack events with relative timings
  data/stats.json      - day counter, 31-day series, measured rates
  data/topstats.json   - daily leaderboard
  data/coverage.json   - which countries report, and their 7-day rate
  data/countries/XX.json - 31-day trend + malware mix, per reporting country

Usage:  python3 tools/capture.py [--seconds 150] [--out docs/data]
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

BASE = "https://threatmap-api.checkpoint.com/ThreatMap/api/"
HDRS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Origin": "https://threatmap.checkpoint.com",
    "Referer": "https://threatmap.checkpoint.com/",
}
# MaxMind's documented country-level placeholder for the US - the coordinate
# returned for 8.8.8.8 with a 1000 km accuracy radius. Not an attack origin.
CENTROIDS = {(37.751, -97.822): "US"}


def get_json(path, timeout=25):
    req = urllib.request.Request(BASE + path, headers=HDRS)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def enrich(d):
    try:
        s_la, s_lo = float(d["s_la"]), float(d["s_lo"])
        d_la, d_lo = float(d["d_la"]), float(d["d_lo"])
    except (TypeError, ValueError, KeyError):
        return None
    src, dst = d.get("s_co") or "??", d.get("d_co") or "??"
    key = (round(s_la, 3), round(s_lo, 3))
    if key in CENTROIDS:
        precision = "country"
    elif d.get("s_s"):
        precision = "region"
    else:
        precision = "city?"
    return {
        "name": d.get("a_n") or "Unknown",
        "type": (d.get("a_t") or "exploit").lower(),
        "count": d.get("a_c") or 1,
        "src": {"co": src, "la": s_la, "lo": s_lo},
        "dst": {"co": dst, "la": d_la, "lo": d_lo},
        "precision": precision,
        "circular": src == dst,
    }


def capture_feed(seconds):
    """Read the SSE stream for `seconds`, returning (events, counters)."""
    events, counters = [], []
    t0 = time.monotonic()
    req = urllib.request.Request(
        BASE + "feed", headers={**HDRS, "Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=seconds + 30) as r:
            fields = {}
            for raw in r:
                if time.monotonic() - t0 > seconds:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    if "data" in fields:
                        try:
                            d = json.loads(fields["data"])
                        except Exception:
                            fields = {}
                            continue
                        if "a_t" in d:
                            ev = enrich(d)
                            if ev:
                                ev["t"] = int((time.monotonic() - t0) * 1000)
                                events.append(ev)
                        elif "today" in d:
                            counters.append((time.monotonic() - t0, d))
                    fields = {}
                    continue
                if line.startswith(":"):
                    continue
                k, _, v = line.partition(":")
                if v.startswith(" "):
                    v = v[1:]
                fields[k] = fields.get(k, "") + v if k == "data" else v
    except Exception as e:
        print(f"  ! feed read ended: {type(e).__name__}: {e}", file=sys.stderr)
    return events, counters



def merge_feeds(old, new, cap):
    """Accumulate captures so country coverage grows over time.

    A single window only ever contains a few dozen countries, which makes the
    country filter look broken. Merging successive runs fixes that - but a
    naive FIFO would just fill up with the US and Brazil, which dominate every
    window. So when trimming we drop events from the most over-represented
    countries first, preserving rare ones.
    """
    for i, e in enumerate(old):
        e["_b"] = e.get("_b", 0)
    for e in new:
        e["_b"] = 1_000_000
    merged = old + new

    if len(merged) > cap:
        freq = Counter(e["dst"]["co"] for e in merged)
        # walk from the most common country down, dropping its oldest events
        drop = set()
        need = len(merged) - cap
        for cc, _ in freq.most_common():
            if need <= 0:
                break
            idxs = [i for i, e in enumerate(merged)
                    if e["dst"]["co"] == cc and i not in drop]
            # never drop a country below 3 events - keeps the map varied
            spare = max(0, len(idxs) - 3)
            for i in idxs[:min(spare, need)]:
                drop.add(i)
                need -= 1
        merged = [e for i, e in enumerate(merged) if i not in drop]
        if len(merged) > cap:
            merged = merged[-cap:]

    # re-time: keep each batch's internal pacing, 800 ms between batches
    gt, pb, pt = 0, None, None
    for e in merged:
        ot = e.get("t", 0)
        if e["_b"] != pb or pt is None:
            gap = 800 if pb is not None else 0
        else:
            gap = max(0, min(ot - pt, 4000))
        gt += gap
        pb, pt = e["_b"], ot
        e["t"] = gt
    for e in merged:
        e.pop("_b", None)
    return merged


def fetch_old(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "capture.py"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read().decode())
        return d if isinstance(d, list) else []
    except Exception as e:
        print(f"  (no previous feed to merge: {type(e).__name__})")
        return []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--out", default="docs/data")
    ap.add_argument("--merge-url", default="",
                    help="URL of a previously published feed.json to accumulate with")
    ap.add_argument("--cap", type=int, default=2000,
                    help="max events to keep after merging")
    a = ap.parse_args()
    out = a.out
    os.makedirs(os.path.join(out, "countries"), exist_ok=True)

    print(f"capturing {a.seconds}s of live feed …")
    events, counters = capture_feed(a.seconds)
    print(f"  {len(events)} attack events, {len(counters)} counter frames")
    if not events:
        print("  ! no events captured - aborting so we don't publish an empty map",
              file=sys.stderr)
        return 1

    counter = counters[-1][1] if counters else {}
    rp = counter.get("recentPeriod") or []

    # measured upstream rate; fall back to the 31-day daily mean
    rate = 0.0
    if len(counters) >= 2:
        (t0, c0), (t1, c1) = counters[0], counters[-1]
        if t1 - t0 > 60 and c1.get("today", 0) >= c0.get("today", 0):
            rate = (c1["today"] - c0["today"]) / (t1 - t0)
    if rate <= 0 and rp:
        rate = sum(rp) / len(rp) / 86400.0

    span = max((events[-1]["t"] - events[0]["t"]) / 1000.0, 1)
    drawn = len(events) / span

    stats = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "window_seconds": a.seconds,
        "events": len(events),
        "today": counter.get("today"),
        "daily": rp,
        "daily_avg": round(sum(rp) / len(rp)) if rp else None,
        "rate_counted": round(rate, 1),
        "rate_drawn": round(drawn, 2),
        "visible_pct": round(100 * drawn / rate, 2) if rate > 0 else None,
        "unresolved_pct": round(
            100 * sum(1 for e in events if e["precision"] == "country") / len(events), 1),
        "circular_pct": round(
            100 * sum(1 for e in events if e["circular"]) / len(events), 1),
        "types": Counter(e["type"] for e in events).most_common(),
    }

    if a.merge_url:
        old = fetch_old(a.merge_url)
        before = len(set(e["dst"]["co"] for e in events) |
                     set(e["src"]["co"] for e in events))
        events = merge_feeds(old, events, a.cap)
        after = len(set(e["dst"]["co"] for e in events) |
                    set(e["src"]["co"] for e in events))
        print(f"  merged with {len(old)} previous -> {len(events)} events, "
              f"countries {before} -> {after}")
        stats["events"] = len(events)
        stats["countries"] = after
        stats["merged"] = True

    json.dump(events, open(f"{out}/feed.json", "w"), separators=(",", ":"))
    json.dump(stats, open(f"{out}/stats.json", "w"), indent=1)

    print("fetching topStats …")
    try:
        json.dump(get_json("topStats"), open(f"{out}/topstats.json", "w"))
    except Exception as e:
        print(f"  ! topStats failed: {e}", file=sys.stderr)

    # coverage: reuse the committed probe result for the country list
    cov_src = "static/coverage.json"
    codes = sorted(json.load(open(cov_src)).keys()) if os.path.exists(cov_src) else []
    print(f"refreshing {len(codes)} country series …")

    def one(cc):
        try:
            return cc, get_json("countries/" + cc)
        except urllib.error.HTTPError as e:
            return cc, (None if e.code == 404 else "skip")
        except Exception:
            return cc, "skip"

    cov, ok, gone = {}, 0, 0
    with ThreadPoolExecutor(max_workers=6) as ex:
        for cc, d in ex.map(one, codes):
            if d == "skip":
                continue
            if d is None:
                cov[cc] = None
                gone += 1
                continue
            arr = d["trend"]["attacks"]
            cov[cc] = {"last7": round(sum(arr[:7]) / 7, 1),
                       "avg31": round(sum(arr) / len(arr), 1),
                       "latest": arr[0]}
            json.dump(d, open(f"{out}/countries/{cc}.json", "w"),
                      separators=(",", ":"))
            ok += 1
    if cov:
        json.dump(cov, open(f"{out}/coverage.json", "w"), separators=(",", ":"))
    print(f"  {ok} countries with data, {gone} returning 404")

    print(f"\ncaptured {len(events)} events over {span:.0f}s")
    print(f"  visible      : {stats['visible_pct']}%  "
          f"({stats['rate_drawn']}/s drawn vs {stats['rate_counted']}/s counted)")
    print(f"  unknown orig : {stats['unresolved_pct']}%")
    print(f"  circular     : {stats['circular_pct']}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
