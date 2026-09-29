#!/usr/bin/env python3
"""
Assemble the static GitHub Pages build in docs/.

Takes the single source-of-truth UI (static/index.html), injects the replay
config, and copies the map assets alongside whatever tools/capture.py produced.

Usage:  python3 tools/build_static.py
"""
import json
import os
import re
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "static")
OUT = os.path.join(ROOT, "docs")

ASSETS = ["world.json", "coverage.json", "countries.json", "dots.json"]


def main():
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(os.path.join(OUT, "data"), exist_ok=True)

    # 1. assets
    for a in ASSETS:
        shutil.copy2(os.path.join(SRC, a), os.path.join(OUT, a))

    # a fresh capture ships its own coverage.json - prefer it
    cap_cov = os.path.join(OUT, "data", "coverage.json")
    if os.path.exists(cap_cov):
        shutil.copy2(cap_cov, os.path.join(OUT, "coverage.json"))

    flags_dst = os.path.join(OUT, "flags")
    if not os.path.isdir(flags_dst):
        shutil.copytree(os.path.join(SRC, "flags"), flags_dst)

    # 2. UI with replay config injected
    html = open(os.path.join(SRC, "index.html"), encoding="utf-8").read()
    cfg = {"mode": "replay", "base": ".", "api": None}
    inject = ("<script>window.__CFG__=" +
              json.dumps(cfg, separators=(",", ":")) + ";</script>\n<script>")
    assert "<script>" in html, "no <script> tag found"
    html = html.replace("<script>", inject, 1)

    # 3. honest banner about what replay means
    stats_path = os.path.join(OUT, "data", "stats.json")
    note = ""
    if os.path.exists(stats_path):
        s = json.load(open(stats_path))
        note = (f"Replaying {s.get('events', '?')} real ThreatCloud events "
                f"captured {s.get('captured_at', '?')}. Country trends and "
                f"rankings are live-fetched daily data.")
    html = html.replace("</body>", f"""<div id="replaynote" style="position:fixed;left:50%;
transform:translateX(-50%);bottom:56px;z-index:30;background:rgba(227,168,30,.12);
border:1px solid rgba(227,168,30,.35);color:#e3a81e;font-size:10.5px;padding:6px 13px;
border-radius:14px;letter-spacing:.03em;max-width:90vw;text-align:center"
onclick="this.remove()" title="click to dismiss">{note} &nbsp;·&nbsp; For a genuinely
live stream, run server.py and open with ?api=https://your-host/api</div>
<script>setTimeout(()=>{{const n=document.getElementById('replaynote');
if(n)n.style.transition='opacity .6s',n.style.opacity='0',setTimeout(()=>n.remove(),700);}},14000);
</script></body>""")

    open(os.path.join(OUT, "index.html"), "w", encoding="utf-8").write(html)

    # 4. Jekyll would eat directories; tell Pages to serve verbatim
    open(os.path.join(OUT, ".nojekyll"), "w").write("")

    n_flags = len(os.listdir(flags_dst))
    n_ctry = len(os.listdir(os.path.join(OUT, "data", "countries"))) \
        if os.path.isdir(os.path.join(OUT, "data", "countries")) else 0
    total = sum(os.path.getsize(os.path.join(dp, f))
                for dp, _, fs in os.walk(OUT) for f in fs)
    print(f"built docs/  ({total/1048576:.1f} MB)")
    print(f"  flags: {n_flags} | country series: {n_ctry}")
    if os.path.exists(os.path.join(OUT, "data", "feed.json")):
        print(f"  feed events: {len(json.load(open(os.path.join(OUT,'data','feed.json'))))}")
    else:
        print("  ! no data/feed.json - run tools/capture.py first", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
