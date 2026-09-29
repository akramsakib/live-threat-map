import json, urllib.request, concurrent.futures as cf, time
world=json.load(open('static/world.json'))
codes=sorted({w['c'] for w in world})
BASE="https://threatmap-api.checkpoint.com/ThreatMap/api/countries/"
def get(cc):
    req=urllib.request.Request(BASE+cc, headers={
        "User-Agent":"Mozilla/5.0","Origin":"https://threatmap.checkpoint.com",
        "Referer":"https://threatmap.checkpoint.com/"})
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return cc, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code==404: return cc, None
            time.sleep(1)
        except Exception:
            time.sleep(1)
    return cc, None
res={}
with cf.ThreadPoolExecutor(max_workers=6) as ex:
    for cc,d in ex.map(get, codes):
        res[cc]=d
cov={}; cache={}
for cc,d in res.items():
    if d is None: cov[cc]=None; continue
    a=d['trend']['attacks']
    cov[cc]={"last7":round(sum(a[:7])/7,1),"avg31":round(sum(a)/len(a),1),"latest":a[0]}
    cache[cc]=d
json.dump(cov, open('static/coverage.json','w'), separators=(',',':'))
json.dump(cache, open('country_cache.json','w'), separators=(',',':'))
have=[c for c,v in cov.items() if v]
print(f"probed {len(codes)} | data {len(have)} | no data {len(codes)-len(have)}")
print("no-data sample:", sorted(c for c,v in cov.items() if not v)[:40])
