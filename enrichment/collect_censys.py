#!/usr/bin/env python3
"""Passive Censys Platform bulk-host enrichment for original 170-IP membership matrix.

NO ACTIVE SCANNING. Uses Censys API only; preserves the JSON and requested time.
Requires an account PAT set in CENSYS_PAT. Supports optional CENSYS_ORG_ID.
Free/Starter/Search/Core tier permissions and API credits may differ.
"""
from __future__ import annotations
import argparse, csv, datetime as dt, json, os, pathlib, sys, time, urllib.error, urllib.parse, urllib.request

API = 'https://api.platform.censys.io/v3/global/asset/host'
DEFAULT_MATRIX = 'experiments/indicator_overlap/Component7_BlackApex_Indicator_Matrix.csv'

def read_ips(path):
    with open(path, newline='', encoding='utf-8-sig') as f:
        rows = list(csv.DictReader(f))
    if not rows or any(not row.get('ip') for row in rows):
        raise SystemExit(f'No valid ip column in {path}')
    ips = list(dict.fromkeys(row['ip'].strip() for row in rows))
    return ips

def request_batch(ips, token, org_id=None, at_time=None, timeout=60):
    payload = {'host_ids': ips}
    if at_time: payload['at_time'] = at_time
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.censys.api.v3.host.v1+json', 'Content-Type': 'application/json'}
    url = API
    if org_id:
        url += '?' + urllib.parse.urlencode({'organization_id': org_id})
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--matrix', default=DEFAULT_MATRIX, help='Use from GitHub repository root')
    ap.add_argument('--out-dir', default='enrichment/raw', help='Save raw response JSON locally')
    ap.add_argument('--at-time', help='Historical RFC3339 time, e.g. 2026-11-12T12:00:00Z; plan-dependent')
    ap.add_argument('--limit', type=int, default=10, help='Safety default: first 10 IPs; specify 170 for full dataset')
    ap.add_argument('--batch-size', type=int, default=50, help='Up to 100 hosts per API call')
    ap.add_argument('--pause', type=float, default=1.5, help='Seconds between API batches')
    ap.add_argument('--execute', action='store_true', help='Must set to issue API queries; otherwise dry run')
    a=ap.parse_args()
    if not 1<=a.batch_size<=100: ap.error('batch-size must be 1..100')
    ips=read_ips(a.matrix)
    selected=ips[:min(a.limit,len(ips))] if a.limit>0 else ips
    stamp=dt.datetime.now(dt.timezone.utc).isoformat()
    chunks=[selected[i:i+a.batch_size] for i in range(0,len(selected),a.batch_size)]
    print(f'{len(ips)} unique IPs in matrix; selected={len(selected)}; batches={len(chunks)}; requested_at_time={a.at_time or "current"}; execute={a.execute}')
    if not a.execute:
        print('DRY RUN only. Set CENSYS_PAT in environment and add --execute to use Censys API. API credits may apply.')
        return 0
    token=os.environ.get('CENSYS_PAT')
    if not token: ap.error('CENSYS_PAT environment variable is required for --execute; never put token in repo')
    out=pathlib.Path(a.out_dir);out.mkdir(parents=True, exist_ok=True)
    for i,chunk in enumerate(chunks,1):
        path=out/f'censys_hosts_batch_{i:02d}.json'
        if path.exists():
            old=json.loads(path.read_text(encoding='utf-8'))
            old_prov=old.get('_provenance',{})
            if old_prov.get('requested_ips')!=chunk or old_prov.get('requested_at_time')!=a.at_time:
                print(f'ERROR: {path} contains different IPs or a different historical timestamp. Use a new --out-dir or move prior files; refusing to mix or overwrite datasets.',file=sys.stderr)
                return 1
            print(f'Identical batch already exists, skipping: {path}');continue
        try:
            data=request_batch(chunk,token,os.environ.get('CENSYS_ORG_ID'),a.at_time)
        except urllib.error.HTTPError as ex:
            msg=ex.read().decode('utf-8','replace')[:300]
            print(f'ERROR batch {i}: HTTP {ex.code} {msg}',file=sys.stderr)
            if ex.code in (401,403,409,429):
                print('Stopped rather than retrying potentially billed or forbidden calls.',file=sys.stderr)
                return 1
            return 1
        path.write_text(json.dumps({'_provenance':{'source':'Censys Platform API v3 bulk host lookup','retrieved_at_utc':stamp,'requested_at_time':a.at_time,'requested_ips':chunk},'api_response':data},indent=2),encoding='utf-8')
        print(f'Saved {path}')
        if i<len(chunks):time.sleep(a.pause)
    return 0

if __name__=='__main__':raise SystemExit(main())
