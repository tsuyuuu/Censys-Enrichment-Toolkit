#!/usr/bin/env python3
"""Analyze the 170-IP Censys sample with honest unknown/evaluable denominators.

Offline; no network. Uses original matrix plus optional raw Censys JSON files.
Does NOT execute JavaScript, visit websites, or claim related-host maliciousness.
"""
from __future__ import annotations
import argparse, collections, csv, datetime as dt, hashlib, ipaddress, json, pathlib, re, sys

DEFAULT_MATRIX = 'experiments/indicator_overlap/Component7_BlackApex_Indicator_Matrix.csv'

def read_csv(path):
    with open(path,newline='',encoding='utf-8-sig') as f:return list(csv.DictReader(f))

def as_hostlist(o):
    """Unwrap Censys Platform v3 bulk result records and single-host records.

    Expected bulk shape: {"result": [{"resource": {"ip": ..., ...}}, ...]}.
    Recurses into lists rather than silently dropping the records.
    """
    if isinstance(o, list):
        hosts = []
        for entry in o:
            hosts.extend(as_hostlist(entry))
        return hosts
    if not isinstance(o, dict):
        return []
    if 'api_response' in o:
        return as_hostlist(o['api_response'])
    if 'resource' in o and isinstance(o['resource'], dict):
        return as_hostlist(o['resource'])
    if 'result' in o:
        return as_hostlist(o['result'])
    for key in ('resources', 'hosts', 'items', 'data'):
        x = o.get(key)
        if isinstance(x, list):
            return as_hostlist(x)
        if isinstance(x, dict):
            if 'ip' in x or 'resource' in x or 'result' in x:
                return as_hostlist(x)
            return as_hostlist([dict(v, ip=v.get('ip', ip)) for ip, v in x.items() if isinstance(v, dict)])
    if 'ip' in o and isinstance(o.get('services', []), list):
        return [o]
    if 'error' in o or 'errors' in o:
        raise ValueError('Censys API returned an error: ' + str(o.get('error') or o.get('errors'))[:400])
    raise ValueError('Unrecognized Censys JSON shape; inspect response keys '+str(list(o.keys())[:15]))

def iter_eps(host):
    """Yield (service, endpoint, http, path) with flexible documented service nesting."""
    for service in host.get('services') or []:
        if not isinstance(service,dict):continue
        eps=service.get('endpoints') or []
        if isinstance(eps,dict):eps=list(eps.values())
        if not isinstance(eps,list): continue
        for ep in eps:
            if not isinstance(ep,dict):continue
            http=ep.get('http') or {}
            if not isinstance(http,dict):continue
            u=ep.get('url') or ep.get('uri') or ep.get('path') or http.get('uri') or http.get('path') or ''
            if isinstance(u,dict):u=u.get('path') or u.get('uri') or ''
            yield service,ep,http,str(u)

def kind_from_path(path):
    clean=path.split('?',1)[0].rstrip('/').lower()
    if clean.endswith('/sitemap.xml') or clean=='sitemap.xml':return 'sitemap.xml'
    if clean.endswith('/robots.txt') or clean=='robots.txt':return 'robots.txt'
    return None

def normalize(b,kind):
    s=b.decode('utf-8')
    if kind=='sitemap.xml':
        out,n=re.subn(r'(?<=<loc>)https?://[^/<>\s]+','https://<DOMAIN>',s)
    elif kind=='robots.txt':
        out,n=re.subn(r'(?im)^(Sitemap:\s*)https?://[^/\s]+',lambda m:m.group(1)+'https://<DOMAIN>',s)
    else: raise ValueError(kind)
    if n!=1:raise ValueError(f'{kind}: expected exactly one hostname; found {n}')
    return out.encode('utf-8')

def body_bytes(http):
    x=http.get('body')
    if isinstance(x,str):return x.encode('utf-8')
    # Do NOT guess decoding of 'base64' or truncated responses; mark non-evaluable.
    return None

def get_title(http):
    for k in ('title','html_title'):
        if isinstance(http.get(k),str) and http[k].strip():return http[k].strip()
    # Some platform versions expose parsed HTML title at http.html.title
    html=http.get('html')
    if isinstance(html,dict) and isinstance(html.get('title'),str):return html['title'].strip()
    return None

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--matrix',default=DEFAULT_MATRIX)
    ap.add_argument('--raw-dir',default='enrichment/raw')
    ap.add_argument('--out-dir',default='enrichment/results')
    ap.add_argument('--reference-dir',default='experiments/structural/samples')
    ap.add_argument('--require-full-170',action='store_true',help='Fail if any IP missing from Censys data')
    a=ap.parse_args()
    rows=read_csv(a.matrix)
    ips={r['ip'] for r in rows}
    if len(rows)!=170 or len(ips)!=170:print(f'NOTE original dataset expected 170 IPs, got {len(rows)} rows / {len(ips)} distinct',file=sys.stderr)
    byip={}
    manifests=[]
    for f in sorted(pathlib.Path(a.raw_dir).glob('*.json')):
        obj=json.loads(f.read_text(encoding='utf-8'))
        provenance=obj.get('_provenance',{}) if isinstance(obj,dict) else {}
        for h in as_hostlist(obj):
            ip=str(h.get('ip') or '')
            if ip not in ips:continue
            if ip in byip:
                raise ValueError(f'Duplicate host {ip} from {f}; use one snapshot per IP to prevent mixed-time aggregation')
            byip[ip]=(h,provenance)
            manifests.append({'ip':ip,'file':str(f),'retrieved_at_utc':provenance.get('retrieved_at_utc'),'at_time':provenance.get('requested_at_time')})
    if a.require_full_170 and set(byip)!=ips:raise SystemExit(f'Missing {len(ips-set(byip))} Censys records')
    root=pathlib.Path(a.reference_dir)
    refs={'sitemap.xml':root/'192_166_82_111_https443_sitemap.xml','robots.txt':root/'192_166_82_111_port5000_robots.txt'}
    ref_hash={}
    expected_sha = {
        'sitemap.xml': '5ec645bf49961d0f1b14e5ddc354e44df42b75b4451c19c6362e6a1d829a917f',
        'robots.txt': '831a8dec4cd5c41ec5f7cb61e9add4e547d564f207f75c053aee19f6f0cf6135',
    }
    for kind,path in refs.items():
        if path.exists():
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_sha[kind]:
                raise SystemExit(f'Reference integrity check failed for {path}')
            ref_hash[kind] = hashlib.sha256(normalize(raw,kind)).hexdigest()
        else:
            print(f'WARNING: reference file missing: {path}; {kind} normalized comparisons will be unavailable', file=sys.stderr)

    members=collections.Counter(); labels=collections.Counter(); prefixes=collections.Counter(); memberpub=collections.Counter()
    enrich=[]; per_match=[]; template_eval=[]; asns=collections.Counter(); countries=collections.Counter(); titles=collections.Counter(); ports=collections.Counter()
    for row in rows:
        ip=row['ip']; a1=row['sitemap_hash_A']=='Yes';b1=row['robots_hash_B']=='Yes';c1=row['javascript_text_C']=='Yes'
        m=''.join(x for x,on in [('A',a1),('B',b1),('C',c1)] if on)
        members[m]+=1; memberpub[(m,'published' if row['published_ioc']=='Yes' else 'unlisted')]+=1
        labels[row['published_label']]+=1
        prefixes[str(ipaddress.ip_network(ip+'/24',strict=False))]+=1
        h,prov=byip.get(ip,({},{}))
        loc=h.get('location') or {};aut=h.get('autonomous_system') or {}
        if not isinstance(loc,dict):loc={}
        if not isinstance(aut,dict):aut={}
        asn=aut.get('asn'); asn_name=aut.get('name') or aut.get('description')
        country=loc.get('country') or loc.get('country_code')
        services=h.get('services') or []
        openports=sorted({s.get('port') for s in services if isinstance(s,dict) and isinstance(s.get('port'),int)})
        ep_titles={get_title(http) for _,_,http,_ in iter_eps(h)} - {None}
        ept=[str(t) for t in sorted(ep_titles)]
        if asn is not None:asns[f'AS{asn} | {asn_name or "unknown"}']+=1
        if country:countries[str(country)]+=1
        for p in openports:ports[str(p)]+=1
        for t in ept:titles[t]+=1
        enrich.append({'ip':ip,'published_ioc':row['published_ioc'],'label':row['published_label'],'indicator_membership':m,
           'has_censys_record':bool(h),'requested_at_time':prov.get('requested_at_time') or '', 'asn':asn or '', 'asn_name':asn_name or '', 'country':country or '',
           'open_ports':';'.join(map(str,openports)) if h else '', 'tcp5000_exposed':'Yes' if 5000 in openports else ('No' if h else 'Unknown'),
           'http_titles':' | '.join(ept) if ept else '', 'http_title_observed':'Yes' if ept else ('No title in accessible response' if h else 'Unknown')})
        # Crucial: numerator and denominator count ONLY independently captured, hash-verified byte resources.
        if not h:continue
        seen_kinds=set()
        for service,ep,http,path in iter_eps(h):
            kind=kind_from_path(path)
            if not kind:continue
            seen_kinds.add(kind)
            meta_hash=http.get('body_hash_sha256')
            body=body_bytes(http)
            status='missing_body'; matching=''
            raw_hash=''
            if body is not None:
                raw_hash=hashlib.sha256(body).hexdigest()
                if not (isinstance(meta_hash,str) and raw_hash==meta_hash.lower()):
                    status='body_not_hash_verified'
                else:
                    try:
                        nh=hashlib.sha256(normalize(body,kind)).hexdigest()
                        if kind not in ref_hash:
                            status='reference_unavailable'
                        else:
                            status='evaluable'
                            matching='Yes' if nh==ref_hash[kind] else 'No'
                    except (ValueError,UnicodeError) as ex:
                        status='normalization_rejected'
            template_eval.append({'ip':ip,'resource':kind,'port':service.get('port',''),'path':path,
                                  'body_status':status,'censys_recorded_body_hash':meta_hash or '', 'local_sha256':raw_hash,
                                  'normalized_match_reference':matching,'scan_time':service.get('scan_time','')})

    out=pathlib.Path(a.out_dir);out.mkdir(parents=True,exist_ok=True)
    def write_csv(filename, data):
        if not data:return
        with (out/filename).open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=list(data[0].keys()));w.writeheader();w.writerows(data)
    write_csv('hosts_enriched.csv',enrich)
    write_csv('template_evaluation.csv',template_eval)
    write_csv('provenance_manifest.csv',manifests)
    tested_hosts={x['ip'] for x in template_eval if x['body_status']=='evaluable'}
    matched_hosts={x['ip'] for x in template_eval if x['normalized_match_reference']=='Yes'}
    unlisted={r['ip'] for r in rows if r['published_ioc']=='No'}
    summary={
       'analysis_type':'offline Censys host dataset analysis','n_original_distinct_ips':len(ips),
       'n_censys_host_records_loaded':len(byip),'n_censys_host_records_missing':len(ips-set(byip)),
       'n_unique_24_prefixes':len(prefixes),'n_prefixes_with_multiple_recovered_ips':sum(1 for v in prefixes.values() if v>1),
       'indicator_combinations':dict(members),'indicator_combinations_by_label':{m:{'published':memberpub[(m,'published')],'unlisted':memberpub[(m,'unlisted')]} for m in sorted(members)},
       'published_panel_labels':dict(labels),'top_24_prefixes':prefixes.most_common(15),
       'host_enrichment_coverage':{'asn':sum(bool(x['asn']) for x in enrich),'country':sum(bool(x['country']) for x in enrich),
          'ports':sum(x['has_censys_record'] for x in enrich),'http_title_with_value':sum(bool(x['http_titles']) for x in enrich)},
       'asn_distribution_observed_only':dict(asns.most_common()),'country_distribution_observed_only':dict(countries.most_common()),
       'open_port_prevalence_among_returned_hosts':dict(ports.most_common()),'title_distribution_observed_only':dict(titles.most_common()),
       'template_population':{'total_unlisted':len(unlisted),'unlisted_with_evaluable_verified_body':len(unlisted & tested_hosts),
             'unlisted_with_at_least_one_reference_template_match':len(unlisted & matched_hosts),
             'all_evaluable_hosts':len(tested_hosts),'all_hosts_with_at_least_one_template_match':len(matched_hosts),
             'raw_comparable_resources':len([x for x in template_eval if x['body_status']=='evaluable']),
             'missing_or_unverifiable_resources':len([x for x in template_eval if x['body_status']!='evaluable']),
             'note':'No denominator of 139 may be called a verified-nonmatch; missing body != nonmatch; historical reconstructed candidate not counted independently.'},
       'limitations':['Source data describes Censys scan observations, not actor control or phishing activity.',
          'Service and country data may reflect current observations rather than collection-period conditions; inspect requested_at_time.',
          'HTTP body hashes and endpoints are observation-specific; requires original complete Censys-returned bytes.',
          'Same /24 is not evidence of shared malicious operator.']
    }
    (out/'analysis_summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:summary[k] for k in ('n_original_distinct_ips','n_censys_host_records_loaded','n_censys_host_records_missing','n_unique_24_prefixes','n_prefixes_with_multiple_recovered_ips','template_population')},indent=2))

if __name__=='__main__':main()
