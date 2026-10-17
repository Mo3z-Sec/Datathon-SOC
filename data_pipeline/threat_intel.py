import os, csv
from pathlib import Path
import pandas as pd

ROOT=Path(__file__).parent
DATA=ROOT/'data'
OUT=ROOT/'outputs'

BAD_SET=set()

def load_openphish():
    p=DATA/'openphish_feed.txt'
    if p.exists():
        with open(p,encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if line and not line.startswith('#'):
                    BAD_SET.add(line)

def load_urlhaus():
    p=DATA/'urlhaus_recent.csv'
    if not p.exists():
        return
    with open(p,encoding='utf-8',errors='ignore',newline='') as f:
        reader=csv.reader(f)
        for row in reader:
            if not row: continue
            if row[0].startswith('#'): continue
            # columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            if len(row)>=3:
                url=row[2].strip()
                if url.startswith('http'):
                    BAD_SET.add(url)

def is_known_bad(x):
    if not x: return 0
    s=str(x).strip()
    return 1 if s in BAD_SET else 0

def load_all():
    load_openphish(); load_urlhaus()
    return BAD_SET

# auto-load on import so `import threat_intel` is ready to use
load_openphish(); load_urlhaus()

def save_lookup_table(limit=20000):
    OUT.mkdir(parents=True, exist_ok=True)
    items=list(BAD_SET)[:limit]
    pd.DataFrame({'url':items}).to_csv(OUT/'threat_urls.csv',index=False)
    print('Saved threat_urls.csv sample',len(items))

if __name__=='__main__':
    load_all()
    print('BAD_SET size',len(BAD_SET))
    save_lookup_table()
    # demo
    sample=next(iter(BAD_SET)) if BAD_SET else ''
    print('is_known_bad(sample)=',is_known_bad(sample),'is_known_bad(random)=',is_known_bad('https://example.com/x'))
    print('threat_intel ready. Import is_known_bad in Jason engine.')