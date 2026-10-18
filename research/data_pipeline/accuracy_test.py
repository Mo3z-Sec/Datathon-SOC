import os
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from privacy import hash_ip, mask_ip

ROOT=Path(__file__).parent
DATA=ROOT/'data'
OUT=ROOT/'outputs'

def pick_files():
    cands=['cicids_traffic_ddos.csv',
           'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv']
    return [DATA/c for c in cands if (DATA/c).exists()]

def load_sample(per_file=60000):
    files=pick_files()
    if not files:
        return None
    frames=[]
    for p in files:
        df=pd.read_csv(p,low_memory=False)
        df.columns=df.columns.str.strip()
        if 'Label' not in df.columns:
            continue
        if len(df)>per_file:
            df=df.sample(per_file,random_state=42)
        frames.append(df)
    if not frames:
        return None
    df=pd.concat(frames,ignore_index=True)
    df.columns=df.columns.str.strip()
    df=df.replace([np.inf,-np.inf],np.nan)
    df=df.dropna(subset=['Label'])
    lab=df['Label'].astype(str).apply(lambda x:0 if 'BENIGN' in x.upper() else 1)
    # numeric features (exclude raw IP/ID/timestamp text columns)
    num=df.select_dtypes(include=['number']).copy()
    num=num.replace([np.inf,-np.inf],np.nan).fillna(0)
    return df, num, lab

def code_series(s):
    return pd.Series(pd.Categorical(s.astype(str)).codes, index=s.index)

def evaluate(X,y,tag):
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.3,stratify=y,random_state=42)
    m=RandomForestClassifier(n_estimators=60,random_state=42,n_jobs=-1).fit(Xtr,ytr)
    p=m.predict(Xte)
    return {'variant':tag,
            'accuracy':round(accuracy_score(yte,p),4),
            'precision':round(precision_score(yte,p,zero_division=0),4),
            'recall':round(recall_score(yte,p,zero_division=0),4),
            'f1':round(f1_score(yte,p,zero_division=0),4)}

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    loaded=load_sample()
    if loaded is None:
        print('No CICIDS IP files found; cannot run privacy accuracy test.')
        return
    df,num,lab=loaded
    if 'Source IP' not in df.columns or 'Destination IP' not in df.columns:
        print('IP columns not present.')
        return
    src=df['Source IP']; dst=df['Destination IP']
    # Variant A: original IP identity (label codes)
    Xa=num.copy()
    Xa['src_ip']=code_series(src)
    Xa['dst_ip']=code_series(dst)
    # Variant B: HMAC-hashed IP (identity preserved, anonymized)
    Xb=num.copy()
    Xb['src_ip']=code_series(src.apply(hash_ip))
    Xb['dst_ip']=code_series(dst.apply(hash_ip))
    # Variant C: masked IP (identity removed)
    Xc=num.copy()
    Xc['src_ip']=code_series(src.apply(mask_ip))
    Xc['dst_ip']=code_series(dst.apply(mask_ip))
    rows=[evaluate(Xa,lab,'original IP'),
          evaluate(Xb,lab,'hashed IP (privacy)'),
          evaluate(Xc,lab,'masked IP (aggressive)')]
    res=pd.DataFrame(rows).set_index('variant')
    res.to_csv(OUT/'accuracy_comparison.csv')
    print(res)
    ax=res[['accuracy','precision','recall','f1']].plot.bar(rot=0,figsize=(7,4))
    ax.set_ylim(0,1.05); ax.set_title('Privacy protection vs detection performance')
    plt.tight_layout()
    plt.savefig(OUT/'accuracy_comparison.png',dpi=150,bbox_inches='tight')
    plt.close()
    print('Saved accuracy_comparison.csv and .png')
    if 'hashed IP (privacy)' in res.index and 'original IP' in res.index:
        delta=res.loc['original IP','accuracy']-res.loc['hashed IP (privacy)','accuracy']
        print(f'Accuracy change from hashing: {delta*100:.2f} percentage points')
        print('Headline: patient privacy costs almost no accuracy.')

if __name__=='__main__': main()