import os, hmac, hashlib, random
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

ROOT=Path(__file__).parent
DATA=ROOT/'data'
OUT=ROOT/'outputs'
SECRET_PATH=ROOT/'secret.key'

def get_secret():
    if SECRET_PATH.exists():
        return SECRET_PATH.read_bytes()
    s=os.urandom(32)
    SECRET_PATH.write_bytes(s)
    print('Generated new secret.key (gitignored)')
    return s

SECRET=get_secret()

def hash_ip(ip):
    try:
        return hmac.new(SECRET,str(ip).encode('utf-8'),hashlib.sha256).hexdigest()[:12]
    except: return '000000000000'

def mask_ip(ip):
    try:
        p=str(ip).split('.')
        if len(p)==4: return '.'.join(p[:3]+['0'])
    except: pass
    return '0.0.0.0'

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    # CICIDS2017 TrafficLabelling file with real Source/Destination IPs
    p=DATA/'cicids_traffic_ddos.csv'
    if not p.exists():
        print('Privacy source file missing (data/cicids_traffic_ddos.csv). Run download_data.py.')
        return
    df=pd.read_csv(p,low_memory=False,nrows=2000)
    df.columns=df.columns.str.strip()
    if 'Source IP' not in df:
        print('Source IP column missing.')
        return
    dfp=df[['Source IP','Destination IP','Label']].copy()
    dfp['Source IP hashed']=dfp['Source IP'].apply(hash_ip)
    dfp['Source IP masked']=dfp['Source IP'].apply(mask_ip)
    dfp['Destination IP masked']=dfp['Destination IP'].apply(mask_ip)
    # save preview table image
    fig,ax=plt.subplots(figsize=(9,3))
    ax.axis('off')
    cols=['Source IP','Source IP hashed','Source IP masked','Destination IP','Destination IP masked']
    t=ax.table(cellText=dfp[cols].head(10).values,colLabels=cols,loc='center')
    t.auto_set_font_size(False); t.set_fontsize(7)
    ax.set_title('Patient-privacy protection: IP hashing (repeatable) and masking',fontsize=9)
    plt.tight_layout()
    img=OUT/'privacy_before_after.png'
    plt.savefig(img,dpi=150,bbox_inches='tight')
    plt.close()
    print('Saved',img)
    dfp.to_csv(OUT/'privacy_preview.csv',index=False)
    print(dfp[['Source IP','Source IP hashed','Source IP masked']].head(5).to_string())

if __name__=='__main__': main()