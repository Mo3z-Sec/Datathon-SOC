import os, sys, json, random
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT=Path(__file__).parent
DATA=ROOT/'data'
OUT=ROOT/'outputs'
ASSETS = {
  "EHR Server":5, "Pharmacy System":5, "Infusion Pump Network":5,
  "PACS Imaging":4, "Lab System":4, "Nurse Workstation":3,
  "Admin Office PC":2, "Guest Wi-Fi":1
}

def clean_df(df):
    df.columns=df.columns.str.strip()
    # fix id mismatch
    if 'id' in df and 'ID_NO' in df:
        df['id']=df['id'].fillna(df['ID_NO'])
        df=df.drop(columns=['ID_NO'])
    df=df.replace([np.inf,-np.inf],np.nan).dropna().drop_duplicates()
    return df

def make_binary_label(df):
    if 'label' in df.columns:
        try:
            return df['label'].astype(int)
        except Exception:
            return df['label'].astype(str).str.lower().apply(lambda x: 0 if 'normal' in x else 1)
    if 'attack_cat' in df.columns:
        return df['attack_cat'].astype(str).str.lower().apply(lambda x: 0 if 'normal' in x else 1)
    if 'Label' in df.columns:
        return df['Label'].astype(str).apply(lambda x: 0 if 'BENIGN' in x.upper() else 1)
    return pd.Series(0,index=df.index)

def process_unsw():
    tr_path=DATA/'UNSW_NB15_training-set.csv'
    te_path=DATA/'UNSW_NB15_testing-set.csv'
    if not tr_path.exists():
        print('UNSW training file missing. Run download_data.py first.')
        return
    tr=pd.read_csv(tr_path)
    te=pd.read_csv(te_path) if te_path.exists() else None
    tr=clean_df(tr)
    if te is not None:
        te=clean_df(te)
    # label each before concatenating
    tr['label_binary']=make_binary_label(tr)
    if te is not None:
        te['label_binary']=make_binary_label(te)
    # tag source, concat, align dummies across both
    tr['_src']='train'; 
    frames=[tr]
    if te is not None:
        te['_src']='test'; frames.append(te)
    df=pd.concat(frames,ignore_index=True)
    # drop the multiclass label column: it would leak the answer
    if 'attack_cat' in df.columns:
        df=df.drop(columns=['attack_cat'])
    # compact integer encoding for categoricals (keeps files small / LinuxONE-friendly)
    encoders={}
    for c in ['proto','service','state']:
        if c in df.columns:
            cats=df[c].astype('category')
            encoders[c]=[str(x) for x in cats.cat.categories]
            df[c]=cats.cat.codes.astype('int32')
    with open(OUT/'encoders_unsw.json','w') as f: json.dump(encoders,f,indent=2)
    random.seed(42)
    df['asset']=random.choices(list(ASSETS),k=len(df))
    df['criticality']=df['asset'].map(ASSETS)
    extra=['label','Label','label_binary','asset','criticality','attack_cat','_src','id','ID_NO']
    drop=[c for c in extra if c in df.columns]
    feature_cols=[c for c in df.columns if c not in drop]
    X_all=df[feature_cols]
    y_all=df['label_binary']
    tr_mask=(df['_src']=='train').values
    X_pool=X_all[tr_mask]; y_pool=y_all[tr_mask]
    if te is not None:
        X_test=X_all[~tr_mask]; y_test=y_all[~tr_mask]
    else:
        X_test=None
    # split the training pool into train/val (85/15)
    X_train,X_val,y_train,y_val=train_test_split(X_pool,y_pool,test_size=0.15,stratify=y_pool,random_state=42)
    scaler=StandardScaler()
    Xtr=scaler.fit_transform(X_train)
    Xva=scaler.transform(X_val)
    scaler_json={'mean':scaler.mean_.tolist(),'scale':scaler.scale_.tolist(),'columns':feature_cols}
    with open(OUT/'scaler_unsw.json','w') as f: json.dump(scaler_json,f,indent=2)
    parts=[('train',Xtr,y_train),('val',Xva,y_val)]
    if X_test is not None:
        Xte=scaler.transform(X_test)
        parts.append(('test',Xte,y_test))
    for name,A,b in parts:
        out=pd.DataFrame(A,columns=feature_cols)
        for c in out.columns:
            if out[c].dtype=='float64': out[c]=out[c].astype('float32')
        out['label_binary']=b.values
        out['asset']=[random.choice(list(ASSETS)) for _ in range(len(out))]
        out['criticality']=out['asset'].map(ASSETS)
        p=OUT/f'unsw_{name}.csv'
        out.to_csv(p,index=False,float_format='%.6g')
        print('Saved',p,len(out))
    print('UNSW done.')

def process_cicids():
    names=[
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'Wednesday-workingHours.pcap_ISCX.csv',
        'Tuesday-WorkingHours.pcap_ISCX.csv',
        'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'Monday-WorkingHours.pcap_ISCX.csv',
        'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    ]
    files=[DATA/n for n in names if (DATA/n).exists()]
    if not files:
        print('CICIDS files missing or partial. Run download_data.py first.')
        return
    PER_FILE=25000
    dfs=[]
    for p in files:
        try:
            df=pd.read_csv(p,low_memory=False)
            df.columns=df.columns.str.strip()
            if 'Label' in df.columns:
                df['label_binary']=df['Label'].astype(str).apply(lambda x: 0 if 'BENIGN' in x.upper() else 1)
            if len(df)>PER_FILE:
                df=df.sample(PER_FILE,random_state=42)
            dfs.append(df)
            print('read',p.name,'->',len(df))
        except Exception as e:
            print('ERR',p,e)
    if not dfs: return
    df=pd.concat(dfs,ignore_index=True)
    del dfs
    df=clean_df(df)
    if len(df)==0:
        print('CICIDS empty after clean'); return
    if 'Label' in df.columns:
        df['label_binary']=df['Label'].astype(str).apply(lambda x: 0 if 'BENIGN' in x.upper() else 1)
    elif 'label' in df.columns:
        df['label_binary']=df['label'].astype(str).apply(lambda x: 0 if 'BENIGN' in x.upper() else 1)
    else:
        df['label_binary']=0
    # keep numeric only for model
    X=df.select_dtypes(include=['number'])
    # drop obvious columns
    drop_cols=[c for c in ['label_binary','asset','criticality','label','Label'] if c in X.columns]
    X=X.drop(columns=drop_cols)
    X=X.replace([np.inf,-np.inf],np.nan).fillna(0)
    y=df['label_binary']
    # sample for size if huge
    n=len(X)
    if n>150000:
        print('Sampling 150000 rows from',n)
        idx=np.random.RandomState(42).choice(n,150000,replace=False)
        idx.sort()
        X=X.iloc[idx].reset_index(drop=True)
        y=y.iloc[idx].reset_index(drop=True)
    random.seed(42)
    assets=[random.choice(list(ASSETS)) for _ in range(len(X))]
    crit=[ASSETS[a] for a in assets]
    X_train,X_tmp,y_train,y_tmp=train_test_split(X,y,test_size=0.3,stratify=y,random_state=42)
    X_val,X_test,y_val,y_test=train_test_split(X_tmp,y_tmp,test_size=0.5,stratify=y_tmp,random_state=42)
    scaler=StandardScaler()
    Xtr=scaler.fit_transform(X_train)
    Xva=scaler.transform(X_val)
    Xte=scaler.transform(X_test)
    scaler_json={'mean':scaler.mean_.tolist(),'scale':scaler.scale_.tolist(),'columns':list(X.columns)}
    with open(OUT/'scaler_cicids.json','w') as f: json.dump(scaler_json,f,indent=2)
    # index sets that mirror the X/y splits above (same params = same shuffle)
    all_idx=np.arange(len(X))
    tr_all,tmp_idx=train_test_split(all_idx,test_size=0.3,stratify=y,random_state=42)
    val_idx,test_idx=train_test_split(tmp_idx,test_size=0.5,stratify=y.iloc[tmp_idx],random_state=42)
    asset_map=dict(zip(all_idx,assets))
    crit_map=dict(zip(all_idx,crit))
    splits=[('train',Xtr,y_train,tr_all),('val',Xva,y_val,val_idx),('test',Xte,y_test,test_idx)]
    for name,A,b,idxs in splits:
        out=pd.DataFrame(A,columns=X.columns)
        for c in out.columns:
            if out[c].dtype=='float64': out[c]=out[c].astype('float32')
        out['label_binary']=b.values
        out['asset']=[asset_map[i] for i in idxs]
        out['criticality']=[crit_map[i] for i in idxs]
        p=OUT/f'cicids_{name}.csv'
        out.to_csv(p,index=False,float_format='%.6g')
        print('Saved',p,len(out))
    print('CICIDS done.')

if __name__=='__main__':
    OUT.mkdir(parents=True,exist_ok=True)
    process_unsw()
    process_cicids()
    print('Pipeline complete.')