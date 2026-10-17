import random, json
from pathlib import Path
import pandas as pd

ROOT=Path(__file__).parent
OUT=ROOT/'outputs'
OUT.mkdir(parents=True, exist_ok=True)

ASSETS = {
  "EHR Server":5, "Pharmacy System":5, "Infusion Pump Network":5,
  "PACS Imaging":4, "Lab System":4, "Nurse Workstation":3,
  "Admin Office PC":2, "Guest Wi-Fi":1
}

def main(n=20):
    random.seed(42)
    df=pd.DataFrame({'asset':random.choices(list(ASSETS), k=n)})
    df['criticality']=df['asset'].map(ASSETS)
    df['simulated']=True
    path=OUT/'assets.csv'
    df.to_csv(path,index=False)
    print('Saved',path,len(df))
    return path

if __name__=='__main__': main(20)