import os, sys, json, time, re
from pathlib import Path
import requests

WORKDIR = Path(__file__).parent
DATA = WORKDIR / 'data'
DATA.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

def download(url, dest, verify_content_len=False):
    print(f'Downloading {url}')
    print(f' -> {dest}')
    if dest.exists():
        print('Exists; skipping.')
        return dest
    r = SESSION.get(url, stream=True, allow_redirects=True, timeout=1200)
    r.raise_for_status()
    total = int(r.headers.get('content-length', 0))
    with open(dest,'wb') as f:
        bytes=0; chunk=1024*1024
        for c in r.iter_content(chunk_size=chunk):
            if c: f.write(c); bytes+=len(c)
            if total: sys.stdout.write(f'\r{bytes//chunk}MB/{total//chunk}MB'); sys.stdout.flush()
        print()
    print('Done.')
    return dest

def main():
    urls = {
        'unsw_train_csv': [
            'https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/UNSW_NB15_training-set.csv',
            'https://raw.githubusercontent.com/TalhaUsuf/unsw_data_analysis/master/UNSW_NB15_training-set.csv',
            'https://raw.githubusercontent.com/tichill/UNSW_DATA/master/UNSW_NB15_training-set.csv',
        ],
        'unsw_test_csv': [
            'https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv',
            'https://raw.githubusercontent.com/TalhaUsuf/unsw_data_analysis/master/UNSW_NB15_testing-set.csv',
            'https://raw.githubusercontent.com/tichill/UNSW_DATA/master/UNSW_NB15_testing-set.csv',
        ],
    }
    # UNSW
    for k,dests in [('UNSW_NB15_training-set.csv', urls['unsw_train_csv']),('UNSW_NB15_testing-set.csv', urls['unsw_test_csv'])]:
        ok=False
        for u in dests:
            try:
                download(u, DATA/k); ok=True; break
            except Exception as e:
                print('FAIL',u,e)
        if not ok: print('WARN: Could not download',k)
    # NSL-KDD
    for k,u in [('KDDTrain+.txt','https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt'),
                ('KDDTest+.txt','https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt')]:
        try: download(u, DATA/k)
        except Exception as e: print('WARN NSL-KDD',k,e)
    # Threat lists
    for k,u in [('openphish_feed.txt','https://openphish.com/feed.txt'),
                ('urlhaus_recent.csv','https://urlhaus.abuse.ch/downloads/csv_recent/')]:
        try: download(u, DATA/k)
        except Exception as e: print('WARN threat',k,e)
    # CICIDS2017 TrafficLabelling with IPs (c01dsnap/HF resolve links)
    cic_ids = [
        ('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'),
        ('Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'),
        ('Wednesday-workingHours.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Wednesday-workingHours.pcap_ISCX.csv'),
        ('Tuesday-WorkingHours.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Tuesday-WorkingHours.pcap_ISCX.csv'),
        ('Friday-WorkingHours-Morning.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Friday-WorkingHours-Morning.pcap_ISCX.csv'),
        ('Monday-WorkingHours.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Monday-WorkingHours.pcap_ISCX.csv'),
        ('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'),
        ('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv','https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'),
    ]
    for name,u in cic_ids:
        try:
            download(u, DATA/name)
        except Exception as e:
            print('WARN CICIDS',name,e)
    # CICIDS2017 TrafficLabelling file WITH real IP columns (Source IP / Destination IP)
    # Source: SHUBHAMRAWAT-25 GitHub mirror. Used for the patient-privacy (hash/mask) demo.
    traffic=DATA/'cicids_traffic_ddos.csv'
    if not traffic.exists():
        url='https://raw.githubusercontent.com/SHUBHAMRAWAT-25/DDOS-attack-detection-using-random-forest-algorithm/main/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
        try:
            download(url, traffic)
        except Exception as e:
            print('WARN traffic file',e)
    print('Downloads done.')

if __name__=='__main__': main()