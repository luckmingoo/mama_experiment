#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-16

@author: mingo
@module: experiment_mama.copy_feature_csv_to_ssd
'''

import shutil
import os 
import csv
from multiprocessing import Pool


def run_task(source_path, dest_dir, idx):
    shutil.copy(source_path, dest_dir)
    if idx % 100 == 0:
        print('%d: %s' % (idx, source_path))

def main():
    benign_dataset = '/mnt/AndroZoo/GooglePlay_firstseen/apks_benign_hash_path_100w.csv'
    malicious_dataset = '/mnt/VirusShare/malware_dataset_vs_vt_amd.csv'
    dataset = []
    with open(benign_dataset, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            md5 = row[0]
            first_seen = row[1]
            dataset.append([md5, first_seen, 0])
    with open(malicious_dataset, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            md5 = row[0]
            first_seen = row[1]
            dataset.append([md5, first_seen, 1])
    print('read dataset over')
    
    save_root_dir = '/mnt/ssd_2T/mamadroid/soot_result'
    for year in range(2012, 2019):
        save_feature_dir = os.path.join(save_root_dir, str(year))
        if not os.path.exists(save_feature_dir):
            os.mkdir(save_feature_dir)
    
    p = Pool(20)
    idx = 0
    for row in dataset:
        md5 = row[0]
        first_seen = row[1]
        fs_year = int(first_seen.split('-')[0])
        label = row[2]
        if label == 0:
            graph_path = '/mnt/AndroZoo/result_benign_soot/benign_{}/graphs/{}.txt'.format(fs_year, md5)
        elif label == 1:
            graph_path = '/mnt/AndroZoo/result_malware_soot/malware_{}/graphs/{}.txt'.format(fs_year, md5)
        if not os.path.exists(graph_path):
            continue
        dest_dir = os.path.join(save_root_dir, str(fs_year))
        if os.path.exists(dest_dir, '{}.txt'.format(md5)):
            continue
        idx += 1
        p.apply_async(run_task, args = (graph_path, dest_dir, idx, ))
    p.close()
    p.join()
    print('finish')

if __name__ == "__main__":
    main()