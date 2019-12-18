#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-17

@author: mingo
@module: experiment_mama.count_api_for_drebin
'''
import csv 
import os 


def count_api_for_drebin():
    benign_dataset = '/mnt/AndroZoo/GooglePlay_firstseen/apks_benign_hash_path_100w.csv'
    malicious_dataset = '/mnt/VirusShare/malware_dataset_vs_vt_amd.csv'
    dataset_list = []
    with open(malicious_dataset, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            md5 = row[0]
            first_seen = row[1]
            fs_year = int(first_seen.split('-')[0])
            dataset_list.append([md5, fs_year])
    with open(benign_dataset, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            md5 = row[0]
            first_seen = row[1]
            fs_year = int(first_seen.split('-')[0])
            dataset_list.append([md5, fs_year])
    idx = 0
    api_set = set()
    for row in dataset_list:
        md5 = row[0]
        fs_year = row[1]
        feature_file_path = '/mnt/AndroZoo/drebin_dl/simplify_features/{}/{}.data'.format(fs_year, md5)
        if not os.path.exists(feature_file_path):
            continue
        with open(feature_file_path, 'r') as f:
            for line in f:
                api = line.strip()
                if api.split('_')[0] in ['SuspiciousApiList', 'RestrictedApiList']:
                    api_set.add(api)    
        idx += 1
        if idx % 1000 == 0:
            print('%d: %s api len: %d' % (idx, md5, len(api_set)))
    api_list = list(api_set)
    api_list.sort()
    with open('api_feature_drebin.txt', 'w') as f:
        f.write('\n'.join(api_list))
        f.write('\n')
    print('api len: %d' % len(api_list))
    print('finish')

if __name__ == "__main__":
    count_api_for_drebin()