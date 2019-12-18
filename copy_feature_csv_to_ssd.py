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
    dataset_list = []
    dataset_dir = '/mnt/VirusShare/dataset_s_baseline/dataset_all_month'
    for file_name in os.listdir(dataset_dir):
        file_abs_path = os.path.join(dataset_dir, file_name)
        with open(file_abs_path, 'r') as f:
            reader = csv.reader(f) 
            for row in reader:
                dataset_list.append(row)
    print('read dataset over')
        
    save_root_dir = '/mnt/ssd_2T/mamadroid/soot_result'
    for year in range(2012, 2019):
        save_feature_dir = os.path.join(save_root_dir, str(year))
        if not os.path.exists(save_feature_dir):
            os.mkdir(save_feature_dir)
    
    p = Pool(30)
    idx = 0
    for row in dataset_list:
        md5 = row[1]
        first_seen = row[2]
        fs_year = int(first_seen.split('-')[0])
        label = int(row[0])
        if label == 0:
            graph_path = '/mnt/AndroZoo/result_benign_soot/benign_{}/graphs/{}.txt'.format(fs_year, md5)
        elif label == 1:
            graph_path = '/mnt/AndroZoo/result_malware_soot/malware_{}/graphs/{}.txt'.format(fs_year, md5)
        if not os.path.exists(graph_path):
            continue
        dest_dir = os.path.join(save_root_dir, str(fs_year))
        if os.path.exists(os.path.join(dest_dir, '{}.txt'.format(md5))):
            continue
        idx += 1
        p.apply_async(run_task, args = (graph_path, dest_dir, idx, ))
    p.close()
    p.join()
    print('finish')

if __name__ == "__main__":
    main()