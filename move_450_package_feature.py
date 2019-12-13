#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-12

@author: mingo
@module: experiment_mama.move_450_package_feature
'''
import os 
import csv 
import shutil


method  = '450_package'
dataset_list = []
dataset_dir = '/mnt/VirusShare/dataset_s_baseline/dataset_20132014'
for file_name in os.listdir(dataset_dir):
    with open(os.path.join(dataset_dir, file_name), 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            label = int(row[0])
            if label != 2:
                md5 = row[1].split('/')[1]
                fs_year = int(row[2].split('-')[0])
                dataset_list.append([label, md5, fs_year])
idx = 0
for row in dataset_list:
    idx += 1
    label = row[0]
    md5 = row[1]
    fs_year = row[2]
    if label == 0:
        graph_path = '/mnt/AndroZoo/result_benign_soot/benign_{}/graphs/{}.txt'.format(fs_year, md5)
    elif label == 1:
        graph_path = '/mnt/AndroZoo/result_malware_soot/malware_{}/graphs/{}.txt'.format(fs_year, md5)
    source_dir = '/mnt/ssd_1T/mamadroid/mama_feature/{}'.format(fs_year)
    source_path = os.path.join(source_dir, '{}.csv'.format(md5))
    if not os.path.exists(source_path):
        continue
    dest_dir = '/mnt/ssd_1T/mamadroid/dataset_20132014/450_package/feature/{}'.format(fs_year)
    if not os.path.exists(dest_dir):
        os.mkdir(dest_dir)
    dest_path = os.path.join(dest_dir, '{}_{}.csv'.format(method, md5))
    shutil.move(source_path, dest_path)
    if idx % 1000 == 0:
        print('%d: %s' % (idx, dest_path))
    