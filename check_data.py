#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-17

@author: mingo
@module: experiment_mama.check_data
'''
import os 
import csv 


dataset = []
with open('/mnt/ssd_2T/mamadroid/dataset_20162017_light_weight/manual_package_v4/manual_package_v4_save_feature_list.csv', 'r') as f:
    reader  = csv.reader(f) 
    for row in reader:
        md5 = row[0]
        first_seen = row[2]
        dataset.append([md5, first_seen])
idx = 0
for row in dataset:
    md5 = row[0]
    first_seen = row[1]
    fs_year = int(first_seen.split('-')[0])
    feature_path = '/mnt/ssd_2T/mamadroid/manual_package_v4/feature/%d/manual_package_v4_%s.csv' % (fs_year, md5)
    if not os.path.exists(feature_path):
        print(feature_path)
    idx += 1
    if idx % 2000 == 0:
        print('%d: %s' % (idx, md5))
print('finish')