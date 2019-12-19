#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-19

@author: mingo
@module: experiment_mama.count_family_num_for_AMD
'''

import csv 
import os 
from matplotlib import pyplot as plt
import numpy as np

amd_csv_path = '/mnt/AMD/amd_apks.csv'
apks = {}
with open(amd_csv_path, 'r') as f:
    reader = csv.reader(f) 
    for row in reader:
        md5 = row[0]
        first_seen = row[1]
        fs_year = int(first_seen.split('-')[0])
        if fs_year < 2000:
            continue
        fs_year_month = str(fs_year) + first_seen.split('-')[1]
        apk_path = row[3]
        family_name = apk_path.split('/')[4]
        if family_name not in apks:
            apks[family_name] = {}
        if fs_year_month not in apks[family_name]:
            apks[family_name][fs_year_month] = 0
        apks[family_name][fs_year_month] += 1
apks_list = []
apks_list_above_200 = []
for family_name in apks:
    apks_list.append([family_name])
    fs_year_month_list = list(apks[family_name].keys())
    fs_year_month_list.sort()
    app_num_list = []
    for fs_year_month in fs_year_month_list:
        app_num_list.append(apks[family_name][fs_year_month])
    apks_list.append(fs_year_month_list)
    apks_list.append(app_num_list)
    num_array = np.array(app_num_list)
    if num_array.sum() >= 200:
        apks_list_above_200.append([family_name])
        apks_list_above_200.append(fs_year_month_list)
        apks_list_above_200.append(app_num_list)
#     plt.cla()
#     plt.figure(figsize = (14, 12))
#     plt.bar(fs_year_month_list, app_num_list)
#     plt.title(family_name)
#     plt.savefig('figure/%s.png' % family_name, dpi = 200)
with open('AMD_family_count.csv', 'wb') as f:
    writer = csv.writer(f) 
    writer.writerows(apks_list)
with open('AMD_family_count_above_200.csv', 'wb') as f:
    writer = csv.writer(f) 
    writer.writerows(apks_list_above_200)    
print('finish')