#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-21

@author: mingo
@module: experiment_mama.get_accurate_family
'''

import csv 
import os 
import json 
import argparse
import matplotlib
matplotlib.use('AGG')
import matplotlib.pyplot as plot

# R1 vt_count >= X1
# R2 family_support_top1 >= X2%*vt_cnt
# R3 (family_support_top1 – top2)/sum(family_support_top_all) >= X3%

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--min_vt_cnt", type = int, default = 15)
parser.add_argument("-sr", "--min_support_rate", type = float, default = 0.3)
parser.add_argument("-sdr", "--min_support_diff_rate", type = float, default = 0.2)
args = parser.parse_args()

def get_md5_family_dict():
    origin_family_label_csv = 'labelinfo.verbose'
    md5_family_dict = {}
    with open(origin_family_label_csv, 'r') as f:
        idx = 0
        for line in f:
            line = line.strip()
            md5 = line.split(',')[0]
            tuple_str = line[line.find('['): line.find(']') + 1]
            tuple_str = tuple_str.replace('\'', '\"')
            tuple_str = tuple_str.replace('(', '[')
            tuple_str = tuple_str.replace(')', ']')
            tuple_list = json.loads(tuple_str)
            tuple_list.sort(key = lambda x: x[1], reverse = True)
            if tuple_list:
                md5_family_dict[md5] = tuple_list
            idx += 1
    return md5_family_dict

def filt_family(md5_family_dict):
    md5_family_filted = []
    malware_dataset_csv = '/mnt/VirusShare/malware_dataset_vs_vt_amd.csv'
    md5_vt_cnt_dict = {}
    with open(malware_dataset_csv, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            first_seen = row[1]
            vt_cnt = int(row[2])
            md5_vt_cnt_dict[md5] = [vt_cnt, first_seen]
    min_vt_cnt = args.min_vt_cnt
    min_support_rate = args.min_support_rate
    min_support_diff_rate = args.min_support_diff_rate
    need_remove_md5 = []
    for md5 in md5_family_dict:
#         print("%s: %s" % (md5, str(md5_family_dict[md5])))
        vt_cnt = md5_vt_cnt_dict[md5][0]
        if vt_cnt < min_vt_cnt: # R1
            need_remove_md5.append(md5)
            continue
        sum_label_num = 0
        for support_list in md5_family_dict[md5]:
            sum_label_num += support_list[1]
        if md5_family_dict[md5][0][1] < min_support_rate*vt_cnt: # R2
            need_remove_md5.append(md5)
            continue
        if len(md5_family_dict[md5]) < 2:
            continue
        if (md5_family_dict[md5][0][1] - md5_family_dict[md5][1][1]) < min_support_diff_rate * vt_cnt: # R3
            need_remove_md5.append(md5)
            continue
    for md5 in need_remove_md5:
        md5_family_dict.pop(md5)
    for md5 in md5_family_dict:
        vt_cnt = md5_vt_cnt_dict[md5][0]
        first_seen = md5_vt_cnt_dict[md5][1]
        md5_family_filted.append([md5, md5_family_dict[md5][0][0], md5_family_dict[md5][0][1], first_seen, vt_cnt])
    return md5_family_filted

def parse_top_family(families_num_list, families_num):
    top_families = []
    for row in families_num_list:
        family = row[0]
        family_app_num = row[1]
        if family_app_num >= 500:
            top_families.append(family)
    idx = 0
    for family in top_families:
        idx += 1
        family_year_month_app_num = {}
        for row in families_num[family]:
            fs_year_month = row[1]
            if fs_year_month not in family_year_month_app_num:
                family_year_month_app_num[fs_year_month] = 0
            family_year_month_app_num[fs_year_month] += 1
        x_y_list = []
        for fs_year_month, num in family_year_month_app_num.items():
            x_y_list.append([fs_year_month, num])
        x_y_list.sort(key = lambda x: x[0])
        x_list = [_[0][2:] for _ in x_y_list]
        y_list = [_[1] for _ in x_y_list]
        
        plot.cla()
        plot.figure(figsize = (10,8))
        plot.tick_params(labelsize=5)
        plot.bar(x_list, y_list)
        plot.title('Top %02d %s' % (idx, family))
        plot.savefig('family/Top_%02d_%s.png' % (idx, family), dpi = 300)
    
def get_accurate_family():
    md5_family_dict = get_md5_family_dict()
    md5_family_filted = filt_family(md5_family_dict) # [md5, family, family_support_num, first_seen, vt_cnt]
    print(len(md5_family_filted))
    families_num = {}
    for row in md5_family_filted:
        md5 = row[0]
        family = row[1]
        first_seen = row[3]
        if family not in families_num:
            families_num[family] = []
        fs_year = int(first_seen.split('-')[0])
        fs_month = int(first_seen.split('-')[1])
        families_num[family].append([md5, "%d-%02d" % (fs_year, fs_month)])
    families_num_list = []
    for family in families_num:
        families_num[family].sort(key = lambda x: x[1])
        families_num_list.append([family, len(families_num[family]), families_num[family][0][1], families_num[family][-1][1]])
    families_num_list.sort(key = lambda x:x[1], reverse = True)
    parse_top_family(families_num_list, families_num)
    with open('dataset_family_filted.csv', 'wb') as f:
        writer = csv.writer(f) 
        writer.writerows(md5_family_filted)
    with open('families.csv', 'wb') as f:
        writer = csv.writer(f) 
        writer.writerows(families_num_list)
    print('finish')

if __name__ == "__main__":
    get_accurate_family()