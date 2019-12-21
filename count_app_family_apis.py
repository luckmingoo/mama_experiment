#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-19

@author: mingo
@module: experiment_mama.count_app_family_apis
'''
import os 
import csv 
import matplotlib.pyplot as plt

def get_medium_year_month(min_year_month, max_year_month):
    if min_year_month > max_year_month:
        return None
    delta_month = int(max_year_month/100)*12 + (max_year_month % 100) - (int(min_year_month/100)*12 + (min_year_month % 100))
#     print(delta_month)
    delta_month = int((delta_month + 1)/2)
#     print(delta_month)
    medium_month = ((min_year_month % 100) + delta_month)
    medium_year = int(min_year_month/100) + int((medium_month - 1)/12)
    if medium_month % 12 == 0:
        return (medium_year) * 100 + 12
    else:
        return (medium_year) * 100 + ((medium_month ) % 12)

def get_seq_path_dict():
    seq_path_dict = {}
    malware_seq_csv_path = '/mnt/VirusShare/lldroid_output/apk_malicious_seq_11w_combine_soot2016.csv'
    with open(malware_seq_csv_path, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            seq_path = row[0]
            md5 = seq_path.split('/')[1]
            seq_path_dict[md5] = seq_path
    return seq_path_dict

def analyze_apis(app_list, seq_path_dict):
    api_count_dict = {}
    lldroid_output = '/mnt/VirusShare/lldroid_output/'
    cnt = 0
    for row in app_list:
        md5 = row[0]
        seq_path = seq_path_dict[md5]
        seq_abspath = os.path.join(lldroid_output, seq_path)
        if os.path.exists(seq_abspath):
            cnt += 1
            with open(seq_abspath, 'r') as f:
                apis = [line.strip() for line in f.readlines()]
                for api in apis:
                    api = api.strip()
                    if api in api_count_dict:
                        api_count_dict[api] = api_count_dict[api] + 1
                    else:
                        api_count_dict[api] = 1
        else:
            print('not exist: %s' % (seq_abspath))
    api_count_list = []
    for api in api_count_dict:
        num = api_count_dict[api]
        average_num = float(num)/cnt
        api_count_list.append([api, average_num])
    api_count_list.sort(key = lambda x:x[1], reverse = True)
    return api_count_list

def get_sensitive_api():
    sensitive_api_set = set()
    with open('sensitive_method.txt', 'r') as f:
        for line in f:
            api = line.strip()
            sensitive_api_set.add(api)
    return sensitive_api_set

def diff_two_part_api_count(part_01_count_list, part_02_count_list): # [api, average_fluence]
    sensitive_api_set = get_sensitive_api()
    part_01_dict = {}
    for row in part_01_count_list:
        api = row[0]
        average_cnt = row[1]
        part_01_dict[api] = average_cnt
    part_02_dict = {}
    for row in part_02_count_list:
        api = row[0]
        average_cnt = row[1]
        part_02_dict[api] = average_cnt
    sensitive_diff_cnt_list = []
    nonsensitive_diff_cnt_list = []
    all_api_set = set(part_01_dict.keys()) | set(part_02_dict.keys())
    for api in all_api_set:
        part_01_cnt = part_01_dict.get(api, 0)
        part_02_cnt = part_02_dict.get(api, 0)
        diff_cnt = abs(part_01_cnt - part_02_cnt)
        if api in sensitive_api_set:
            sensitive_diff_cnt_list.append([api, diff_cnt])
        else:
            nonsensitive_diff_cnt_list.append([api, diff_cnt])
    sensitive_diff_cnt_list.sort(key = lambda x:x[1], reverse = True)
    nonsensitive_diff_cnt_list.sort(key = lambda x:x[1], reverse = True)
    return sensitive_diff_cnt_list, nonsensitive_diff_cnt_list

def get_y_label(bound_list):
    y_labels = []
    for i in range(len(bound_list)):
        if i != (len(bound_list) - 1):
            y_label = '%.1f~%.1f' % (bound_list[i], bound_list[i+1])
        else:
            y_label = 'above %.1f' % (bound_list[i])
        y_labels.append(y_label)
    return y_labels
    
def plot_diff_bar(sensitive_diff_cnt_list, nonsensitive_diff_cnt_list, save_name):
    bound_list = [0, 0.1, 0.5, 1, 5, 20]
    sensitive_cnt_bar_list = [0 for _ in range(len(bound_list))]
    nonsensitive_cnt_bar_list = [0 for _ in range(len(bound_list))]
    for row in sensitive_diff_cnt_list:
        average_cnt = row[1]
        idx = 0
        while idx < len(bound_list):
            if average_cnt <= bound_list[idx]:
                break
            idx += 1
        sensitive_cnt_bar_list[idx - 1] += 1
    for row in nonsensitive_diff_cnt_list:
        average_cnt = row[1]
        idx = 0
        while idx < len(bound_list):
            if average_cnt < bound_list[idx]:
                break
            idx += 1
        nonsensitive_cnt_bar_list[idx - 1] += 1
    y_labels = get_y_label(bound_list)
    print('sensitive cnt list: %s nonsensitive cnt list: %s' % (sensitive_cnt_bar_list, nonsensitive_cnt_bar_list) )
    plt.cla()
    plt.bar(y_labels, sensitive_cnt_bar_list, fc='r', label = 'sensitive')
    plt.bar(y_labels, nonsensitive_cnt_bar_list, fc='g', label = 'nonsensitive', bottom=sensitive_cnt_bar_list)
    plt.title(save_name)
    plt.legend()
    plt.savefig("api_count/%s.png" % save_name)
    
    
def count_apis():
    seq_path_dict = get_seq_path_dict()
    amd_dataset_path = '/mnt/AMD/amd_apks.csv'
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(amd_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in seq_path_dict:
                continue
            first_seen = row[1]
            apk_path = row[3]
            family_name = apk_path.split('/')[4]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    for family_name in ["Mecor", "Dowgin", "Airpush", "Kuguo", "DroidKungFu", "Youmi", "FakeInst", "Jisut"]:
        family_app[family_name].sort(key = lambda x:x[1])
        min_year_month = family_app[family_name][0][1]
        max_year_month = family_app[family_name][-1][1]
        medium_year_month = get_medium_year_month(min_year_month, max_year_month)
        part_01 = []
        part_02 = []
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < medium_year_month:
                part_01.append(row)
            else:
                part_02.append(row)
        print("%s part 01: %d part 02: %d" % (family_name, len(part_01), len(part_02)))
        part_01_api_count_list = analyze_apis(part_01, seq_path_dict)
        part_02_api_count_list = analyze_apis(part_02, seq_path_dict)
        with open('api_count/%s_part_01_count.csv' % (family_name), 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(part_01_api_count_list)
        with open('api_count/%s_part_02_count.csv' % (family_name), 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(part_02_api_count_list)
        sensitive_diff_cnt, nonsensitive_diff_cnt = diff_two_part_api_count(part_01_api_count_list, part_02_api_count_list)
        with open('api_count/%s_diff_cnt_sensitive.csv' % family_name, 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(sensitive_diff_cnt)
        with open('api_count/%s_diff_cnt_nonsensitive.csv' % family_name, 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(nonsensitive_diff_cnt)
        plot_diff_bar(sensitive_diff_cnt, nonsensitive_diff_cnt, '%s_diff_api_count' % family_name)

if __name__ == "__main__":
    count_apis()
#     print(get_medium_year_month(201304, 201602))