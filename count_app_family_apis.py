#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-19

@author: mingo
@module: experiment_mama.count_app_family_apis
'''
import os 
import csv 
import matplotlib
matplotlib.use('AGG')
import matplotlib.pyplot as plt
import numpy as np
import pickle as pkl

def generate_droidevolver_feature_idx():
    malware_dataset_csv = '/mnt/VirusShare/malware_dataset_vs_vt_amd.csv'
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    malware_dataset = []
    with open(malware_dataset_csv, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            malware_dataset.append(row)
    malware_dataset_droidevolver_feature = []
    idx = 0
    for row in malware_dataset:
        idx += 1
        md5 = row[0]
        first_seen = row[1]
        fs_year = int(first_seen.split('-')[0])
        feature_path = 'malware_feature/{}/{}.feature'.format(fs_year, md5)
        if os.path.exists(os.path.join(root_dir, feature_path)):
            malware_dataset_droidevolver_feature.append([md5, first_seen, feature_path])
        if idx % 1000 == 0:
            print('%d: %s' % (idx, md5))
    with open(os.path.join(root_dir, 'malware_dataset_droidevolver_feature_path.csv'), 'wb') as f:
        writer = csv.writer(f) 
        writer.writerows(malware_dataset_droidevolver_feature)
    print('finish')


def get_droidevolver_feature_path_dict():
    droidevolver_feature_path_dict = {}
    malware_droidevolver_feature_csv_path = '/mnt/AndroZoo/DroidEvolver_feature/malware_dataset_droidevolver_feature_path.csv'
    with open(malware_droidevolver_feature_csv_path, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            md5 = row[0]
            feature_path = row[2]
            droidevolver_feature_path_dict[md5] = feature_path
    return droidevolver_feature_path_dict    

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

def analyze_apis_from_droidevolver_feature(app_list, feature_path_dict):
    api_count_dict = {}
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    cnt = 0
    for row in app_list:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            cnt += 1
            with open(feature_abspath, 'r') as f:
                feature_list = pkl.load(f)
                for api in feature_list:
                    if api in api_count_dict:
                        api_count_dict[api] = api_count_dict[api] + 1
                    else:
                        api_count_dict[api] = 1
        else:
            print('not exist: %s' % (feature_abspath))
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

def count_apis_malware():
    seq_path_dict = get_seq_path_dict()
    malware_dataset_path = 'dataset_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in seq_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    for family_name in ['airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu']:
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
        with open('api_count/malware_%s_part_01_count.csv' % (family_name), 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(part_01_api_count_list)
        with open('api_count/malware_%s_part_02_count.csv' % (family_name), 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(part_02_api_count_list)
        sensitive_diff_cnt, nonsensitive_diff_cnt = diff_two_part_api_count(part_01_api_count_list, part_02_api_count_list)
        with open('api_count/malware_%s_diff_cnt_sensitive.csv' % family_name, 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(sensitive_diff_cnt)
        with open('api_count/malware_%s_diff_cnt_nonsensitive.csv' % family_name, 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(nonsensitive_diff_cnt)
        plot_diff_bar(sensitive_diff_cnt, nonsensitive_diff_cnt, 'malware_%s_diff_api_count' % family_name)

def update_stop_time(period_start_year_month, one_period):
    min_year = int(period_start_year_month/100)
    min_month = int(period_start_year_month%100)
    family_time_stop_year = min_year + int((min_month + one_period)/13)
    tmp_month = (min_month + one_period)
    if tmp_month == 12:  
        family_time_stop_month =  tmp_month
    else:
        family_time_stop_month = tmp_month%12
    period_end_year_month = int('%d%02d' % (family_time_stop_year, family_time_stop_month)) 
    return period_end_year_month 

def diff_two_period(period_left, period_right):
    delete_api_set = period_left - period_right
    common_api_set = period_left & period_right
    add_api_set = period_right - period_left
    return delete_api_set, common_api_set, add_api_set

def diff_two_period_dict(period_left, period_right):
    period_left = set(period_left.keys())
    period_right = set(period_right.keys())
    delete_api_set = period_left - period_right
    common_api_set = period_left & period_right
    add_api_set = period_right - period_left
    return delete_api_set, common_api_set, add_api_set

def parse_family_app_periods(family_app_periods, seq_path_dict, family_name):
    periods_api = []
    lldroid_output = '/mnt/VirusShare/lldroid_output/'
    idx = 0
    diff_period = []
    diff_p0_period = []
    diff_all_period = []
    previous_api_set = set()
    for period in family_app_periods:
        period_time = period[0]
        period_app_list = period[1]
        cnt = 0
        period_api_set = set()
        for row in period_app_list:
            md5 = row[0]
            seq_path = seq_path_dict[md5]
            seq_abspath = os.path.join(lldroid_output, seq_path)
            if os.path.exists(seq_abspath):
                cnt += 1
                with open(seq_abspath, 'r') as f:
                    apis = [line.strip() for line in f.readlines()]
                    for api in apis:
                        api = api.strip()
                        period_api_set.add(api)
            else:
                print('not exist: %s' % (seq_abspath))
        periods_api.append(period_api_set)
        if idx != 0:
            delete_api_set, common_api_set, add_api_set = diff_two_period(periods_api[idx - 1], periods_api[idx])
            diff_period.append([period_time, len(delete_api_set), len(common_api_set), len(add_api_set)])

            delete_p0_api_set, common_p0_api_set, add_p0_api_set = diff_two_period(periods_api[0], periods_api[idx])
            diff_p0_period.append([period_time, len(delete_p0_api_set), len(common_p0_api_set), len(add_p0_api_set)])
            
            delete_previous_api_set, common_previous_api_set, add_previous_api_set = diff_two_period(previous_api_set, period_api_set)
            diff_all_period.append([period_time, len(delete_previous_api_set), len(common_previous_api_set), len(add_previous_api_set)])
        previous_api_set.update(period_api_set)
        idx += 1
    plt.cla()
    plt.figure(figsize = (10, 8))
    x_label = [_[0] for _ in diff_period]
    delete_y_value = np.array([_[1] for _ in diff_period])
    common_y_value = np.array([_[2] for _ in diff_period])
    add_y_value = np.array([_[3] for _ in diff_period])
    plt.bar(x_label, common_y_value, color = '#B0C4DE', label = 'common apis') #  fc = 'g'
    plt.bar(x_label, -delete_y_value, color = '#00BFFF', label = 'delete apis') # fc = 'r', bottom = common_y_value
    plt.bar(x_label, add_y_value, color = '#4169E1', label = 'add apis', bottom =  common_y_value) # fc = 'b', delete_y_value +
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware %s period diff' % family_name)
    plt.savefig('api_count/malware_%s_period_diff.png' % family_name, dpi = 200)

    plt.cla()
    plt.figure(figsize = (10, 8))
    x_label = [_[0] for _ in diff_p0_period]
    delete_y_value = np.array([_[1] for _ in diff_p0_period])
    common_y_value = np.array([_[2] for _ in diff_p0_period])
    add_y_value = np.array([_[3] for _ in diff_p0_period])
    plt.bar(x_label, common_y_value, color = '#B0C4DE',label = 'common apis')
    plt.bar(x_label, -delete_y_value, color = '#00BFFF', label = 'delete apis') # , bottom = common_y_value
    plt.bar(x_label, add_y_value, color = '#4169E1', label = 'add apis', bottom = common_y_value) # delete_y_value + 
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware %s vs p0 period diff' % family_name)
    plt.savefig('api_count/malware_%s_vs_p0_period_diff.png' % family_name, dpi = 200)
    plt.clf()
    
    plt.cla()
    plt.figure(figsize = (10, 8))
    x_label = [_[0] for _ in diff_all_period]
    delete_y_value = np.array([_[1] for _ in diff_all_period])
    common_y_value = np.array([_[2] for _ in diff_all_period])
    add_y_value = np.array([_[3] for _ in diff_all_period])
    plt.bar(x_label, common_y_value, color = '#B0C4DE',label = 'common apis')
    plt.bar(x_label, -delete_y_value, color = '#00BFFF', label = 'delete apis') # , bottom = common_y_value
    plt.bar(x_label, add_y_value, color = '#4169E1', label = 'add apis', bottom = common_y_value) # delete_y_value + 
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware %s vs all previous period diff' % family_name)
    plt.savefig('api_count/malware_%s_vs_all_previous_period_diff.png' % family_name, dpi = 200)
    plt.clf()


def get_x_y_delete_common_add_labels(diff_period): 
    x_labels = []
    y_values = []
    for row in diff_period: # row [period_time, len(delete_api_set), len(common_api_set), len(add_api_set)]
        period_time = row[0]
        start_period_time = int(period_time.split('-')[0])
        end_period_time = int(period_time.split('-')[1])
        delete_api = row[1]
        common_api = row[2]
        add_api = row[3]
        x_labels.append(str(start_period_time))
        y_values.append([delete_api, common_api, add_api])
        tmp_end_period_time = update_stop_time(start_period_time, 3)
        while tmp_end_period_time < end_period_time:
            x_labels.append(str(tmp_end_period_time))
            y_values.append([0, 0, 0])
            tmp_end_period_time = update_stop_time(tmp_end_period_time, 3)
    delete_y_value = np.array([_[0] for _ in y_values])
    common_y_value = np.array([_[1] for _ in y_values])
    add_y_value = np.array([_[2] for _ in y_values])
    return x_labels, delete_y_value, common_y_value, add_y_value

def parse_family_app_periods_droidevolver(family_app_periods, feature_path_dict, family_name):
    periods_api = []
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    idx = 0
    diff_period = []
    diff_p0_period = []
    diff_all_period = []
    previous_api_set = set()
    for period in family_app_periods: # period ['%d-%d' % (period_start_year_month, period_end_year_month), period_row]
        period_time = period[0]
        period_app_list = period[1]
        cnt = 0
        period_api_set = set()
        for row in period_app_list:
            md5 = row[0]
            feature_path = feature_path_dict[md5]
            feature_abspath = os.path.join(root_dir, feature_path)
            if os.path.exists(feature_abspath):
                cnt += 1
                with open(feature_abspath, 'rb') as f:
                    apis = pkl.load(f)
                    for api in apis:
                        period_api_set.add(api)
            else:
                print('not exist: %s' % (feature_abspath))
        periods_api.append(period_api_set)
        if idx != 0:
            delete_api_set, common_api_set, add_api_set = diff_two_period(periods_api[idx - 1], periods_api[idx])
            diff_period.append([period_time, len(delete_api_set), len(common_api_set), len(add_api_set)])

            delete_p0_api_set, common_p0_api_set, add_p0_api_set = diff_two_period(periods_api[0], periods_api[idx])
            diff_p0_period.append([period_time, len(delete_p0_api_set), len(common_p0_api_set), len(add_p0_api_set)])
            
            delete_previous_api_set, common_previous_api_set, add_previous_api_set = diff_two_period(previous_api_set, period_api_set)
            diff_all_period.append([period_time, len(delete_previous_api_set), len(common_previous_api_set), len(add_previous_api_set)])
        else:
            diff_period.append([period_time, 0, len(period_api_set), 0]) # p0
            diff_p0_period.append([period_time, 0, len(period_api_set), 0]) # p0
            diff_all_period.append([period_time, 0, len(period_api_set), 0]) # p0
            
        previous_api_set.update(period_api_set)
        idx += 1
    plt.cla()
    plt.figure(figsize = (10, 8))
    x_label, delete_y_value, common_y_value, add_y_value = get_x_y_delete_common_add_labels(diff_period)
#     print(x_label)
#     print(delete_y_value)
#     print(common_y_value)
#     print(add_y_value)
#     delete_y_value = np.array([_[1] for _ in diff_period])
#     common_y_value = np.array([_[2] for _ in diff_period])
#     add_y_value = np.array([_[3] for _ in diff_period])
    plt.bar(x_label, common_y_value, color = '#B0C4DE', label = 'common apis') #  fc = 'g'
    plt.bar(x_label, -delete_y_value, color = '#00BFFF', label = 'delete apis') # fc = 'r', bottom = common_y_value
    plt.bar(x_label, add_y_value, color = '#4169E1', label = 'add apis', bottom =  common_y_value) # fc = 'b', delete_y_value +
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware %s period diff' % family_name)
    plt.savefig('api_count_droidevolver/malware_%s_period_diff.png' % family_name, dpi = 200)

    plt.cla()
    plt.figure(figsize = (10, 8))
    x_label, delete_y_value, common_y_value, add_y_value = get_x_y_delete_common_add_labels(diff_p0_period)
#     x_label = [_[0] for _ in diff_p0_period]
#     delete_y_value = np.array([_[1] for _ in diff_p0_period])
#     common_y_value = np.array([_[2] for _ in diff_p0_period])
#     add_y_value = np.array([_[3] for _ in diff_p0_period])
    plt.bar(x_label, common_y_value, color = '#B0C4DE',label = 'common apis')
    plt.bar(x_label, -delete_y_value, color = '#00BFFF', label = 'delete apis') # , bottom = common_y_value
    plt.bar(x_label, add_y_value, color = '#4169E1', label = 'add apis', bottom = common_y_value) # delete_y_value + 
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware %s vs p0 period diff' % family_name)
    plt.savefig('api_count_droidevolver/malware_%s_vs_p0_period_diff.png' % family_name, dpi = 200)
    plt.clf()
    
    plt.cla()
    plt.figure(figsize = (10, 8))
    x_label, delete_y_value, common_y_value, add_y_value = get_x_y_delete_common_add_labels(diff_all_period)
#     x_label = [_[0] for _ in diff_all_period]
#     delete_y_value = np.array([_[1] for _ in diff_all_period])
#     common_y_value = np.array([_[2] for _ in diff_all_period])
#     add_y_value = np.array([_[3] for _ in diff_all_period])
    plt.bar(x_label, common_y_value, color = '#B0C4DE',label = 'common apis')
    plt.bar(x_label, -delete_y_value, color = '#00BFFF', label = 'delete apis') # , bottom = common_y_value
    plt.bar(x_label, add_y_value, color = '#4169E1', label = 'add apis', bottom = common_y_value) # delete_y_value + 
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware %s vs all previous period diff' % family_name)
    plt.savefig('api_count_droidevolver/malware_%s_vs_all_previous_period_diff.png' % family_name, dpi = 200)
    plt.clf()

def count_api_evolver_in_family():
    seq_path_dict = get_seq_path_dict()
    malware_dataset_path = 'dataset_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in seq_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    period_month = 3 # 3 months
    for family_name in ['airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu']: # , 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        family_app_periods = []
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, period_month)
        one_period = []
        period_id = 0
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                one_period.append(row)
#             elif period_id == 0:
#                 if len(one_period) < 50:
#                     one_period.append(row)
#                     period_end_year_month = update_stop_time(first_year_month, 1)
#                 else:
#                     family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), one_period])
#                     one_period = [row]
#                     period_id += 1
#                     period_start_year_month = period_end_year_month
#                     period_end_year_month = update_stop_time(period_start_year_month, period_month)
            else:
                if len(one_period) >= 50:
                    period_id += 1
                    family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), one_period])
                    one_period = [row]
                    period_start_year_month = period_end_year_month
                    period_end_year_month = update_stop_time(period_start_year_month, period_month)
                else:
                    one_period.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, 1)
        if len(one_period) >= 50:
            family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), one_period])
        parse_family_app_periods(family_app_periods, seq_path_dict, family_name)
        print(family_name),
        for row in family_app_periods:
            print('%s:%d ' % (row[0], len(row[1]))),
        print('')


def diff_two_period_with_frequency(previous_period_api_dict, previous_cnt, next_period_api_dict, next_cnt, average_frequency_diff):
    previous_apis_set = set(previous_period_api_dict.keys())
    next_apis_set = set(next_period_api_dict.keys())
    delete_api_set = previous_apis_set - next_apis_set
    add_api_set = next_apis_set - previous_apis_set
    original_common_api_set = previous_apis_set & next_apis_set
    common_api_set = set()
    diff_frequency_api_set = set()
    for api in original_common_api_set:
        previous_frequency = previous_period_api_dict[api]/float(previous_cnt)
        next_frequency = next_period_api_dict[api]/float(next_cnt)
        if abs(previous_frequency - next_frequency) >= (average_frequency_diff * previous_frequency):
            diff_frequency_api_set.add(api)
        else:
            common_api_set.add(api)
    return delete_api_set, common_api_set, diff_frequency_api_set, add_api_set    

def parse_family_app_two_periods(previous_period, next_period, seq_path_dict, family_name, average_frequency_diff):
    lldroid_output = '/mnt/VirusShare/lldroid_output/'
    previous_period_time = previous_period[0]
    previous_period_api_dict = {}
    previous_cnt = 0
    for row in previous_period[1]:
        md5 = row[0]
        seq_path = seq_path_dict[md5]
        seq_abspath = os.path.join(lldroid_output, seq_path)
        if os.path.exists(seq_abspath):
            previous_cnt += 1
            with open(seq_abspath, 'r') as f:
                apis = [line.strip() for line in f.readlines()]
                for api in apis:
                    api = api.strip()
                    if api not in previous_period_api_dict:
                        previous_period_api_dict[api] = 0
                    previous_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (seq_abspath)) 
    
    next_period_time = next_period[0]
    next_period_api_dict = {}
    next_cnt = 0
    for row in next_period[1]:
        md5 = row[0]
        seq_path = seq_path_dict[md5]
        seq_abspath = os.path.join(lldroid_output, seq_path)
        if os.path.exists(seq_abspath):
            next_cnt += 1
            with open(seq_abspath, 'r') as f:
                apis = [line.strip() for line in f.readlines()]
                for api in apis:
                    api = api.strip()
                    if api not in next_period_api_dict:
                        next_period_api_dict[api] = 0
                    next_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (seq_abspath)) 
    delete_apis_set, common_apis_set, diff_frequency_apis_set, add_apis_set = diff_two_period_with_frequency(previous_period_api_dict, previous_cnt, 
                                                                                                             next_period_api_dict, next_cnt, average_frequency_diff)
    len_delete = len(delete_apis_set)
    len_common = len(common_apis_set)
    len_diff_frequency = len(diff_frequency_apis_set)
    len_add = len(add_apis_set)
    diff_rate = float(len_delete + len_diff_frequency + len_add)/ (len_delete + len_common + len_diff_frequency)
    print('%s previous %d app: %s next %d app: %s diff_rate: %f %d %d %d %d' % (family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_diff_frequency, len_add ))
    return [family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_diff_frequency, len_add]


def parse_family_app_two_periods_droidevolver_with_diff_frequency(previous_period, next_period, feature_path_dict, family_name, average_frequency_diff):
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    previous_period_time = previous_period[0]
    previous_period_api_dict = {}
    previous_cnt = 0
    for row in previous_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            previous_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in previous_period_api_dict:
                        previous_period_api_dict[api] = 0
                    previous_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath)) 
    
    next_period_time = next_period[0]
    next_period_api_dict = {}
    next_cnt = 0
    for row in next_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            next_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in next_period_api_dict:
                        next_period_api_dict[api] = 0
                    next_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath)) 

    delete_apis_set, common_apis_set, diff_frequency_apis_set, add_apis_set = diff_two_period_with_frequency(previous_period_api_dict, previous_cnt, 
                                                                                                             next_period_api_dict, next_cnt, average_frequency_diff)
    len_delete = len(delete_apis_set)
    len_common = len(common_apis_set)
    len_diff_frequency = len(diff_frequency_apis_set)
    len_add = len(add_apis_set)
    diff_rate = float(len_delete + len_diff_frequency + len_add)/ (len_delete + len_common + len_diff_frequency)
    print('%s previous %d app: %s next %d app: %s diff_rate: %f %d %d %d %d' % (family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_diff_frequency, len_add ))
    return [family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_diff_frequency, len_add]

def parse_family_app_two_periods_droidevolver_with_diff_frequency_sensitive_method(previous_period, next_period, feature_path_dict, family_name, average_frequency_diff, sensitive_methods):
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    previous_period_time = previous_period[0]
    previous_period_api_dict = {}
    previous_cnt = 0
    for row in previous_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            previous_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in sensitive_methods:
                        continue
                    if api not in previous_period_api_dict:
                        previous_period_api_dict[api] = 0
                    previous_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath)) 
    
    next_period_time = next_period[0]
    next_period_api_dict = {}
    next_cnt = 0
    for row in next_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            next_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in sensitive_methods:
                        continue
                    if api not in next_period_api_dict:
                        next_period_api_dict[api] = 0
                    next_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath)) 

    delete_apis_set, common_apis_set, diff_frequency_apis_set, add_apis_set = diff_two_period_with_frequency(previous_period_api_dict, previous_cnt, 
                                                                                                             next_period_api_dict, next_cnt, average_frequency_diff)
    len_delete = len(delete_apis_set)
    len_common = len(common_apis_set)
    len_diff_frequency = len(diff_frequency_apis_set)
    len_add = len(add_apis_set)
    diff_rate = float(len_delete + len_diff_frequency + len_add)/ (len_delete + len_common + len_diff_frequency)
    print('%s previous %d app: %s next %d app: %s diff_rate: %f %d %d %d %d' % (family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_diff_frequency, len_add ))
    return [family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_diff_frequency, len_add]

def parse_family_app_two_periods_droidevolver(previous_period, next_period, feature_path_dict, family_name):
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    previous_period_time = previous_period[0]
    previous_period_api_dict = {}
    previous_cnt = 0
    for row in previous_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            previous_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in previous_period_api_dict:
                        previous_period_api_dict[api] = 0
                    previous_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath)) 
    
    next_period_time = next_period[0]
    next_period_api_dict = {}
    next_cnt = 0
    for row in next_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            next_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in next_period_api_dict:
                        next_period_api_dict[api] = 0
                    next_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath))
    delete_apis_set, common_apis_set, add_apis_set = diff_two_period_dict(previous_period_api_dict, next_period_api_dict)
    len_delete = len(delete_apis_set)
    len_common = len(common_apis_set)
    len_add = len(add_apis_set)
    diff_rate = float(len_delete + len_add)/ (len_delete + len_common)
    print('%s previous %d app: %s next %d app: %s diff_rate: %f %d %d %d' % (family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_add ))
    return [family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_add]


def parse_family_app_two_periods_droidevolver_sensitive_method(previous_period, next_period, feature_path_dict, family_name, sensitive_methods):
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    previous_period_time = previous_period[0]
    previous_period_api_dict = {}
    previous_cnt = 0
    for row in previous_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            previous_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in sensitive_methods:
                        continue
                    if api not in previous_period_api_dict:
                        previous_period_api_dict[api] = 0
                    previous_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath)) 
    
    next_period_time = next_period[0]
    next_period_api_dict = {}
    next_cnt = 0
    for row in next_period[1]:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            next_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    if api not in sensitive_methods:
                        continue
                    if api not in next_period_api_dict:
                        next_period_api_dict[api] = 0
                    next_period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath))
    delete_apis_set, common_apis_set, add_apis_set = diff_two_period_dict(previous_period_api_dict, next_period_api_dict)
    len_delete = len(delete_apis_set)
    len_common = len(common_apis_set)
    len_add = len(add_apis_set)
    diff_rate = float(len_delete + len_add)/ (len_delete + len_common)
    print('%s previous %d app: %s next %d app: %s diff_rate: %f %d %d %d' % (family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_add ))
    return [family_name, previous_cnt, previous_period_time, next_cnt, next_period_time, 
                                                    diff_rate, len_delete, len_common, len_add]


def plot_two_period_with_diff_frequency():
    families_diff = []
    with open('top_families_diff_droidevolver_with_frequency_0.10.csv') as f:
        reader = csv.reader(f) 
        for row in reader:
            family_name = row[0]
            previous_period_app_num = int(row[1])
            previous_period_time = row[2]
            next_period_app_num = int(row[3])
            next_period_time = row[4]
            diff_rate = float(row[5])
            delete_api = int(row[6])
            common_api = int(row[7])
            diff_freq_api = int(row[8])
            add_api = int(row[9])
            families_diff.append([family_name, previous_period_time, next_period_time, delete_api, common_api, diff_freq_api, add_api])
    families_x_label = []
    families_delete_label = []
    families_common_label = []
    families_diff_freq_label = []
    families_add_label = []
    for row in families_diff:
        family_name = row[0]
        delete_api = row[3]
        common_api = row[4]
        diff_freq_api = row[5]
        add_api = row[6]
        families_x_label.append(family_name)
        families_delete_label.append(delete_api)
        families_common_label.append(common_api)
        families_diff_freq_label.append(diff_freq_api)
        families_add_label.append(add_api)
    families_delete_label = np.array(families_delete_label)
    families_common_label = np.array(families_common_label)
    families_diff_freq_label = np.array(families_diff_freq_label)
    families_add_label = np.array(families_add_label)
    plt.cla()
    plt.figure(figsize = (10, 8))
    plt.bar(families_x_label, - families_delete_label, color = '#00BFFF', label = 'family delete apis')
    plt.bar(families_x_label, families_common_label, color = '#B0C4DE', label = 'family common apis')
    plt.bar(families_x_label, families_diff_freq_label, color = '#4682B4', label = 'family diff frequency apis', bottom = families_common_label)
    plt.bar(families_x_label, families_add_label, color = '#4169E1', label = 'family add apis', bottom = families_common_label + families_diff_freq_label)
    plt.tick_params(labelsize=4)
    plt.legend()
    plt.title('malware families period diff apis')
    plt.savefig('diff_api/malware_families_period_diff_apis_with_diff_freq.png', dpi = 300)

    plt.cla()
    plt.figure(figsize = (10, 8))
#     plt.bar(families_x_label, - families_delete_label, color = '#00BFFF', label = 'family delete apis')
    plt.bar(families_x_label, families_common_label, color = '#B0C4DE', label = 'family common apis')
    plt.bar(families_x_label, families_diff_freq_label, color = '#4682B4', label = 'family diff frequency apis', bottom = families_common_label)
#     plt.bar(families_x_label, families_add_label, color = '#4169E1', label = 'family add apis', bottom = families_common_label + families_diff_freq_label)
    plt.tick_params(labelsize=4)
    plt.legend()
    plt.title('malware families period diff between common apis')
    plt.savefig('diff_api/malware_families_period_diff_apis_with_diff_freq_simplified.png', dpi = 300)
    
    families_diff_freq_label = families_diff_freq_label.astype('float')
    print(families_x_label)
    print(families_diff_freq_label/(families_common_label + families_diff_freq_label))

def plot_two_period_with_diff_frequency_sensitive_method():
    families_diff = []
    with open('top_families_diff_droidevolver_with_frequency_sensitive_method_0.10.csv') as f:
        reader = csv.reader(f) 
        for row in reader:
            family_name = row[0]
            previous_period_app_num = int(row[1])
            previous_period_time = row[2]
            next_period_app_num = int(row[3])
            next_period_time = row[4]
            diff_rate = float(row[5])
            delete_api = int(row[6])
            common_api = int(row[7])
            diff_freq_api = int(row[8])
            add_api = int(row[9])
            families_diff.append([family_name, previous_period_time, next_period_time, delete_api, common_api, diff_freq_api, add_api])
    families_x_label = []
    families_delete_label = []
    families_common_label = []
    families_diff_freq_label = []
    families_add_label = []
    for row in families_diff:
        family_name = row[0]
        delete_api = row[3]
        common_api = row[4]
        diff_freq_api = row[5]
        add_api = row[6]
        families_x_label.append(family_name)
        families_delete_label.append(delete_api)
        families_common_label.append(common_api)
        families_diff_freq_label.append(diff_freq_api)
        families_add_label.append(add_api)
    families_delete_label = np.array(families_delete_label)
    families_common_label = np.array(families_common_label)
    families_diff_freq_label = np.array(families_diff_freq_label)
    families_add_label = np.array(families_add_label)
    plt.cla()
    plt.figure(figsize = (10, 8))
    plt.bar(families_x_label, - families_delete_label, color = '#00BFFF', label = 'family delete sensitive apis')
    plt.bar(families_x_label, families_common_label, color = '#B0C4DE', label = 'family common sensitive apis')
    plt.bar(families_x_label, families_diff_freq_label, color = '#4682B4', label = 'family diff frequency sensitive apis', bottom = families_common_label)
    plt.bar(families_x_label, families_add_label, color = '#4169E1', label = 'family add sensitive apis', bottom = families_common_label + families_diff_freq_label)
    plt.tick_params(labelsize=4)
    plt.legend()
    plt.title('malware families period diff sensitive apis')
    plt.savefig('diff_sensitive_api/malware_families_period_diff_apis_with_diff_freq_sensitive_method.png', dpi = 300)

    plt.cla()
    plt.figure(figsize = (10, 8))
#     plt.bar(families_x_label, - families_delete_label, color = '#00BFFF', label = 'family delete apis')
    plt.bar(families_x_label, families_common_label, color = '#B0C4DE', label = 'family common sensitive apis')
    plt.bar(families_x_label, families_diff_freq_label, color = '#4682B4', label = 'family diff frequency sensitive apis', bottom = families_common_label)
#     plt.bar(families_x_label, families_add_label, color = '#4169E1', label = 'family add apis', bottom = families_common_label + families_diff_freq_label)
    plt.tick_params(labelsize=4)
    plt.legend()
    plt.title('malware families period diff between common sensitive apis')
    plt.savefig('diff_sensitive_api/malware_families_period_diff_apis_with_diff_freq_simplified_sensitive_method.png', dpi = 300)
    
    families_diff_freq_label = families_diff_freq_label.astype('float')
    print(families_x_label)
    print(families_diff_freq_label/(families_common_label + families_diff_freq_label))

        
#     for row in families_diff:
#         family_name = row[0]
#         previous_period_time = row[1]
#         start_period_time = int(previous_period_time.split('-')[0])
#         end_period_time = int(previous_period_time.split('-')[1])
#         delete_api = row[3]
#         common_api = row[4]
#         add_api = row[5]
#         x_labels = [str(start_period_time)]
#         y_values = [[delete_api, common_api, 0]]
#         tmp_end_period_time = update_stop_time(start_period_time, 3)
#         while tmp_end_period_time < end_period_time:
#             x_labels.append(str(tmp_end_period_time))
#             y_values.append([0, 0, 0])
#             tmp_end_period_time = update_stop_time(tmp_end_period_time, 3)
#         start_period_time = int(next_period_time.split('-')[0])
#         end_period_time = int(next_period_time.split('-')[1])
#         x_labels.append(str(start_period_time))
#         y_values.append([delete_api, common_api, add_api])
#         tmp_end_period_time = update_stop_time(start_period_time, 3)
#         while tmp_end_period_time < end_period_time:
#             x_labels.append(str(tmp_end_period_time))
#             y_values.append([0, 0, 0])
#             tmp_end_period_time = update_stop_time(tmp_end_period_time, 3)
#         plt.cla()
#         plt.figure(figsize = (10, 8))
#         delete_y_value = np.array([_[0] for _ in y_values])
#         common_y_value = np.array([_[1] for _ in y_values])
#         add_y_value = np.array([_[2] for _ in y_values])
# #         print(x_labels)
# #         print(delete_y_value)
# #         print(common_y_value)
# #         print(add_y_value)
#         plt.bar(x_labels, - delete_y_value, color = '#00BFFF', label = 'delete apis')
#         plt.bar(x_labels, common_y_value, color = '#B0C4DE', label = 'common apis')
#         plt.bar(x_labels, add_y_value, color = '#4169E1', label = 'add apis', bottom = common_y_value)
#         plt.tick_params(labelsize=5)
#         plt.legend()
#         plt.title('malware %s period diff apis' % family_name)
#         plt.savefig('diff_api/malware_%s_period_diff_apis.png' % family_name, dpi = 300)
#     print('finish')


def plot_two_period():
    families_diff = []
    with open('top_families_diff_droidevolver.csv') as f:
        reader = csv.reader(f) 
        for row in reader:
            family_name = row[0]
            previous_period_app_num = int(row[1])
            previous_period_time = row[2]
            next_period_app_num = int(row[3])
            next_period_time = row[4]
            diff_rate = float(row[5])
            delete_api = int(row[6])
            common_api = int(row[7])
            add_api = int(row[8])
            families_diff.append([family_name, previous_period_time, next_period_time, delete_api, common_api, add_api])
    families_x_label = []
    families_delete_label = []
    families_common_label = []
    families_add_label = []
    for row in families_diff:
        family_name = row[0]
        delete_api = row[3]
        common_api = row[4]
        add_api = row[5]
        families_x_label.append(family_name)
        families_delete_label.append(delete_api)
        families_common_label.append(common_api)
        families_add_label.append(add_api)
    families_delete_label = np.array(families_delete_label)
    families_common_label = np.array(families_common_label)
    families_add_label = np.array(families_add_label)
    plt.cla()
    plt.figure(figsize = (10, 8))
    plt.bar(families_x_label, - families_delete_label, color = '#00BFFF', label = 'family delete apis')
    plt.bar(families_x_label, families_common_label, color = '#B0C4DE', label = 'family common apis')
    plt.bar(families_x_label, families_add_label, color = '#4169E1', label = 'family add apis', bottom = families_common_label)
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware families period diff apis')
    plt.savefig('diff_api/malware_families_period_diff_apis.png', dpi = 300)
    
        
    for row in families_diff:
        family_name = row[0]
        previous_period_time = row[1]
        start_period_time = int(previous_period_time.split('-')[0])
        end_period_time = int(previous_period_time.split('-')[1])
        delete_api = row[3]
        common_api = row[4]
        add_api = row[5]
        x_labels = [str(start_period_time)]
        y_values = [[delete_api, common_api, 0]]
        tmp_end_period_time = update_stop_time(start_period_time, 3)
        while tmp_end_period_time < end_period_time:
            x_labels.append(str(tmp_end_period_time))
            y_values.append([0, 0, 0])
            tmp_end_period_time = update_stop_time(tmp_end_period_time, 3)
        start_period_time = int(next_period_time.split('-')[0])
        end_period_time = int(next_period_time.split('-')[1])
        x_labels.append(str(start_period_time))
        y_values.append([delete_api, common_api, add_api])
        tmp_end_period_time = update_stop_time(start_period_time, 3)
        while tmp_end_period_time < end_period_time:
            x_labels.append(str(tmp_end_period_time))
            y_values.append([0, 0, 0])
            tmp_end_period_time = update_stop_time(tmp_end_period_time, 3)
        plt.cla()
        plt.figure(figsize = (10, 8))
        delete_y_value = np.array([_[0] for _ in y_values])
        common_y_value = np.array([_[1] for _ in y_values])
        add_y_value = np.array([_[2] for _ in y_values])
#         print(x_labels)
#         print(delete_y_value)
#         print(common_y_value)
#         print(add_y_value)
        plt.bar(x_labels, - delete_y_value, color = '#00BFFF', label = 'delete apis')
        plt.bar(x_labels, common_y_value, color = '#B0C4DE', label = 'common apis')
        plt.bar(x_labels, add_y_value, color = '#4169E1', label = 'add apis', bottom = common_y_value)
        plt.tick_params(labelsize=5)
        plt.legend()
        plt.title('malware %s period diff apis' % family_name)
        plt.savefig('diff_api/malware_%s_period_diff_apis.png' % family_name, dpi = 300)
    print('finish')


def plot_two_period_sensitive_method():
    families_diff = []
    with open('top_families_diff_droidevolver_sensitive_method_0.10.csv') as f:
        reader = csv.reader(f) 
        for row in reader:
            family_name = row[0]
            previous_period_app_num = int(row[1])
            previous_period_time = row[2]
            next_period_app_num = int(row[3])
            next_period_time = row[4]
            diff_rate = float(row[5])
            delete_api = int(row[6])
            common_api = int(row[7])
            add_api = int(row[8])
            families_diff.append([family_name, previous_period_time, next_period_time, delete_api, common_api, add_api])
    families_x_label = []
    families_delete_label = []
    families_common_label = []
    families_add_label = []
    for row in families_diff:
        family_name = row[0]
        delete_api = row[3]
        common_api = row[4]
        add_api = row[5]
        families_x_label.append(family_name)
        families_delete_label.append(delete_api)
        families_common_label.append(common_api)
        families_add_label.append(add_api)
    families_delete_label = np.array(families_delete_label)
    families_common_label = np.array(families_common_label)
    families_add_label = np.array(families_add_label)
    plt.cla()
    plt.figure(figsize = (10, 8))
    plt.bar(families_x_label, - families_delete_label, color = '#00BFFF', label = 'family delete sensitive apis')
    plt.bar(families_x_label, families_common_label, color = '#B0C4DE', label = 'family common sensitive apis')
    plt.bar(families_x_label, families_add_label, color = '#4169E1', label = 'family add sensitive apis', bottom = families_common_label)
    plt.tick_params(labelsize=5)
    plt.legend()
    plt.title('malware families period diff sensitive apis')
    plt.savefig('diff_sensitive_api/malware_families_period_diff_sensitive_apis.png', dpi = 300)
    
        
    for row in families_diff:
        family_name = row[0]
        previous_period_time = row[1]
        start_period_time = int(previous_period_time.split('-')[0])
        end_period_time = int(previous_period_time.split('-')[1])
        delete_api = row[3]
        common_api = row[4]
        add_api = row[5]
        x_labels = [str(start_period_time)]
        y_values = [[delete_api, common_api, 0]]
        tmp_end_period_time = update_stop_time(start_period_time, 3)
        while tmp_end_period_time < end_period_time:
            x_labels.append(str(tmp_end_period_time))
            y_values.append([0, 0, 0])
            tmp_end_period_time = update_stop_time(tmp_end_period_time, 3)
        start_period_time = int(next_period_time.split('-')[0])
        end_period_time = int(next_period_time.split('-')[1])
        x_labels.append(str(start_period_time))
        y_values.append([delete_api, common_api, add_api])
        tmp_end_period_time = update_stop_time(start_period_time, 3)
        while tmp_end_period_time < end_period_time:
            x_labels.append(str(tmp_end_period_time))
            y_values.append([0, 0, 0])
            tmp_end_period_time = update_stop_time(tmp_end_period_time, 3)
        plt.cla()
        plt.figure(figsize = (10, 8))
        delete_y_value = np.array([_[0] for _ in y_values])
        common_y_value = np.array([_[1] for _ in y_values])
        add_y_value = np.array([_[2] for _ in y_values])
#         print(x_labels)
#         print(delete_y_value)
#         print(common_y_value)
#         print(add_y_value)
        plt.bar(x_labels, - delete_y_value, color = '#00BFFF', label = 'delete sensitive apis')
        plt.bar(x_labels, common_y_value, color = '#B0C4DE', label = 'common sensitive apis')
        plt.bar(x_labels, add_y_value, color = '#4169E1', label = 'add sensitive apis', bottom = common_y_value)
        plt.tick_params(labelsize=5)
        plt.legend()
        plt.title('malware %s period diff sensitive apis' % family_name)
        plt.savefig('diff_sensitive_api/malware_%s_period_diff_sensitive_apis.png' % family_name, dpi = 300)
    print('finish')


def get_all_families_periods(min_x_month_after, min_rate, feature_path_dict):
    malware_dataset_path = 'dataset_euphony_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in feature_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    all_families_periods = {}
    for family_name in family_app: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        if len(family_app[family_name]) < 500:
            continue
        family_app_periods = []
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                period_row.append(row)
            else:
                if len(period_row) < min_app_num:
                    period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, min_x_month_after)
                else:
                    family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), period_row])
                    period_row = []
                    period_start_year_month = period_end_year_month
                    period_end_year_month = update_stop_time(period_end_year_month, min_x_month_after)
        if len(period_row) >= (min_app_num/2):
            family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), period_row])
        all_families_periods[family_name] = family_app_periods
        print(family_name),
        for row in family_app_periods:
            print('%s:%d ' % (row[0], len(row[1]))),
        print('')
    return all_families_periods


def get_periods_interested_method(family_app_period, interested_method, feature_path_dict):
    root_dir = '/mnt/AndroZoo/DroidEvolver_feature'
    period_api_dict = {}
    app_cnt = 0
    for row in family_app_period:
        md5 = row[0]
        feature_path = feature_path_dict[md5]
        feature_abspath = os.path.join(root_dir, feature_path)
        if os.path.exists(feature_abspath):
            app_cnt += 1
            with open(feature_abspath, 'rb') as f:
                apis = pkl.load(f)
                for api in apis:
                    api = api.replace(':', '.')
                    if api not in interested_method:
                        continue
                    if api not in period_api_dict:
                        period_api_dict[api] = 0
                    period_api_dict[api] += 1
        else:
            print('not exist: %s' % (feature_abspath)) 
    for method in period_api_dict:
        period_api_dict[method] = period_api_dict[method]/float(app_cnt) # average
    return period_api_dict

def analyze_top_families_diff_data():
    diff_rate_bound = [0.1, 0.3, 0.5, 1, 5]
    diff_rate_families = [[] for _ in range(len(diff_rate_bound) + 1)]
    span_month_sum = 0
    span_month_families = []
    diff_rate_big_num = 0
    with open('top_families_diff_droidevolver.csv') as f:
        reader = csv.reader(f) 
        for row in reader:
            family_name = row[0]
            previous_period_app_num = int(row[1])
            previous_period_time = row[2]
            next_period_app_num = int(row[3])
            next_period_time = row[4]
            diff_rate = float(row[5])
            delete_api = int(row[6])
            common_api = int(row[7])
            add_api = int(row[8])
            idx = 0
            while idx < len(diff_rate_bound):
                if diff_rate < diff_rate_bound[idx]:
                    break
                idx += 1
            diff_rate_families[idx].append(family_name)
            if idx >= 0:
                start_period_year = int(next_period_time.split('-')[0][0:4])
                start_period_month = int(next_period_time.split('-')[0][4:])
                end_period_year = int(next_period_time.split('-')[1][0:4])
                end_period_month = int(next_period_time.split('-')[1][4:])
                span_month = (end_period_year * 12 + end_period_month) - (start_period_year * 12 + start_period_month)
                if  span_month <= 6 and diff_rate >= 0.3:
                    diff_rate_big_num += 1
                    span_month_sum += span_month
                    span_month_families.append([family_name, span_month])
    span_month_families.sort(key = lambda x:x[1])
    print(diff_rate_big_num)
    print(span_month_families)
    print('average span month: %f' % (span_month_sum/float(len(span_month_families))))
    x_label = []
    for i in range(len(diff_rate_bound)):
        if i == 0:
            x_label.append('0%%~%.0f%%' % (diff_rate_bound[i]*100))
        else:
            x_label.append('%.0f%%~%.0f%%' % (diff_rate_bound[i-1] * 100, diff_rate_bound[i]*100))
    x_label.append('above %.0f%%' % (diff_rate_bound[-1] * 100))
    y_values = [len(_) for _ in diff_rate_families]
    print(x_label)
    print(y_values)
    plt.cla()
    plt.figure(figsize = (10, 8))
    plt.xticks(np.arange(len(x_label)), x_label)
    plt.bar(np.arange(len(y_values)), y_values, width = 0.5)
    plt.title('diff rate in families')
    plt.savefig('diff_rate_in_families.png', dpi = 300)
# #             families_diff.append([family_name, previous_period_time, next_period_time, delete_api, common_api, add_api])


def count_api_unstability_v0(x_month_after, average_frequency_diff): # X month after the malicious family appears,  Y of all families changed at least Z% APIs
    seq_path_dict = get_seq_path_dict()
    malware_dataset_path = 'dataset_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in seq_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    for family_name in ['airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu']: # , 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, x_month_after)
        previous_period_row = []
        next_period_row = []
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                next_period_row.append(row)
                if len(next_period_row) >= len(previous_period_row):
                    next_end_year_month = first_year_month
                    break
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        parse_family_app_two_periods(previous_period, next_period, seq_path_dict, family_name, average_frequency_diff)

def count_api_unstability_v1(min_x_month_after, average_frequency_diff): # X month after the malicious family appears,  Y of all families changed at least Z% APIs
    seq_path_dict = get_seq_path_dict()
    malware_dataset_path = 'dataset_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in seq_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    for family_name in ['airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu']: # , 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        previous_period_row = []
        next_period_row = []
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                if len(previous_period_row) < 50:
                    previous_period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, 1)
                else:
                    if first_year_month < update_stop_time(period_end_year_month, 3):
                        next_period_row.append(row)
                    else:
                        break
        next_end_year_month = update_stop_time(period_end_year_month, 3)         
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        parse_family_app_two_periods(previous_period, next_period, seq_path_dict, family_name, average_frequency_diff)

def count_api_unstability_v2(min_x_month_after, average_frequency_diff, min_rate): # X month after the malicious family appears,  Y of all families changed at least Z% APIs
    seq_path_dict = get_seq_path_dict()
    malware_dataset_path = 'dataset_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in seq_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    families_diff = []
    for family_name in ['airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu']: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        next_end_year_month = update_stop_time(period_end_year_month, 3)
        previous_period_row = []
        next_period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                if len(previous_period_row) < min_app_num:
                    previous_period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, 3)
                    next_end_year_month = update_stop_time(period_end_year_month, 3)
                else:
                    if first_year_month < next_end_year_month:
                        next_period_row.append(row)
                    else:
                        if len(next_period_row) < min_app_num:
                            next_period_row.append(row)
                            next_end_year_month = update_stop_time(next_end_year_month, 3)
#                             print(next_end_year_month)
                        else:
                            break
#         next_end_year_month = update_stop_time(period_end_year_month, 3)         
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        family_diff = parse_family_app_two_periods(previous_period, next_period, seq_path_dict, family_name, average_frequency_diff)
        families_diff.append(family_diff)
    with open('top_families_diff.csv', 'wb') as f:
        writer = csv.writer(f)
        writer.writerows(families_diff)

def count_api_unstability_v3(min_x_month_after, min_rate): # get api from droidevolver feature
    feature_path_dict = get_droidevolver_feature_path_dict()
    malware_dataset_path = 'dataset_euphony_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in feature_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    families_diff = []
    for family_name in family_app: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        if len(family_app[family_name]) < 500:
            continue
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        next_end_year_month = update_stop_time(period_end_year_month, 3)
        previous_period_row = []
        next_period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                if len(previous_period_row) < min_app_num:
                    previous_period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, 3)
                    next_end_year_month = update_stop_time(period_end_year_month, 3)
                else:
                    if first_year_month < next_end_year_month:
                        next_period_row.append(row)
                    else:
                        if len(next_period_row) < min_app_num:
                            next_period_row.append(row)
                            next_end_year_month = update_stop_time(next_end_year_month, 3)
#                             print(next_end_year_month)
                        else:
                            break
#         next_end_year_month = update_stop_time(period_end_year_month, 3)         
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        family_diff = parse_family_app_two_periods_droidevolver(previous_period, next_period, feature_path_dict, family_name)
        families_diff.append(family_diff)
    with open('top_families_diff_droidevolver_%0.2f.csv' % min_rate, 'wb') as f:
        writer = csv.writer(f)
        writer.writerows(families_diff)

def count_api_unstability_v3_sensitive_method(min_x_month_after, min_rate): # get api from droidevolver feature
    sensitive_apis = get_sensitive_api()
    sensitive_methods = set()
    for method in sensitive_apis: # translate the format of method string 
        method = method.replace('->', ':')
        sensitive_methods.add(method)
    feature_path_dict = get_droidevolver_feature_path_dict()
    malware_dataset_path = 'dataset_euphony_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in feature_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    families_diff = []
    for family_name in family_app: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        if len(family_app[family_name]) < 500:
            continue
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        next_end_year_month = update_stop_time(period_end_year_month, 3)
        previous_period_row = []
        next_period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                if len(previous_period_row) < min_app_num:
                    previous_period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, 3)
                    next_end_year_month = update_stop_time(period_end_year_month, 3)
                else:
                    if first_year_month < next_end_year_month:
                        next_period_row.append(row)
                    else:
                        if len(next_period_row) < min_app_num:
                            next_period_row.append(row)
                            next_end_year_month = update_stop_time(next_end_year_month, 3)
#                             print(next_end_year_month)
                        else:
                            break
#         next_end_year_month = update_stop_time(period_end_year_month, 3)         
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        family_diff = parse_family_app_two_periods_droidevolver_sensitive_method(previous_period, next_period, feature_path_dict, family_name, sensitive_methods)
        families_diff.append(family_diff)
    with open('top_families_diff_droidevolver_sensitive_method_%0.2f.csv' % min_rate, 'wb') as f:
        writer = csv.writer(f)
        writer.writerows(families_diff)

def count_api_unstability_v4(min_x_month_after, min_rate, diff_average_frequency): # get api from droidevolver feature
    feature_path_dict = get_droidevolver_feature_path_dict()
    malware_dataset_path = 'dataset_euphony_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in feature_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    families_diff = []
    for family_name in family_app: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        if len(family_app[family_name]) < 500:
            continue
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        next_end_year_month = update_stop_time(period_end_year_month, 3)
        previous_period_row = []
        next_period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                if len(previous_period_row) < min_app_num:
                    previous_period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, 3)
                    next_end_year_month = update_stop_time(period_end_year_month, 3)
                else:
                    if first_year_month < next_end_year_month:
                        next_period_row.append(row)
                    else:
                        if len(next_period_row) < min_app_num:
                            next_period_row.append(row)
                            next_end_year_month = update_stop_time(next_end_year_month, 3)
#                             print(next_end_year_month)
                        else:
                            break
#         next_end_year_month = update_stop_time(period_end_year_month, 3)         
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        family_diff = parse_family_app_two_periods_droidevolver_with_diff_frequency(previous_period, next_period, feature_path_dict, family_name, diff_average_frequency)
        families_diff.append(family_diff)
    with open('top_families_diff_droidevolver_with_frequency_%0.2f.csv' % min_rate, 'wb') as f:
        writer = csv.writer(f)
        writer.writerows(families_diff)

def count_api_unstability_v4_sensitive_method(min_x_month_after, min_rate, diff_average_frequency): # get api from droidevolver feature
    sensitive_apis = get_sensitive_api()
    sensitive_methods = set()
    for method in sensitive_apis: # translate the format of method string 
        method = method.replace('->', ':')
        sensitive_methods.add(method)
    feature_path_dict = get_droidevolver_feature_path_dict()
    malware_dataset_path = 'dataset_euphony_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in feature_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    families_diff = []
    for family_name in family_app: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        if len(family_app[family_name]) < 500:
            continue
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        next_end_year_month = update_stop_time(period_end_year_month, 3)
        previous_period_row = []
        next_period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                if len(previous_period_row) < min_app_num:
                    previous_period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, 3)
                    next_end_year_month = update_stop_time(period_end_year_month, 3)
                else:
                    if first_year_month < next_end_year_month:
                        next_period_row.append(row)
                    else:
                        if len(next_period_row) < min_app_num:
                            next_period_row.append(row)
                            next_end_year_month = update_stop_time(next_end_year_month, 3)
#                             print(next_end_year_month)
                        else:
                            break
#         next_end_year_month = update_stop_time(period_end_year_month, 3)         
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        family_diff = parse_family_app_two_periods_droidevolver_with_diff_frequency_sensitive_method(previous_period, next_period, feature_path_dict, family_name, diff_average_frequency, sensitive_methods)
        families_diff.append(family_diff)
    with open('top_families_diff_droidevolver_with_frequency_sensitive_method_%0.2f.csv' % min_rate, 'wb') as f:
        writer = csv.writer(f)
        writer.writerows(families_diff)


def count_api_evolver_with_periods_in_family(min_x_month_after, min_rate):
    feature_path_dict = get_droidevolver_feature_path_dict()
    malware_dataset_path = 'dataset_euphony_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in feature_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    for family_name in family_app: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        if len(family_app[family_name]) < 500:
            continue
        family_app_periods = []
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                period_row.append(row)
            else:
                if len(period_row) < min_app_num:
                    period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, min_x_month_after)
                else:
                    family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), period_row])
                    period_row = []
                    period_start_year_month = period_end_year_month
                    period_end_year_month = update_stop_time(period_end_year_month, min_x_month_after)
        if len(period_row) >= (min_app_num/2):
            family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), period_row])
        print(family_name),
        for row in family_app_periods:
            print('%s:%d ' % (row[0], len(row[1]))),
        print('')
        parse_family_app_periods_droidevolver(family_app_periods, feature_path_dict, family_name)

def count_evolver_for_four_sensitve_api(): # getDeviceId, getImeiId
    interested_method = ['android.telephony.TelephonyManager.getDeviceId', 'android.telephony.TelephonyManager.getSubscriberId',
                         'android.telephony.TelephonyManager.getImei', 'android.telephony.TelephonyManager.getMeid']
    feature_path_dict = get_droidevolver_feature_path_dict()
    all_families_periods = get_all_families_periods(3, 0.1, feature_path_dict)
    for family_name in all_families_periods: #['admogo']:# # all_families_periods[family_name] = [['%d-%d' % (period_start_year_month, period_end_year_month), period_row], ]
        families_periods = all_families_periods[family_name]
        periods_api_frequency_list = []
        x_label = []
        y_values = []
        period_id = 0
        for one_period in families_periods:
            period_time = one_period[0]
            x_label.append(period_time)
            y_values.append([])
            period_api_frequency_dict = get_periods_interested_method(one_period[1], interested_method, feature_path_dict)
            periods_api_frequency_list.append([period_time, period_api_frequency_dict])
            for method in interested_method:
                method_frequency = period_api_frequency_dict.get(method, 0.0)
                y_values[period_id].append(method_frequency)
            period_id += 1
        print(x_label)
        print(y_values)
        y0 = np.array([_[0] for _ in y_values])
        y1 = np.array([_[1] for _ in y_values])
        y2 = np.array([_[2] for _ in y_values])
        y3 = np.array([_[3] for _ in y_values])
        plt.cla()
        plt.figure(figsize = (10, 8))
        plt.bar(x_label, y0, color = '#87CEFA', label = interested_method[0])
        plt.bar(x_label, y1, color = '#1E90FF', label = interested_method[1], bottom = y0)
        plt.bar(x_label, y2, color = '#6495ED', label = interested_method[2], bottom = y0 + y1)
        plt.bar(x_label, y3, color = '#4169E1', label = interested_method[3], bottom = y0 + y1 + y2)
        plt.legend()
        plt.tick_params(labelsize=4)
        plt.title('%s interested method evolver' % family_name)
        plt.savefig('interested_method/%s_interested_method_evolver.png' % family_name, dpi = 300)
        print('counted %s' % family_name)



if __name__ == "__main__":
#     count_apis()
#     count_apis_malware()
#     count_api_evolver_in_family()
#     count_api_unstability_v0(3, 0.2)
#     count_api_unstability_v1(3, 0.2)
#     count_api_unstability_v2(3, 0.2, 0.1)
#     count_api_unstability_v3(3, 0.05)
#     count_api_unstability_v4(3, 0.1, 0.2)
#     plot_two_period_with_diff_frequency()
#     plot_two_period()
#     count_api_evolver_with_periods_in_family(3, 0.1)
#     analyze_top_families_diff_data()

#     analyze_top_families_diff_data()
#     count_api_unstability_v3_sensitive_method(3, 0.1)
#     plot_two_period_sensitive_method()
#     count_api_unstability_v4_sensitive_method(3, 0.1, 0.2)
    plot_two_period_with_diff_frequency_sensitive_method()
#     count_evolver_for_four_sensitve_api()

#     generate_droidevolver_feature_idx()
#     print(get_medium_year_month(201304, 201602))
#     print(update_stop_time(201202, 10))