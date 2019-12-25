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
        if abs(previous_frequency - next_frequency) >= average_frequency_diff:
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

def count_api_unstability(x_month_after, average_frequency_diff): # X month after the malicious family appears,  Y of all families changed at least Z% APIs
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
        previous_period = True
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                previous_period_row.append(row)
            else:
                previous_period = False
                next_period_row.append(row)
                if len(next_period_row) >= len(previous_period_row):
                    next_end_year_month = first_year_month
                    break
        previous_period = ['%d-%d' % (period_start_year_month, period_end_year_month), previous_period_row]
        next_period = ['%d-%d' % (period_end_year_month, next_end_year_month), next_period_row]
        parse_family_app_two_periods(previous_period, next_period, seq_path_dict, family_name, average_frequency_diff)

if __name__ == "__main__":
#     count_apis()
#     count_apis_malware()
#     count_api_evolver_in_family()
    count_api_unstability(3, 0.2)

#     print(get_medium_year_month(201304, 201602))
#     print(update_stop_time(201202, 10))