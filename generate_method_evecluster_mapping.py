#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-21

@author: mingo
@module: experiment_mama.generate_method_evecluster_mapping
'''

import os
import pickle 
import csv

def generate_method_evecluster_mapping(cluster_k):
    current_method_min_len_dict = {}
    method_evecluster_mapping = {}
    if cluster_k == 1000:
        cluster_txt_dir = '/home/shellhand/mamadroid_RF_PAC_Bayesian/evedroid1221/cluster1000_1221'
    elif cluster_k == 800:
        cluster_txt_dir = '/home/shellhand/mamadroid_RF_PAC_Bayesian/evedroid1221/cluster800_1227'
    elif cluster_k == 1200:
        cluster_txt_dir = '/home/shellhand/mamadroid_RF_PAC_Bayesian/evedroid1221/cluster1200_1227'
    else:
        print('error cluster_k %d' % cluster_k)
        exit(1)
    for i in range(cluster_k):
        cluster_txt_path = os.path.join(cluster_txt_dir, 'cluster_%04d.txt' % i)
        with open(cluster_txt_path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                class_name = row[0]
                ret_name = row[1]
                method_name = row[2]
                para_name = row[3]
                full_method_name = '.'.join([class_name, method_name])
                ret_para_name = '.'.join([ret_name, para_name])
                if full_method_name not in current_method_min_len_dict:
                    current_method_min_len_dict[full_method_name] = 10000 # init the ret and para len a large number
                if len(ret_para_name) < current_method_min_len_dict[full_method_name]:
                    method_evecluster_mapping[full_method_name] = i
    print('cluster_k %d method num: %d' % (cluster_k, len(method_evecluster_mapping)))
    with open('method_evecluster_mapping_%d.pkl' % cluster_k, 'wb') as f:
        pickle.dump(method_evecluster_mapping, f) 

def diff_two_cluster_method():
    method_evecluster_mapping = {}
    with open('method_evecluster_mapping_1000.pkl', 'rb') as f:
        old_method_evecluster_mapping = pickle.load(f)
    for key in old_method_evecluster_mapping:
        new_key = key.replace('.init', '')
        method_evecluster_mapping[new_key] = old_method_evecluster_mapping[key]

    with open('method_cluster_mapping_1000.pkl', 'rb') as f:
        method_cluster_mapping = pickle.load(f) 
    diff_cluster_set = set(method_cluster_mapping.keys()) - set(method_evecluster_mapping.keys())
    diff_evecluste_set = set(method_evecluster_mapping.keys()) - set(method_cluster_mapping.keys())
    with open('diff_cluster_method.txt', 'w') as f:
        f.write('\n'.join(list(diff_cluster_set)))
        f.write('\n')
    with open('diff_evecluster_method.txt', 'w') as f:
        f.write('\n'.join(list(diff_evecluste_set)))
        f.write('\n')
    print('diff_cluster len: %d' % (len(diff_cluster_set)))
    print('diff_evecluster len: %d' % (len(diff_evecluste_set)))
    
    
if __name__ == "__main__":
    generate_method_evecluster_mapping(800)
#     diff_two_cluster_method()