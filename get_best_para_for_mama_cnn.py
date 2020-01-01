#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-31

@author: mingo
@module: experiment_mama.get_best_para_for_mama_cnn
'''

import os 

f1_list = []
log_file = './log/optimize_cnn_dataset_20132014_light_weight_450_package_evaluation.txt'
log_file = './log/optimize_cnn_dataset_20132014_light_weight_450_package_evaluation_v1.txt'
with open(log_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith('test'):
            f1_socre = float(line.split(' ')[-1])
            f1_list.append([line, f1_socre])
f1_list.sort(key = lambda x: x[1], reverse = True)
for i in range(20):
    print(f1_list[i][0])