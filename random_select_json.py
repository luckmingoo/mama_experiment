#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-28

@author: mingo
@module: experiment_mama.random_select_json
'''
import random
import os 
import shutil 

source_dir = '/home/mlsnrs/share/zm/build_KG/data/json'
json_file_list = []
for f_name in os.listdir(source_dir):
    if f_name.endswith('.json'):
        json_file_list.append(f_name)
print('json file num: %d' % len(json_file_list))
dest_dir = '/home/mlsnrs/share/zm/build_KG/data/selected_json_v2'
if not os.path.exists(dest_dir):
    os.mkdir(dest_dir)
num_json_file = len(json_file_list)
selected_num = int(num_json_file * 0.01)
selected_file = []
for i in range(selected_num):
    rand_idx = random.randint(0, len(json_file_list) - 1)
    f_name = json_file_list.pop(rand_idx)
    selected_file.append(f_name)
for f_name in selected_file:
    source_path = os.path.join(source_dir, f_name)
    shutil.copy(source_path, dest_dir)
print("selected file len: %d" % (len(selected_file)))
print('finish')