#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-11-29

@author: mingo
@module: script_zm.collect_feature_csv
'''

import time
import csv
import copy
import numpy as np
import os 
import argparse
from sklearn.externals import joblib


parser = argparse.ArgumentParser()
parser.add_argument("-m","--method", type=str)
args = parser.parse_args()

# start = time.time()
# data = pd.read_csv('92f3ae12c953d6f1f057dfacb070c358.csv')
# print('spend %f' % (time.time() - start))
  
# start = time.time()
# data_all = []
# with open('92f3ae12c953d6f1f057dfacb070c358.csv', 'r') as f:
#     reader = csv.reader(f) 
#     for row in reader:
#         data = []
#         length = len(row)
#         for i in range(length):
#             data.append(float(row[i]))
#         data_all.append(data)
# print('spend %f' % (time.time() - start)) 
# print(len(data_all[0]))
# datas = []
# for i in range(100):
#     datas.append(copy.deepcopy(data_all[0]))
# print(len(datas))
# with open('save_list3_np.jlb', 'wb') as f:
#     joblib.dump(np.array(data_all, dtype=np.float16), f)
# with open('save_list4_np.jlb', 'wb') as f:
#     joblib.dump(np.array(datas, dtype=np.float16), f)   
  
  
# start = time.time() 
# with open('save_list4_np.jlb', 'rb') as f:
#     data = joblib.load(f)
# print('spend %f' % (time.time() - start))
# print(type(data))

def save_feature_to_pickle(method):
    root_dir = '/home/mlsnrs/apks/ssd_1T/mamadroid/light_weight_dataset/%s' % method
    dataset_dir = '/home/mlsnrs/apks/VirusShare/dataset_s_baseline/dataset_20132014_light_weight'
    dataset = {}
    for file_name in os.listdir(dataset_dir):
        dataset[file_name] = []
        with open(os.path.join(dataset_dir, file_name), 'r') as f:
            reader = csv.reader(f) 
            for row in reader:
                label = int(row[0])
                if label != 2:
                    md5 = row[1].split('/')[1]
                    firstseen = row[2]
                    dataset[file_name].append([label, md5, firstseen])
    
    save_feature_list = []
    for file_name in dataset:
        idx = 0
        mamadroid_feature_list = []
        mamadroid_feature_numpy = []
        for row in dataset[file_name]:
            label = row[0]
            md5 = row[1]
            firstseen = row[2]
            fs_year = int(firstseen.split('-')[0])
            feature_csv_path = os.path.join(root_dir, 'feature/{}/{}_{}.csv'.format(fs_year, method, md5))
            if not os.path.exists(feature_csv_path):
                continue
#                 print(feature_csv_path)
            with open(feature_csv_path, 'r') as f:
                reader = csv.reader(f) 
                for row in reader:
                    data = []
                    length = len(row)
                    for i in range(length):
                        data.append(float(row[i]))
#                     mamadroid_feature_list.append(data)
                    if idx == 0:
                        mamadroid_feature_numpy = np.array([data], dtype = np.float16)
                    else:
                        mamadroid_feature_list.append(data)
#                             mamadroid_feature_numpy = np.concatenate((mamadroid_feature_numpy,np.array(data, dtype = np.float16)), axis=0)
            save_feature_list.append([md5, label, firstseen, file_name, idx])
            idx += 1
            if idx % 100 == 0:
                print("%s %s %d: %s" % (file_name, firstseen, idx, md5))
            if idx % 1000 == 0:
                mamadroid_feature_numpy = np.concatenate((mamadroid_feature_numpy,np.array(mamadroid_feature_list, dtype = np.float16)), axis=0)
                mamadroid_feature_list = []
        if mamadroid_feature_list:
            mamadroid_feature_numpy = np.concatenate((mamadroid_feature_numpy,np.array(mamadroid_feature_list, dtype = np.float16)), axis=0)
        save_pickle_dir = os.path.join(root_dir, 'save_pickle')
        if not os.path.exists(save_pickle_dir):
            os.mkdir(save_pickle_dir)
        with open(os.path.join(root_dir, 'save_pickle/{}.jlb'.format(file_name.replace('.txt', ''))), 'wb') as f:
            joblib.dump(mamadroid_feature_numpy, f)
    with open(os.path.join(root_dir, '{}_save_feature_list.csv'.format(method)), 'wb') as f:
        writer = csv.writer(f) 
        writer.writerows(save_feature_list)
    
                 
if __name__ == "__main__":
    method = args.method
    save_feature_to_pickle(method)
    print('finish')