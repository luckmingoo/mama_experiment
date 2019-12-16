#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-10

@author: mingo
@module: experiment_mama.split_new_dataset
'''

import os 
import csv
import random


def split_new_dataset():
    dataset_dir = '/mnt/VirusShare/dataset_s_baseline/dataset_20172018/'
    year_2013_txt = ['train_00_filename.txt', 'test_00_filename.txt']
    year_2014_txt = ['test_%02d_filename.txt' % (_ + 1) for _ in range(12)]
    
    year_2013_data = [[], []] # benign, malware
    for file_name in year_2013_txt:
        file_path = os.path.join(dataset_dir, file_name)
        with open(file_path, 'r') as f:
            reader = csv.reader(f) 
            for row in reader:
                label = int(row[0])
                if label == 2:
                    continue
                year_2013_data[label].append(row)
    
    year_2014_data = [[[], []] for _ in range(12)]
    for file_name in year_2014_txt:
        file_path = os.path.join(dataset_dir, file_name)
        with open(file_path, 'r') as f:
            reader = csv.reader(f) 
            for row in reader:
                label = int(row[0])
                if label == 2:
                    continue
                first_seen = row[2]
                fs_month = int(first_seen.split('-')[1])
                year_2014_data[fs_month - 1][label].append(row)
    train_data = []
    test_data = [[] for _ in range(13)]
    print('before year_2013_data len: %d %d' % (len(year_2013_data[0]), len(year_2013_data[1])))
    for _ in range(4500): # get train benign data for 2013
        rand_idx = random.randint(0, len(year_2013_data[0]) - 1)
        row = year_2013_data[0].pop(rand_idx)
        train_data.append(row)
    for _ in range(500): # get train malware data for 2013
        rand_idx = random.randint(0, len(year_2013_data[1]) - 1)
        row = year_2013_data[1].pop(rand_idx)
        train_data.append(row)
    print('after year_2013_data len: %d %d' % (len(year_2013_data[0]), len(year_2013_data[1])))
    for _ in range(1800): # get train benign data for 2013
        rand_idx = random.randint(0, len(year_2013_data[0]) - 1)
        row = year_2013_data[0].pop(rand_idx)
        test_data[0].append(row)
    for _ in range(200): # get train malware data for 2013
        rand_idx = random.randint(0, len(year_2013_data[1]) - 1)
        row = year_2013_data[1].pop(rand_idx)
        test_data[0].append(row)
    for i in range(12):
        malware_num = min(len(year_2014_data[i][1]), 200)
        print('month: %d' % (i + 1))
        for _ in range(malware_num * 9):
            rand_idx = random.randint(0, len(year_2014_data[i][0]) - 1)
            row = year_2014_data[i][0].pop(rand_idx)
            test_data[i + 1].append(row)
        for _ in range(malware_num):
            rand_idx = random.randint(0, len(year_2014_data[i][1]) - 1)
            row = year_2014_data[i][1].pop(rand_idx)
            test_data[i + 1].append(row)
    save_dir = '/mnt/VirusShare/dataset_s_baseline/dataset_20172018_light_weight'
    if not os.path.exists(save_dir):
        os.mkdir(save_dir)
    with open(os.path.join(save_dir, 'train_00_filename.txt'), 'wb') as f:
        writer = csv.writer(f) 
        writer.writerows(train_data)
    for i in range(13):
        with open(os.path.join(save_dir, 'test_%02d_filename.txt' % i), 'wb') as f:
            writer = csv.writer(f) 
            writer.writerows(test_data[i])
    print('finish')
    
    

if __name__ == "__main__":
    split_new_dataset()