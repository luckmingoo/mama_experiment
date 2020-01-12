#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2020-01-11

@author: mingo
@module: experiment_mama.dataset_operate
'''
import os 
import csv 

def save_dataset():
    root_dir = '/mnt/VirusShare/dataset_s_baseline'
    for year in range(2012, 2019):
        dataset_year_benign = []
        dataset_year_malware = []
        for month in range(12):
            file_name_txt = os.path.join(root_dir, 'dataset_all_month_5k/%d%02d_filename.txt' % (year, month + 1))
            with open(file_name_txt, 'r') as f:
                reader = csv.reader(f) 
                for row in reader:
                    label = int(row[0])
                    if label == 0:
                        md5 = row[1]
                        dataset_year_benign.append(md5)
                    elif label == 1:
                        md5 = row[1]
                        dataset_year_malware.append(md5)
        save_name_benign = os.path.join(root_dir, 'export_dataset_list/%d_benign.txt' % (year))
        with open(save_name_benign, 'w') as f:
            f.write('\n'.join(dataset_year_benign))
            f.write('\n') 
        save_name_malware = os.path.join(root_dir, 'export_dataset_list/%d_malware.txt' % (year))
        with open(save_name_malware, 'w') as f:
            f.write('\n'.join(dataset_year_malware))
            f.write('\n') 

if __name__ == "__main__":
    save_dataset()
