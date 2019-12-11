#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-11-28

@author: mingo
@module: script_zm.MaMaStat_new
'''

import csv 
import os 
from multiprocessing import Pool
import subprocess
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--method', type=str)
args = parser.parse_args()

def run_task(method, graph_path, output_path, idx):
    child = subprocess.Popen('python extract_mama_feature_%s.py -s %s -o %s' % (method, graph_path, output_path), shell = True)
    child.wait()
    if idx % 500 == 0:
        print('process %d: %s' % (idx, graph_path))

def main():
    method = args.method
    root_dir = '/home/mlsnrs/apks/ssd_1T/mamadroid/light_weight_dataset/%s' % method
    dataset_list = []
    dataset_dir = '/home/mlsnrs/apks/VirusShare/dataset_s_baseline/dataset_20132014_light_weight'
    for file_name in os.listdir(dataset_dir):
        with open(os.path.join(dataset_dir, file_name), 'r') as f:
            reader = csv.reader(f) 
            for row in reader:
                label = int(row[0])
                if label != 2:
                    md5 = row[1].split('/')[1]
                    fs_year = int(row[2].split('-')[0])
                    dataset_list.append([label, md5, fs_year])
    p = Pool(25)
    idx = 0
    for row in dataset_list:
        idx += 1
        label = row[0]
        md5 = row[1]
        fs_year = row[2]
        if label == 0:
            graph_path = '/home/mlsnrs/apks/AndroZoo/result_benign_soot/benign_{}/graphs/{}.txt'.format(fs_year, md5)
        elif label == 1:
            graph_path = '/home/mlsnrs/apks/AndroZoo/result_malware_soot/malware_{}/graphs/{}.txt'.format(fs_year, md5)
        output_dir = os.path.join(root_dir, 'feature/{}'.format(fs_year))
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, 0775)
        output_path = os.path.join(output_dir, '{}_{}.csv'.format(method, md5))
        p.apply_async(run_task, args = (method, graph_path, output_path, idx, ))
    p.close()
    p.join()
    print('finish')

if __name__ == "__main__":
    main()