#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-18

@author: mingo
@module: experiment_mama.tidy_ssd_feature
'''

import csv 
import os 
import shutil
from subprocess import Popen

def tidy_ssd_feature():
    dataset_dirs = ['dataset_20132014','dataset_20152016_light_weight',
                    'dataset_20162017_light_weight','dataset_20172018_light_weight',
                    'dataset_20132014_light_weight','dataset_20162017',
                    'dataset_20172018']
    
    method_list = ['450_package', 'cluster_v0', 'manual_package_v0', 
                    'manual_package_v1', 'manual_package_v2', 'manual_package_v3', 
                    'manual_package_v4']
    year_list = range(2012, 2019)
    root_dir = '/mnt/ssd_1T/mamadroid'
    for dataset_dir in dataset_dirs:
        dataset_dir_abs = os.path.join(root_dir, dataset_dir)
        for method in method_list:
            method_dir_abs = os.path.join(dataset_dir_abs, method)
            for year in year_list:
                feature_dir_abs = os.path.join(method_dir_abs, 'feature/%d' % year)
                if os.path.exists(feature_dir_abs):
                    dest_dir = os.path.join(root_dir, '{}/feature/'.format(method))
                    if not os.path.exists(dest_dir):
                        os.makedirs(dest_dir, 0775)
#                     child = Popen('mv %s %s' % (feature_dir_abs, dest_dir), shell = True)
#                     child.wait()
                    print('mv %s %s' % (feature_dir_abs, dest_dir))
#                     print('move %s to %s' % (feature_dir_abs, dest_dir))

if __name__ == "__main__":
    tidy_ssd_feature()