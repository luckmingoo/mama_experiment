#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-21

@author: mingo
@module: experiment_mama.get_accurate_family
'''

import csv 
import os 
import json 

def get_accurate_family():
    origin_family_label_csv = '/home/shellhand/mamadroid_RF_PAC_Bayesian/label/labelinfo.verbose'
    with open(origin_family_label_csv, 'r') as f:
        idx = 0
        for line in f:
            line = line.strip()
            md5 = line.split(',')[0]
            tuple_str = line[line.find('['): line.find(']') + 1]
            tuple_str = tuple_str.replace('\'', '\"')
            if idx < 5:
                print(tuple_str)
                tuple_list = json.loads(tuple_str)
                print(tuple_list)
            idx += 1

if __name__ == "__main__":
    get_accurate_family()