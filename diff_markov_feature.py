#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-11

@author: mingo
@module: experiment_mama.diff_markov_feature
'''
import json
import pickle
import csv 
import numpy as np


def get_v0_allnodes():
    with open('packages_translate.json', 'r') as f:
        packages_translate = json.load(f)
    PACKETS = list(set(packages_translate.values()))
    allnodes = PACKETS
    allnodes.append('selfdefined')
    allnodes.append('obfuscated')
    return allnodes

def get_v1_allnodes():
    PACKETS=[]
    with open('package_uniq.txt', 'r') as packseq:
        for line in packseq:
            PACKETS.append(line.replace('\n',''))
        packseq.close()
    allnodes = PACKETS
    allnodes.append('selfdefined')
    allnodes.append('obfuscated')
    return allnodes

def get_v0_headers():
    allnodes = get_v0_allnodes()
    Header=[]
    for i in range (0,len(allnodes)):
        for j in range (0,len(allnodes)):
            Header.append(allnodes[i]+'To'+allnodes[j])    
    return Header

def get_v1_headers():
    allnodes = get_v1_allnodes()
    Header=[]
    for i in range (0,len(allnodes)):
        for j in range (0,len(allnodes)):
            Header.append(allnodes[i]+'To'+allnodes[j])    
    return Header

def get_not_zero_dimension(feature_csv, header):
    not_zero_dimension_set = set()
    feature_csv_len = len(feature_csv)
    for idx in range(feature_csv_len):
        if feature_csv[idx] != 0:
            not_zero_dimension_set.add(header[idx])
    return not_zero_dimension_set

def get_feature(feature_file):
    data = []
    with open(feature_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            row_len = len(row)
            for i in range(row_len):
                data.append(float(row[i]))
    return data

def main():
    manual_package_v0 = 'manual_package_v0_92f3ae12c953d6f1f057dfacb070c358.csv'
    manual_package_v1 = 'manual_package_v1_92f3ae12c953d6f1f057dfacb070c358.csv'
    feature_v0 = get_feature(manual_package_v0)
    feature_v1 = get_feature(manual_package_v1)
    header_v0 = get_v0_headers()
    header_v1 = get_v1_headers()
    feature_v0_not_zero = get_not_zero_dimension(feature_v0, header_v0)
    feature_v1_not_zero = get_not_zero_dimension(feature_v1, header_v1)
    print(feature_v0_not_zero - feature_v1_not_zero)
    print(feature_v1_not_zero - feature_v0_not_zero)

if __name__ == "__main__":
    main()
    
    