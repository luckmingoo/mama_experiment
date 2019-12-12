#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-11

@author: mingo
@module: experiment_mama.visual_data
'''

from matplotlib import pyplot as plt

def cal_AUT(f1_list, labels):
    AUTs = []
    for i, y in enumerate(f1_list):
        s = 0.0
        y = y[1: ]
        for j, f1 in enumerate(y):
            if j == 0 or j == (len(y) - 1):
                s += f1
            else:
                s += (2 * f1)
        AUT = s/2/(len(y) - 1)
        print('%s AUT: %f' % (labels[i], AUT))
        AUTs.append(AUT)
    return AUTs
                
                
def visual_data(log_list, labels):
    x = ['train']
    for i in range(26):
        x.append('test' + str(i))
    y_list = []
    for log_file in log_list:
        y = []
        with open(log_file, 'r') as f:
            for line in f:
                f1 = float(line.strip().split(' ')[-1])
                y.append(f1)
        y_list.append(y)
    AUTs = cal_AUT(y_list, labels)
    plt.figure(figsize = (8, 6))
    plt.xlabel('data type relate to month')
    for i, y in enumerate(y_list):
        plt.plot(x[0:], y[0:], 'o-', label = labels[i])
    plt.title('f1')
    for i, y in enumerate([0.74, 0.71]):
        plt.text(6.5, y, '%s AUT: %.4f' % (labels[i], AUTs[i]))
    plt.legend()
    plt.savefig('f1.png', dpi = 150)

def main1():
    labels = ['450_package', 'cluster_v0'] # 'manual_package_v0', 'manual_package_v1', 
#     labels = ['origin', 'bagging'] # , 'bagging','validation'
    log_list = []
    for label in labels:
        log_list.append('./log/' + label + '_evaluation.txt')
#         log_list.append('./log/' + label + '12_10.txt')
    labels = ['mamadroid_origin_450', 'mamadroid_metaknowledge']
    visual_data(log_list, labels)

def main2():
    labels = ['origin', 'bagging'] # , 'bagging','validation'
    log_list = []
    for label in labels:
#         log_list.append('./log/' + label + '_evaluation.txt')
        log_list.append('./log/' + label + '12_10.txt')
    labels = ['mamadroid_origin_200', 'mamadroid_PAC_Bayesian']
    visual_data(log_list, labels)

def main3():
    dataset = 'dataset_20162017_light_weight'
    labels = ['450_package', 'cluster_v0'] # 'manual_package_v0', 'manual_package_v1', 
#     labels = ['origin', 'bagging'] # , 'bagging','validation'
    log_list = []
    for label in labels:
        log_list.append('./log/'  + dataset+ '_' + label + '_evaluation.txt')
#         log_list.append('./log/' + label + '12_10.txt')
    labels = ['mamadroid_origin_450', 'mamadroid_metaknowledge']
    visual_data(log_list, labels)   

def main4():
    dataset = 'dataset_20132014_light_weight'
    labels = ['450_package', 'cluster_v0'] # 'manual_package_v0', 'manual_package_v1', 
#     labels = ['origin', 'bagging'] # , 'bagging','validation'
    log_list = []
    for label in labels:
        log_list.append('./log/'  + dataset+ '_' + label + '_evaluation.txt')
#         log_list.append('./log/' + label + '12_10.txt')
    labels = ['mamadroid_origin_450', 'mamadroid_metaknowledge']
    visual_data(log_list, labels)    

if __name__ == "__main__":
#     main2()
#     main1()
#     main3()    
    main4()