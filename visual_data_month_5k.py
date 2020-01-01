#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-11

@author: mingo
@module: experiment_mama.visual_data
'''

import os
import matplotlib
matplotlib.use('AGG')
from matplotlib import pyplot as plt
import numpy as np

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
                
                
def visual_data(log_list, labels, title):
    x_list = []
    y_list = []
    for log_file in log_list:
        x = []
        y = []
        if not os.path.exists(log_file):
            return 
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                x_label = line.split(' ')[1]
                f1 = float(line.split(' ')[-1])
                x.append(x_label)
                y.append(f1)
        x_list.append(x)
        y_list.append(y)
    AUTs = cal_AUT(y_list, labels)
    plt.figure(figsize = (10, 8))
    plt.xlabel('data type relate to month')
    for i in range(len(x_list)):
        plt.plot(x_list[i][0:], y_list[i][0:], 'o-', label = labels[i])
    plt.title(title)
    for i, label in enumerate(labels):
        plt.text(4.5, 0.71 + 0.03*i, '%s AUT: %.4f' % (label, AUTs[i]))
    plt.legend()
    plt.savefig('f1_figure/%s.png' % title, dpi = 150)

def main_average_f1():  
    dataset = 'dataset_all_month_5k'
    labels = ['450_package', 'cluster_simplified_v0']# ['450_package', 'cluster_v0'] # 'manual_package_v0', 'manual_package_v1', 
    x_list = ['train']
    for i in range(12):
        x_list.append('%02d' % (i+1))
    average_y_list = []
    std_y_list = []
    for label in labels:
        y_all_year = []
        for year in range(2012, 2018):
            log_file = './log/{}_{}_{}train_evaluation.txt'.format(dataset, label, year)
            y = []
            with open(log_file, 'r') as f:
                idx = 0
                for line in f:
                    line = line.strip()
                    f1 = float(line.split(' ')[-1])
                    y.append(f1)
                    idx += 1
                    if idx >= 13:
                        break
            y_all_year.append(y)
        y_all_year_np = np.array(y_all_year)
        average_y = np.mean(y_all_year_np, axis = 0)
        std_y = np.std(y_all_year_np, axis = 0)
        std_y_list.append(std_y)
        average_y_list.append(average_y)
    AUTs = cal_AUT(average_y_list, labels)
    plt.figure(figsize = (10, 8))
    plt.xlabel('data type relate to month')
    for i in range(len(average_y_list)):
        plt.plot(x_list[0:], average_y_list[i][0:], 'o-', label = labels[i])
    plt.title("{}_average f1".format(dataset))
    for i, label in enumerate(labels):
        plt.text(4.5, 0.71 + 0.03*i, '%s AUT: %.4f' % (label, AUTs[i]))
    plt.legend()
    plt.savefig('f1_figure/%s_average_f1.png' % dataset, dpi = 150)    
    
    plt.cla()
    for i in range(len(std_y_list)):
        plt.plot(x_list[0:], std_y_list[i][0:], 'o-', label = labels[i])
    plt.title("{}_std f1".format(dataset))
    plt.legend()
    plt.savefig('f1_figure/%s_std_f1.png' % dataset, dpi = 150)

def main_average_f1_according_raw_data():
    dataset = 'dataset_all_month_5k'
    labels = ['450_package', 'cluster_simplified_v0','cluster_simplified_v1', 'cluster_simplified_v2', 
              'evecluster_simplified_v0', 'evecluster_simplified_v1', 'evecluster_simplified_v2']# ['450_package', 'cluster_v0'] # 'manual_package_v0', 'manual_package_v1', 
    alias_labels = ['450_package', 'cluster_simplified_k_1000','cluster_simplified_k_800', 'cluster_simplified_k_1200', 
              'evecluster_simplified_k_1000', 'evecluster_simplified_k_800', 'evecluster_simplified_k_1200']
    x_list = ['train']
    for i in range(12):
        x_list.append('%02d' % (i+1))
    average_y_list = []
    for label in labels:
        TP_list = [[] for _ in range(2012, 2018)]
        FP_list = [[] for _ in range(2012, 2018)]
        FN_list = [[] for _ in range(2012, 2018)]
        for year in range(2012, 2018):
            log_file = './log/{}_{}_{}train_evaluation.txt'.format(dataset, label, year)
            with open(log_file, 'r') as f:
                idx = 0
                for line in f:
                    line = line.strip()
                    TP = int(line.split(' ')[-5])
                    FP = int(line.split(' ')[-4])
                    FN = int(line.split(' ')[-2])
                    TP_list[year - 2012].append(TP)
                    FP_list[year - 2012].append(FP)
                    FN_list[year - 2012].append(FN)
                    idx += 1
                    if idx >= 13:
                        break
        average_y = []
        for i in range(13):
            sum_TP = 0
            sum_FP = 0
            sum_FN = 0
            for year in range(2012, 2018):
                sum_TP += TP_list[year - 2012][i]
                sum_FP += FP_list[year - 2012][i]
                sum_FN += FN_list[year - 2012][i]
            f1 = float(2*sum_TP)/(2*sum_TP + sum_FN + sum_FP) 
            average_y.append(f1)
        average_y_list.append(average_y)
    AUTs = cal_AUT(average_y_list, labels)
    plt.figure(figsize = (10, 8))
    plt.xlabel('data type relate to month')
    for i in range(len(average_y_list)):
        plt.plot(x_list[0:], average_y_list[i][0:], 'o-', label = alias_labels[i])
    plt.title("{}_average f1 raw data".format(dataset))
    for i, label in enumerate(labels):
        plt.text(4.5, 0.71 + 0.03*i, '%s AUT: %.4f' % (label, AUTs[i]))
    plt.legend()
    plt.savefig('f1_figure/%s_average_f1_raw_data.png' % dataset, dpi = 150)    
    
# float(2*TP)/(2*TP + FN + FP)
 
def main():
    dataset = 'dataset_all_month_5k'
    labels = ['450_package', 'cluster_simplified_v0','cluster_simplified_v1', 'cluster_simplified_v2', 
              'evecluster_simplified_v0', 'evecluster_simplified_v1', 'evecluster_simplified_v2']# ['450_package', 'cluster_v0'] # 'manual_package_v0', 'manual_package_v1', 
    alias_labels = ['450_package', 'cluster_simplified_k_1000','cluster_simplified_k_800', 'cluster_simplified_k_1200', 
              'evecluster_simplified_k_1000', 'evecluster_simplified_k_800', 'evecluster_simplified_k_1200']
    for year in range(2012,2018):
        log_list = []
        new_labels = []
        for i, label in enumerate(labels):
            log_list.append('./log/{}_{}_{}train_evaluation.txt'.format(dataset, label, year))
            new_labels.append('{}_{}_{}'.format(dataset, alias_labels[i], year))
        title = '%s_%d_train f1' % (dataset, year)
        visual_data(log_list, new_labels, title) 

if __name__ == "__main__":    
    main()
#     main_average_f1()
    main_average_f1_according_raw_data()