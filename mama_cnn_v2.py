#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-18

@author: mingo
@module: experiment_mama.mama_cnn
'''

import numpy as np
import csv 
import time 
import os 
import math
import argparse
import joblib
from sklearn.metrics import confusion_matrix
from cnn_model import CNN
import torch

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--method', type=str)
parser.add_argument('-d', '--dataset', type=str)
# ['dataset_20132014_light_weight', 'dataset_20162017_light_weight']
parser.add_argument('-u', '--user', type=str)
# ['mlsnrs', 'shellhand']
parser.add_argument('-s', '--device_source', type = str)
# ['ssd_1T', 'ssd_2T']
args = parser.parse_args()

def get_save_feature_dict(save_feature_file):
    save_feature_dict = {}
    with open(save_feature_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader: # [md5, label, firstseen, file_name, idx]
            md5 = row[0]
            label = int(row[1])
            firstseen = row[2]
            file_name = row[3]
            save_idx = int(row[4])
            save_feature_dict[md5] = [label, firstseen, file_name, save_idx]
    return save_feature_dict

def get_test_data(dataset, test_year, test_month, method, save_feature_dict, root_dir_prefix):
    root_dir = '%s/ssd_1T/mamadroid/%s/%s' % (root_dir_prefix, dataset, method)
    test_data_dir = '%s/VirusShare/dataset_s_baseline/%s' % (root_dir_prefix, dataset)
    tmp_x_test = []
    tmp_y_test = []
    test_data_md5 = []
    test_file  = '%d%02d_filename.txt' % (test_year, test_month + 1)
    with open(os.path.join(test_data_dir, test_file), 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            label = int(row[0])
            if label == 2:
                continue
#             elif label == 0:
#                 label = -1  # change benign label to -1
            md5 = row[1]
            test_data_md5.append([md5, label])
    feature_joblib_file = os.path.join(root_dir, 'save_pickle/{}.jlb'.format(test_file.replace('.txt', '')))
    with open(feature_joblib_file, 'rb') as f:
        feature_np = joblib.load(f)
        print('feature_np %s shape: %s' % (test_file.replace('.txt', ''), feature_np.shape))
        vec_len = feature_np.shape[1]
        m_dimension = int(math.sqrt(vec_len))
    for row in test_data_md5:
        md5 = row[0]
        label = row[1]
        if md5 not in save_feature_dict:
            continue
        idx = save_feature_dict[md5][3]
        markov_feature = feature_np[idx,]
        markov_feature = markov_feature.reshape((m_dimension, m_dimension))
        tmp_x_test.append(markov_feature)
        tmp_y_test.append(label)
    x_test = np.array(tmp_x_test)
    y_test = np.array(tmp_y_test)
    s = np.arange(x_test.shape[0])
    np.random.shuffle(s)
    x_test = x_test[s]
    y_test = y_test[s]
    return x_test, y_test


def get_train_data(dataset, train_year, method, save_feature_dict, root_dir_prefix):
    root_dir = '%s/ssd_1T/mamadroid/%s/%s' % (root_dir_prefix, dataset, method)
    train_data_dir = '%s/VirusShare/dataset_s_baseline/%s' % (root_dir_prefix, dataset)
    tmp_x_train = []
    tmp_y_train = []
    for train_month in range(0, 12):
        train_data_md5 = []
        train_file  = '%d%02d_filename.txt' % (train_year, train_month + 1)
        with open(os.path.join(train_data_dir, train_file), 'r') as f:
            reader = csv.reader(f) 
            for row in reader:
                label = int(row[0])
                if label == 2:
                    continue
#                 elif label == 0:
#                     label = -1  # change benign label to -1
                md5 = row[1]
                train_data_md5.append([md5, label])
        feature_joblib_file = os.path.join(root_dir, 'save_pickle/{}.jlb'.format(train_file.replace('.txt', '')))
        with open(feature_joblib_file, 'rb') as f:
            feature_np = joblib.load(f)
            print('feature_np %s shape: %s' % (train_file.replace('.txt', ''), feature_np.shape))
            vec_len = feature_np.shape[1]
            m_dimension = int(math.sqrt(vec_len))
        for row in train_data_md5:
            md5 = row[0]
            label = row[1]
            if md5 not in save_feature_dict:
                continue
            idx = save_feature_dict[md5][3]
            markov_feature = feature_np[idx,]
            markov_feature = markov_feature.reshape((m_dimension, m_dimension))
            tmp_x_train.append(markov_feature)
            tmp_y_train.append(label)
    x_train = np.array(tmp_x_train)
    y_train = np.array(tmp_y_train)
    s = np.arange(x_train.shape[0])
    np.random.shuffle(s)
    x_train = x_train[s]
    y_train = y_train[s]
    return x_train, y_train


def evaluation(method, dataset, user, device_source): 
    if user == 'mlsnrs':
        root_dir_prefix = '/home/mlsnrs/apks'
    elif user == 'shellhand':
        root_dir_prefix = '/mnt'
    save_feature_path = '%s/ssd_1T/mamadroid/%s/%s/%s_save_feature_list.csv' % (root_dir_prefix, dataset, method, method)
    save_feature_dict = get_save_feature_dict(save_feature_path)
    print('have read save_feature_dict: %d' % len(save_feature_dict))
    for train_year in range(2012, 2018):
        log_name = 'log/cnn_%s_%s_%dtrain_evaluation.txt' % (dataset, method, train_year)
        if os.path.exists(log_name):
            os.remove(log_name)
        x_train, y_train = get_train_data(dataset, train_year, method, save_feature_dict, root_dir_prefix)
        print('x_train shape: %s y_train shape: %s' % (str(x_train.shape), str(y_train.shape)))
        start = time.time()
        print('start train')
        clf = CNN(layer_num = 3, kernel_size = 5, gpu_id = 3)
        clf.fit(x_train, y_train, epoch = 260, batch_size = 350, lr = 0.01) # 260
        end = time.time()
        print('Training  model time used: %f s' % (end - start))
        print(x_train.shape)
        len_x = x_train.shape[0]
        if (len_x % 20) != 1:
            y_pred = clf.predict(x_train, batch_size = 20)
        else:
            y_pred = clf.predict(x_train, batch_size = 21)
        print(y_pred.shape)
        cm = confusion_matrix(y_train, np.int32(y_pred >= 0.5))
        TP = cm[1][1]
        FP = cm[0][1]
        TN = cm[0][0]
        FN = cm[1][0]
        F1 = float(2*TP)/(2*TP + FN + FP)
        print('train %d data TP FP TN FN F1: %d %d %d %d %.4f' % (train_year, TP, FP, TN, FN, F1))
        with open(log_name, 'a') as f:
            f.write('train %d data TP FP TN FN F1: %d %d %d %d %.4f\n' % (train_year, TP, FP, TN, FN, F1))
        x_train = []
        y_train = []
        for test_year in range(train_year+1, 2019):
            for test_month in range(0, 12):
                x_test, y_test = get_test_data(dataset, test_year, test_month, method, save_feature_dict, root_dir_prefix)
                print('%d-%02d x_test shape: %s y_test shape: %s' % (test_year, test_month + 1, str(x_test.shape), str(y_test.shape)))
                len_x = x_test.shape[0]
                if (len_x % 20) != 1:
                    y_pred = clf.predict(x_test, batch_size = 20)
                else:
                    y_pred = clf.predict(x_test, batch_size = 21)
#                 y_pred = clf.predict(x_test, batch_size = 20)
                cm = confusion_matrix(y_test, np.int32(y_pred >= 0.5))
                TP = cm[1][1]
                FP = cm[0][1]
                TN = cm[0][0]
                FN = cm[1][0]
                F1 = float(2*TP)/(2*TP + FN + FP)
                print('test %d-%02d TP FP TN FN F1: %d %d %d %d %.4f' % (test_year, test_month+1, TP, FP, TN, FN, F1))
                with open(log_name, 'a') as f:
                    f.write('test %d-%02d TP FP TN FN F1: %d %d %d %d %.4f\n' % (test_year, test_month+1, TP, FP, TN, FN, F1))

def optimize_para(method, dataset, user, device_source):
    log_name = 'log/optimize_cnn_%s_%s_evaluation_v2.txt' % (dataset, method)
#     if os.path.exists(log_name):
#         os.remove(log_name)
    if user == 'mlsnrs':
        root_dir_prefix = '/home/mlsnrs/apks'
    elif user == 'shellhand':
        root_dir_prefix = '/mnt'
    save_feature_path = '%s/%s/mamadroid/%s/%s/%s_save_feature_list.csv' % (root_dir_prefix, device_source, dataset, method, method)
    save_feature_dict = get_save_feature_dict(save_feature_path)
    print('have read save_feature_dict: %d' % len(save_feature_dict))
    x_train, y_train = get_train_data(dataset, 2012, method, save_feature_dict, root_dir_prefix) # dataset, train_year, method, save_feature_dict, root_dir_prefix
    print('x_train shape: %s y_train shape: %s' % (str(x_train.shape), str(y_train.shape)))
    start = time.time()
    print('start train')
    for b in range(50, 501, 50):
        for k in [5]: # 3, 5
            for lr in [0.01, 0.1, 0.001]:
                clf = CNN(layer_num = 3, kernel_size = k, gpu_id = 2)
                step_size = 10
                for e in range(10, 501, step_size):
                    clf.fit(x_train, y_train, epoch = step_size, batch_size = b, lr = lr)
                    end = time.time()
#                     print('Training batch_size=%d kernel_size=%d lr=%.2f epoch=%d time used: %f s' % (b, k, lr, e, end - start))
                #     torch.cuda.empty_cache()
                    y_pred = clf.predict(x_train, batch_size = 20)
                    cm = confusion_matrix(y_train, np.int32(y_pred >= 0.5))
                    TP = cm[1][1]
                    FP = cm[0][1]
                    TN = cm[0][0]
                    FN = cm[1][0]
                    F1 = float(2*TP)/(2*TP + FN + FP)
                    print('train data batch_size=%d kernel_size=%d lr=%.2f epoch=%d TP FP TN FN F1: %d %d %d %d %.4f' % (b, k, lr, e, TP, FP, TN, FN, F1))
                    with open(log_name, 'a') as f:
                        f.write('train data batch_size=%d kernel_size=%d lr=%.2f epoch=%d TP FP TN FN F1: %d %d %d %d %.4f\n' % (b, k, lr, e, TP, FP, TN, FN, F1))
                    for test_id in range(0, 1):#13):
                        x_test, y_test = get_test_data(dataset, 2013, 0, method, save_feature_dict, root_dir_prefix) # dataset, test_year, test_month, method, save_feature_dict, root_dir_prefix
        #                 print('x_test shape: %s y_test shape: %s' % (str(x_test.shape), str(y_test.shape)))
                        y_pred = clf.predict(x_test, batch_size = 20)
                #         y_pred = classify(y_pred)
                        cm = confusion_matrix(y_test, np.int32(y_pred >= 0.5))
                        TP = cm[1][1]
                        FP = cm[0][1]
                        TN = cm[0][0]
                        FN = cm[1][0]
                        F1 = float(2*TP)/(2*TP + FN + FP)
                        print('test_id %d batch_size=%d kernel_size=%d lr=%.2f epoch=%d TP FP TN FN F1: %d %d %d %d %.4f' % (test_id, b, k, lr, e, TP, FP, TN, FN, F1))
                        with open(log_name, 'a') as f:
                            f.write('test_id %d batch_size=%d kernel_size=%d lr=%.2f epoch=%d TP FP TN FN F1: %d %d %d %d %.4f\n' % (test_id, b, k, lr, e, TP, FP, TN, FN, F1))

if __name__ == "__main__":
    method = args.method
    dataset = args.dataset
    user = args.user
    device_source = args.device_source
    evaluation(method, dataset, user, device_source)
#     optimize_para(method, dataset, user, device_source)
    print('finish')