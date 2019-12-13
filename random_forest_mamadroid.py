#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-02

@author: mingo
@module: linux_920b.random_forest
'''

import numpy as np
import csv 
import time 
import os 
import argparse
from sklearn.externals import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--method', type=str)
parser.add_argument('-d', '--dataset', type=str)
# ['dataset_20132014_light_weight', 'dataset_20162017_light_weight']
parser.add_argument('-u', '--user', type=str)
# ['mlsnrs', 'shellhand']
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

def get_test_data(dataset, test_id, method, save_feature_dict, root_dir_prefix):
    root_dir = '%s/ssd_1T/mamadroid/%s/%s' % (root_dir_prefix, dataset, method)
    test_data_md5 = []
    test_data_dir = '%s/VirusShare/dataset_s_baseline/%s' % (root_dir_prefix, dataset)
    test_file  = 'test_%02d_filename.txt' % test_id
    with open(os.path.join(test_data_dir, test_file), 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            label = int(row[0])
            if label == 2:
                continue
            elif label == 0:
                label = -1  # change benign label to -1
            seq_file_path = row[1]
            md5 = seq_file_path.split('/')[1]
            test_data_md5.append([md5, label])
                
    feature_joblib_file = os.path.join(root_dir, 'save_pickle/{}.jlb'.format(test_file.replace('.txt', '')))
    with open(feature_joblib_file, 'rb') as f:
        feature_np = joblib.load(f)
        print('feature_np %s shape: %s' % (test_file.replace('.txt', ''), feature_np.shape))
    tmp_x_test = []
    tmp_y_test = []
    for row in test_data_md5:
        md5 = row[0]
        label = row[1]
        if md5 not in save_feature_dict:
            continue
        idx = save_feature_dict[md5][3]
        markov_feature = feature_np[idx,]
        tmp_x_test.append(markov_feature)
        tmp_y_test.append(label)
    x_test = np.array(tmp_x_test)
    y_test = np.array(tmp_y_test)
    s = np.arange(x_test.shape[0])
    np.random.shuffle(s)
    x_test = x_test[s]
    y_test = y_test[s]
    return x_test, y_test

def get_train_data(dataset, method, save_feature_dict, root_dir_prefix):
    root_dir = '%s/ssd_1T/mamadroid/%s/%s' % (root_dir_prefix, dataset, method)
    train_data_md5 = []
    train_data_dir = '%s/VirusShare/dataset_s_baseline/%s' % (root_dir_prefix, dataset)
    train_file  = 'train_00_filename.txt'
    with open(os.path.join(train_data_dir, train_file), 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            label = int(row[0])
            if label == 2:
                continue
            elif label == 0:
                label = -1  # change benign label to -1
            seq_file_path = row[1]
            md5 = seq_file_path.split('/')[1]
            train_data_md5.append([md5, label])
                
    feature_joblib_file = os.path.join(root_dir, 'save_pickle/{}.jlb'.format(train_file.replace('.txt', '')))
    with open(feature_joblib_file, 'rb') as f:
        feature_np = joblib.load(f)
        print('feature_np %s shape: %s' % (train_file.replace('.txt', ''), feature_np.shape))
    tmp_x_train = []
    tmp_y_train = []
    for row in train_data_md5:
        md5 = row[0]
        label = row[1]
        if md5 not in save_feature_dict:
            continue
        idx = save_feature_dict[md5][3]
        markov_feature = feature_np[idx,]
        tmp_x_train.append(markov_feature)
        tmp_y_train.append(label)
    x_train = np.array(tmp_x_train)
    y_train = np.array(tmp_y_train)
    s = np.arange(x_train.shape[0])
    np.random.shuffle(s)
    x_train = x_train[s]
    y_train = y_train[s]
    return x_train, y_train

def evaluation(method, dataset, user): 
    log_name = 'log/%s_%s_evaluation.txt' % (dataset, method)
    if os.path.exists(log_name):
        os.remove(log_name)
    if user == 'mlsnrs':
        root_dir_prefix = '/home/mlsnrs/apks'
    elif user == 'shellhand':
        root_dir_prefix = '/mnt'
    save_feature_path = '%s/ssd_1T/mamadroid/%s/%s/%s_save_feature_list.csv' % (root_dir_prefix, dataset, method, method)
    save_feature_dict = get_save_feature_dict(save_feature_path)
    print('have read save_feature_dict: %d' % len(save_feature_dict))
    x_train, y_train = get_train_data(dataset, method, save_feature_dict, root_dir_prefix)
    print('x_train shape: %s y_train shape: %s' % (str(x_train.shape), str(y_train.shape)))
    start = time.time()
    print('start train')
    clf = RandomForestClassifier(n_estimators=101, max_depth=64)
    clf.fit(x_train, y_train)
    end = time.time()
    print('Training  model time used: %f s' % (end - start))
    y_pred = clf.predict(x_train)
    cm = confusion_matrix(y_train, y_pred)
    TP = cm[1][1]
    FP = cm[0][1]
    TN = cm[0][0]
    FN = cm[1][0]
    F1 = float(2*TP)/(2*TP + FN + FP)
    print('train data TP FP TN FN F1: %d %d %d %d %.4f' % (TP, FP, TN, FN, F1))
    with open(log_name, 'a') as f:
        f.write('train data TP FP TN FN F1: %d %d %d %d %.4f\n' % (TP, FP, TN, FN, F1))
    x_train = []
    y_train = []
    for test_id in range(0, 13):
        x_test, y_test = get_test_data(dataset, test_id, method, save_feature_dict, root_dir_prefix)
        print('x_test shape: %s y_test shape: %s' % (str(x_test.shape), str(y_test.shape)))
        y_pred = clf.predict(x_test)
        cm = confusion_matrix(y_test, y_pred)
        TP = cm[1][1]
        FP = cm[0][1]
        TN = cm[0][0]
        FN = cm[1][0]
        F1 = float(2*TP)/(2*TP + FN + FP)
        print('test_id %d TP FP TN FN F1: %d %d %d %d %.4f' % (test_id, TP, FP, TN, FN, F1))
        with open(log_name, 'a') as f:
            f.write('test_id %d TP FP TN FN F1: %d %d %d %d %.4f\n' % (test_id, TP, FP, TN, FN, F1))


if __name__ == "__main__":
    method = args.method
    dataset = args.dataset
    user = args.user
    evaluation(method, dataset, user)
    print('finish')