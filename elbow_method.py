#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-21

@author: mingo
@module: experiment_mama.elbow_method
'''

# clustering dataset
# determine k using elbow method

import matplotlib
matplotlib.use('AGG')  
from sklearn.cluster import KMeans
from scipy.spatial.distance import cdist
import numpy as np
import matplotlib.pyplot as plt
import pickle
import csv
import time
 
# x1 = np.array([3, 1, 1, 2, 1, 6, 6, 6, 5, 6, 7, 8, 9, 8, 9, 9, 8, 8, 9, 9, 8, 9, 8, 7, 6, 5, 6, 6, 6, 1, 2, 1, 1, 3])
# x2 = np.array([5, 4, 5, 6, 5, 8, 6, 7, 6, 7, 1, 2, 1, 2, 3, 2, 3, 5, 4, 5, 6, 5, 8, 6, 7, 6, 7, 1, 2, 1, 2, 3, 2, 3])
#  
# # plt.plot()
# # plt.xlim([0, 10])
# # plt.ylim([0, 10])
# # plt.title('Dataset')
# # plt.scatter(x1, x2)
# # plt.show()
# #  
# # # create new plot and data
# # plt.plot()
# X = np.array(list(zip(x1, x2))).reshape(len(x1), 2)
# print(X)
# colors = ['b', 'g', 'r']
# markers = ['o', 'v', 's']
#  
# # k means determine k
# distortions = []
# K = range(1, 10)
# for k in K:
#     kmeanModel = KMeans(n_clusters=k).fit(X)
#     kmeanModel.fit(X)
# #     print(kmeanModel.inertia_/X.shape[0])
#     distortions.append(sum(np.min(cdist(X, kmeanModel.cluster_centers_, 'euclidean'), axis=1)) / X.shape[0])
# #     print('%d: %s' % (k, str(kmeanModel.cluster_centers_)))
#  
# # Plot the elbow
# plt.plot(K, distortions, 'bx-')
# plt.xlabel('k')
# plt.ylabel('Distortion')
# plt.title('The Elbow Method showing the optimal k')
# plt.show()

def elbow_method_TransE_embedding():
    pkl_path = 'entity_embedding_TransE.pkl'
    with open(pkl_path, 'rb') as f:
        entity_embedding = pickle.load(f)
    print(type(entity_embedding))
    print(entity_embedding.shape)
    
    embeddings_id_entity_mapping = {}
    embeddings = []
    with open('entity_method.txt', 'r') as f:
        reader = csv.reader(f) 
        idx = 0
        for row in reader:
            entity = row[0]
            entity_id = int(row[1])
            embeddings.append(entity_embedding[entity_id, ])
            embeddings_id_entity_mapping[idx] = entity
            idx += 1
    embeddings = np.array(embeddings)
#     y_pred = KMeans(n_clusters=1000, random_state=0).fit_predict(embeddings)
    distortions = []
    K = range(100,2001, 100)
    for k in K:
        start = time.time()
        kmeanModel = KMeans(n_clusters=k)
        kmeanModel.fit(embeddings)
        inertia = kmeanModel.inertia_
        distortions.append(inertia)
        print('fit k=%d spend %fs inertia: %f' % (k, time.time() - start, inertia))
    with open('distortions.txt', 'w') as f:
        f.write('\n'.join([str(_) for _ in distortions]))
        f.write('\n')    
    plt.figure(figsize=(16,8))
    plt.plot(K, distortions, 'bx-')
    plt.xlabel('k')
    plt.ylabel('Distortion')
    plt.title('The Elbow Method showing the optimal k')
    plt.savefig('elbow_method_distortion.png')
    print('finish')

def elbow_method_evedroid_embedding():
    pkl_path = 'entity_embedding_TransE.pkl'
    with open(pkl_path, 'rb') as f:
        entity_embedding = pickle.load(f)
    print(type(entity_embedding))
    print(entity_embedding.shape)
    
    embeddings_id_entity_mapping = {}
    embeddings = []
    with open('entity_method.txt', 'r') as f:
        reader = csv.reader(f) 
        idx = 0
        for row in reader:
            entity = row[0]
            entity_id = int(row[1])
            embeddings.append(entity_embedding[entity_id, ])
            embeddings_id_entity_mapping[idx] = entity
            idx += 1
    embeddings = np.array(embeddings)
#     y_pred = KMeans(n_clusters=1000, random_state=0).fit_predict(embeddings)
    distortions = []
    K = range(100,2001, 100)
    for k in K:
        start = time.time()
        kmeanModel = KMeans(n_clusters=k)
        kmeanModel.fit(embeddings)
        inertia = kmeanModel.inertia_
        distortions.append(inertia)
        print('fit k=%d spend %fs inertia: %f' % (k, time.time() - start, inertia))
    with open('distortions.txt', 'w') as f:
        f.write('\n'.join([str(_) for _ in distortions]))
        f.write('\n')    
    plt.figure(figsize=(16,8))
    plt.plot(K, distortions, 'bx-')
    plt.xlabel('k')
    plt.ylabel('Distortion')
    plt.title('The Elbow Method showing the optimal k')
    plt.savefig('elbow_method_distortion.png')
    print('finish')

if __name__ == "__main__":
    elbow_method_TransE_embedding()