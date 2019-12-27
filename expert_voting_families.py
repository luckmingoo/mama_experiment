#!/usr/bin/env python
# coding: utf-8

from collections import defaultdict
import random
import string
import math
import statistics as sts
import numpy as np
import plotly.graph_objects as go
import csv 
import os
import time


# # Utils: Tree plotter

# In[28]:


def make_annotations(pos, text, font_size=10, font_color='rgb(250,250,250)'):
    L=len(pos)
    if len(text)!=L:
        raise ValueError('The lists pos and text must have the same len')
    annotations = []
    for k in range(L):
        annotations.append(
            dict(
                text=text[k], # or replace labels with a different list for the text within the circle
                x=pos[k][0], y=pos[k][1],
                xref='x1', yref='y1',
                font=dict(color=font_color, size=font_size),
                showarrow=False)
        )
    return annotations

def gather_level_nodes_info(nodes, parents, Xn, Yn, Xe, Ye, labels):
    next_level_childs = []
    parents_pos = []
    all_len = 0
    for n in nodes:
        all_len += len(n)
    num = 0 # precocess nodes num
    for i, pos in enumerate(parents):
        ci = nodes[i]
        y_pos = pos[1] - 1
        for j, c in enumerate(ci):
            k = c[0]
            node = c[1]
            
            # plot info
            Xn.append(num + j - all_len/2)
            Yn.append(y_pos)
            labels.append('{}|{:d}|{:.2f}'.format(k, int(node[0]), node[1]))
            Xe.extend([pos[0], Xn[-1], None])
            Ye.extend([pos[1], Yn[-1], None])
            
            # recusive
            childs = [(k, node[2][k]) for k in node[2]]
            if len(childs) > 0:
                parents_pos.append([Xn[-1], Yn[-1]])
                next_level_childs.append(childs)
        num += len(ci)
#     return None
    if len(next_level_childs) > 0:
        gather_level_nodes_info(next_level_childs, parents_pos, Xn, Yn, Xe, Ye, labels)
    
def plot_trie(trie, use_marker=False):
    labels = ['root']
    Xn = [0]
    Yn = [0]
    Xe = []
    Ye = []
    
    first_level_nodes = []
    for k in trie.root:
        first_level_nodes.append((k,trie.root[k]))
    gather_level_nodes_info([first_level_nodes], [[0,0]], Xn, Yn, Xe, Ye, labels)
    
    fig = go.Figure()
    # plot egdes
    fig.add_trace(go.Scatter(x=Xe,
                       y=Ye,
                       mode='lines',
                       name='edges',
                       line=dict(color='rgb(210,210,210)', width=1),
                       hoverinfo='none'
                       ))
    
    # plot nodes
    fig.add_trace(go.Scatter(x=Xn,
                      y=Yn,
                      mode='markers' if use_marker else 'text',
                      name='Nodes',
                      marker=dict(symbol='circle-dot',
                                    size=18,
                                    color='#6175c1',    #'#DB4551',
                                    line=dict(color='rgb(50,50,50)', width=1)
                                    ),
                      text=labels,
                      hoverinfo='text',
                      opacity=0.8
                      ))
    fig.update_layout(title= 'Trie Layout')
    fig.show()
# plot_trie(seq_trie)


# # 1. build sequence Trie

# In[29]:


class Trie:
    def __init__(self, depth):
        self.root = {}
        self.depth = depth - 1 # subsract root level
        # Node type: k:(frequency, entropy, subnodes)
        
    def _insert_word(self, word):
        """
        insert a sequence
        """
        cur = self.root
        for c in word:
            if c in cur:
                cur[c][0] += 1
            else:
                cur[c] = [1,0,{}]
            cur = cur[c][2]
        
        return self
    
    def insert_sequence(self, seq):
        """
        insert a sequence.
        """
        # TODO improve efficiency
        for i in range(len(seq)):
            self._insert_word(seq[i:i+self.depth])
        return self
    
    def insert_sequences(self, seqs):
        """
        insert a list of sequences
        """
        for seq in seqs:
            self.insert_sequence(seq)
            
        return self

    def search_word(self, word):
        """
        search the node of the word
        """
        cur = self.root
        node = None
        for c in word:
            try:
                node = cur[c]
            except KeyError: # no such word
                return None
            cur = node[2]
            
        return node


# In[5]:


## test
def randomString(stringLength=30):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))



# # 2. expert voting
# ## 2.1 calculate entropy

# In[33]:


def cal_entropy(node):
    
    fre = node[0]
    p = []
    
    # search child
    childs = node[2]
    for k in childs:
        child = childs[k]
        p.append(child[0]/fre)
        
        # cal entropy of the child
        if len(child[2]) == 0:
            continue # leaf node
        cal_entropy(child)
    
    # calculate entropy
    e = 0
    for pi in p:
        try:
            e += pi * math.log(pi)
        except ValueError:
            print(pi)
    node[1] = -e


# In[34]:


def cal_trie_entropy(trie):
    for k in trie.root:
        cal_entropy(trie.root[k])



# ## 2.2 normalize frequency and entropy

# In[38]:


def normalize_nodes(nodes):
    """
    input: nodes belong to the same level
    """
    fres = []
    ens = []
    for node in nodes:
        fres.append(node[0])
        ens.append(node[1])
    
    # calculate mean and std
    fres_mean = sts.mean(fres)
    fres_std = sts.stdev(fres) + 1e-8
    ens_mean = sts.mean(ens) 
    ens_std = sts.stdev(ens) + 1e-8
    
    all_childs = []
    for node in nodes:
        node[0] = (node[0] - fres_mean) / fres_std
        node[1] = (node[1] - ens_mean) / ens_std
        
        # collect non empty childs in next level
        cur_node_childs = node[2]
        for k in cur_node_childs:
            child = cur_node_childs[k]
            all_childs.append(child)
    
    # normalize the childs of next level
    if len(all_childs) > 0:
        normalize_nodes(all_childs)


# In[39]:


def normalize_trie(trie):
    first_level_nodes = []
    for k in trie.root:
        first_level_nodes.append(trie.root[k])
    normalize_nodes(first_level_nodes)

# ## 2.3 extract episodes

# In[19]:


# cal entropy and normalize
def preprocess_trie(trie):
    first_level_nodes = []
    for k in trie.root:
        node = trie.root[k]
        cal_entropy(node)
        first_level_nodes.append(node)
    normalize_trie(trie)


# In[20]:

def extract_episodes(trie, seqs, verbose=False):
    """
    extract episodes accordding to the info in trie
    """
    
    episodes = []
    
    # calculate score
    for seq in seqs:
        scores = [0 for _ in range(len(seq))]
        for i in range(len(seq) - trie.depth):
            k = trie.depth
            fre_score = []
            en_score = []
            for j in range(k):
                node1 = trie.search_word(seq[i:i+j+1])
                if j < k-1:
                    node2 = trie.search_word(seq[i+j+1:i+k])
                else:
                    node2 = [0] # this is a problem, 0 does not mean no infulence??
                fre_score.append(node1[0] + node2[0])
                en_score.append(node1[1])
            fre_max = np.argmax(fre_score)
            en_max = np.argmax(en_score)
            scores[i + fre_max] += 1
            scores[i + en_max] += 1
    

        # divide seq
        end = start = 0
        for i in range(len(scores) - 2):
            j = i + 1
            if scores[j] > scores[j-1] and scores[j] > scores[j+1]:
                end = j + 1
                episodes.append(seq[start:end])
                start = end
        if start < len(seq): # this would be ok
            episodes.append(seq[start:]) 
        
        if verbose:
            print(scores)
    return episodes

def get_seq_path_dict():
    seq_path_dict = {}
    malware_seq_csv_path = '/mnt/VirusShare/lldroid_output/apk_malicious_seq_11w_combine_soot2016.csv'
    with open(malware_seq_csv_path, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            seq_path = row[0]
            md5 = seq_path.split('/')[1]
            seq_path_dict[md5] = seq_path
    return seq_path_dict

def update_stop_time(period_start_year_month, one_period):
    min_year = int(period_start_year_month/100)
    min_month = int(period_start_year_month%100)
    family_time_stop_year = min_year + int((min_month + one_period)/13)
    tmp_month = (min_month + one_period)
    if tmp_month == 12:  
        family_time_stop_month =  tmp_month
    else:
        family_time_stop_month = tmp_month%12
    period_end_year_month = int('%d%02d' % (family_time_stop_year, family_time_stop_month)) 
    return period_end_year_month 

def get_all_families_periods(min_x_month_after, min_rate, seq_path_dict):
    malware_dataset_path = 'dataset_euphony_family_filted.csv' # [md5, family, support_num, first_seen, vt_cnt]
    family_app = {} # key = family_name, value = [[md5, first_year_month]
    with open(malware_dataset_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            md5 = row[0]
            if md5 not in seq_path_dict:
                continue
            first_seen = row[3]
            family_name = row[1]
            if family_name not in family_app:
                family_app[family_name] = []
            first_year_month = int(first_seen.split('-')[0] + first_seen.split('-')[1])
            family_app[family_name].append([md5, first_year_month])
    all_families_periods = {}
    for family_name in family_app: # 'airpush', 'smsreg', 'fakeinst', 'gappusin', 'youmi', 'dowgin', 'adwo', 'kuguo', 'secapk', 'droidkungfu'
        if len(family_app[family_name]) < 500:
            continue
        family_app_periods = []
        family_app[family_name].sort(key = lambda x:x[1])
        period_start_year_month = family_app[family_name][0][1]
        period_end_year_month = update_stop_time(period_start_year_month, min_x_month_after)
        period_row = []
        min_app_num = int(len(family_app[family_name]) * min_rate)
        for row in family_app[family_name]:
            first_year_month = row[1]
            if first_year_month < period_end_year_month:
                period_row.append(row)
            else:
                if len(period_row) < min_app_num:
                    period_row.append(row)
                    period_end_year_month = update_stop_time(period_end_year_month, min_x_month_after)
                else:
                    family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), period_row])
                    period_row = []
                    period_start_year_month = period_end_year_month
                    period_end_year_month = update_stop_time(period_end_year_month, min_x_month_after)
        if len(period_row) >= (min_app_num/2):
            family_app_periods.append(['%d-%d' % (period_start_year_month, period_end_year_month), period_row])
        all_families_periods[family_name] = family_app_periods
        print(family_name),
        for row in family_app_periods:
            print('%s:%d ' % (row[0], len(row[1]))),
        print('')
    return all_families_periods

def get_seq_list(family_app_period, seq_path_dict, api_id_dict): # [[md5, first_year_month]]
    not_in_dict_api = set()
    root_dir = '/mnt/VirusShare/lldroid_output'
    seq_list = []
    for row in family_app_period:
        md5 = row[0]
        seq_path = seq_path_dict[md5]
        seq_path = seq_path.replace('.seq', '.dfs')
        seq_abspath = os.path.join(root_dir, seq_path)
        if os.path.exists(seq_abspath):
            with open(seq_abspath, 'r') as f:
                api_seq = []
                for api in f:
                    api = api.strip()
                    api = api.replace('->', '.')
                    if api in api_id_dict:
                        api_seq.append(api_id_dict[api])
                    else:
                        not_in_dict_api.add(api)
#                         print(api)
                if api_seq:
                    seq_list.append(api_seq)
        else:
            print('not exist: %s' % seq_path)
    with open('not_in_dict_api.csv', 'wb') as f:
        writer = csv.writer(f) 
        writer.writerows([[_] for _ in not_in_dict_api])
    return seq_list

#     sensitive_method_file = '/home/mlsnrs/share/zm/embedding/data/kg_dir/sensitive_method.txt'
#     idx = 0
#     api_id_dict = {}
#     id_api_dict = {}
#     with open(sensitive_method_file, 'r') as f:
#         for line in f:
#             idx += 1
#             api = line.strip()
#             api_id_dict[api] = idx
#             id_api_dict[idx] = api
#     malicious_csv_file = '/home/mlsnrs/apks/ssd_1T/lldroid_output/apk_malicious_seq_11w_combine_soot2016.csv'
#     benign_csv_file = '/home/mlsnrs/apks/ssd_1T/lldroid_output/apk_benign_seq_100w_combine_soot2016.csv'
#     
#     # for malicious
#     malicious_seq_year_list = [[] for _ in range(2012, 2019)]
#     malicious_seq_file_list = [[] for _ in range(2012, 2019)]
#     with open(malicious_csv_file, 'r') as f:
#         reader = csv.reader(f) 
#         for row in reader:
#             seq_file_path = row[0]
#             first_seen = row[1]
#             fs_year = int(first_seen.split('-')[0])
#             malicious_seq_file_list[fs_year - 2012].append(seq_file_path)
#     idx = 0
#     for fs_year in range(2012, 2019):
#         for seq_file_path in malicious_seq_file_list[fs_year - 2012]:
#             dfs_file_abspath = os.path.join('/home/mlsnrs/apks/ssd_1T/lldroid_output/', seq_file_path.replace('.seq', '.dfs'))
#             if not os.path.exists(dfs_file_abspath):
#                 continue 
#             with open(dfs_file_abspath, 'r') as f:
#                 api_seq = []
#                 for line in f:
#                     api = line.strip()
#                     if api in api_id_dict:
#                         api_seq.append(api_id_dict[api])
#                 if api_seq:
#                     malicious_seq_year_list[fs_year - 2012].append(api_seq)
#             idx += 1
#             if idx % 10000 == 0:
#                 print('malicious %d: %s' % (idx, seq_file_path))
# #             if idx > 20000:
# #                 break
#     
#     # for benign
#     benign_seq_year_list = [[] for _ in range(2012, 2019)]
#     benign_seq_file_list = [[] for _ in range(2012, 2019)]
#     with open(benign_csv_file, 'r') as f:
#         reader = csv.reader(f) 
#         for row in reader:
#             seq_file_path = row[0]
#             first_seen = row[1]
#             fs_year = int(first_seen.split('-')[0])
#             benign_seq_file_list[fs_year - 2012].append(seq_file_path)
#     idx = 0
#     for fs_year in range(2012, 2019):
#         for seq_file_path in benign_seq_file_list[fs_year - 2012]:
#             dfs_file_abspath = os.path.join('/home/mlsnrs/apks/ssd_1T/lldroid_output/', seq_file_path.replace('.seq', '.dfs'))
#             if not os.path.exists(dfs_file_abspath):
#                 continue 
#             with open(dfs_file_abspath, 'r') as f:
#                 api_seq = []
#                 for line in f:
#                     api = line.strip()
#                     if api in api_id_dict:
#                         api_seq.append(api_id_dict[api])
#                 if api_seq:
#                     benign_seq_year_list[fs_year - 2012].append(api_seq)
#             idx += 1
#             if idx % 10000 == 0:
#                 print('benign %d: %s' % (idx, seq_file_path))
# #             if idx > 50000:
# #                 break
#     return malicious_seq_year_list, benign_seq_year_list, api_id_dict, id_api_dict

def get_method_mapping():
    method_file = 'entity_method.txt'
    api_id_dict = {}
    id_api_dict = {}
    with open(method_file, 'r') as f:
        reader = csv.reader(f) 
        for row in reader:
            api = row[0]
            api_id = int(row[1])
            api_id_dict[api] = api_id 
            id_api_dict[api_id] = api
    return api_id_dict, id_api_dict

def main():
    api_id_dict, id_api_dict = get_method_mapping()
    seq_path_dict = get_seq_path_dict()
    all_families_periods = get_all_families_periods(3, 0.1, seq_path_dict)
#     print("len api_id_dict: %d id_api_dict: %d" % (len(api_id_dict), len(id_api_dict)))
#     print(len(all_families_periods))
#     print(all_families_periods.keys())

    for family_name in all_families_periods: # all_families_periods[family_name] = [['%d-%d' % (period_start_year_month, period_end_year_month), period_row], ]
        families_periods = all_families_periods[family_name]
        for one_period in families_periods:
            period_time = one_period[0]
            seq_dict = {}
            seq_list = get_seq_list(one_period[1], seq_path_dict, api_id_dict)
            print(len(seq_list))
            start = time.time()
            d = 5
            test_trie = Trie(depth=d).insert_sequences(seq_list)
            preprocess_trie(test_trie)
            split_seq_list = extract_episodes(test_trie, seq_list)
            for seq in split_seq_list:
                seq_tuple = tuple(seq)
                if seq_tuple in seq_dict:
                    seq_dict[seq_tuple] = seq_dict[seq_tuple] + 1
                else:
                    seq_dict[seq_tuple] = 1
            print('%s %s spend time: %f seq_kind: %d' % (family_name, period_time, time.time() - start, len(seq_dict)))
            save_csv = []
            for id_seq, count in seq_dict.items():
                api_seq = [id_api_dict[id] for id in id_seq]
                average_count = count/float(len(one_period[1]))
                save_csv.append([api_seq, average_count])
            save_csv.sort(key=lambda x:x[1], reverse=True)
            with open('expert_voting_seqs/%s_%s_depth%02d.csv' % (family_name,period_time, d ), 'wb') as f:
                writer = csv.writer(f) 
                writer.writerows(save_csv)


#     malicious_seq_year_list, benign_seq_year_list, api_id_dict, id_api_dict = get_seq_list()
#     
#     # for malicious
#     malicious_seq_year_dict = [{} for _ in range(2012, 2019)]
#     for fs_year in range(2012, 2019):
#         start = time.time()
#         d = 5
#         test_trie = Trie(depth=d).insert_sequences(malicious_seq_year_list[fs_year - 2012])
#         preprocess_trie(test_trie)
#         split_seq_list = extract_episodes(test_trie, malicious_seq_year_list[fs_year - 2012])
#         for seq in split_seq_list:
#             seq_tuple = tuple(seq)
#             if seq_tuple in malicious_seq_year_dict[fs_year - 2012]:
#                 malicious_seq_year_dict[fs_year - 2012][seq_tuple] = malicious_seq_year_dict[fs_year - 2012][seq_tuple] + 1
#             else:
#                 malicious_seq_year_dict[fs_year - 2012][seq_tuple] = 1
#         print('malicious %d time: %f seq_kind: %d' % (fs_year, time.time() - start, len(malicious_seq_year_dict[fs_year - 2012])))
#         save_csv = []
#         for id_seq, count in malicious_seq_year_dict[fs_year - 2012].items():
#             api_seq = [id_api_dict[id] for id in id_seq]
#             save_csv.append([api_seq, count])
#         save_csv.sort(key=lambda x:x[1], reverse=True)
#         with open('split_seqs/malicious_depth%02d_%d.csv' % (d, fs_year), 'w') as f:
#             writer = csv.writer(f) 
#             writer.writerows(save_csv)
#     
#     # for benign
#     benign_seq_year_dict = [{} for _ in range(2012, 2019)]
#     for fs_year in range(2012, 2019):
#         start = time.time()
#         d = 5
#         test_trie = Trie(depth=d).insert_sequences(benign_seq_year_list[fs_year - 2012])
#         preprocess_trie(test_trie)
#         split_seq_list = extract_episodes(test_trie, benign_seq_year_list[fs_year - 2012])
#         for seq in split_seq_list:
#             seq_tuple = tuple(seq)
#             if seq_tuple in benign_seq_year_dict[fs_year - 2012]:
#                 benign_seq_year_dict[fs_year - 2012][seq_tuple] = benign_seq_year_dict[fs_year - 2012][seq_tuple] + 1
#             else:
#                 benign_seq_year_dict[fs_year - 2012][seq_tuple] = 1
#         print('benign %d time: %f seq_kind: %d' % (fs_year, time.time() - start, len(benign_seq_year_dict[fs_year - 2012])))
#         save_csv = []
#         for id_seq, count in benign_seq_year_dict[fs_year - 2012].items():
#             api_seq = [id_api_dict[id] for id in id_seq]
#             save_csv.append([api_seq, count])
#         save_csv.sort(key=lambda x:x[1], reverse=True)
#         with open('split_seqs/benign_depth%02d_%d.csv' % (d, fs_year), 'w') as f:
#             writer = csv.writer(f) 
#             writer.writerows(save_csv)
            
#     # strs = [randomString(30) for _ in range(10)]
# #     strs = [['Fe', 'Dj', 'Fd', 'Fe', 'Fd', 'Dg', 'Ke']]
#     # seq_trie = Trie(depth=5).insert_sequences(strs)
#     seq_trie = Trie(depth=5).insert_sequences(malicious_seq_list)
#     # In[32]:
#     seq_trie.root
#     # In[9]:
# #     seq_trie.search_word(['Fe', 'Dj'])
#     # test 
#     cal_trie_entropy(seq_trie)
#     seq_trie.root
#     # In[37]:
#     plot_trie(seq_trie)
#     
#     # In[40]:
#     normalize_trie(seq_trie)
#     # In[41]:
#     seq_trie.root
#     # test all
#     test_strs = [['Fe', 'Dj', 'Fd', 'Fe', 'Fd', 'Dg', 'Ke'],
#                 ['Fc', 'Fe', 'Fd', 'Kf', 'Ia', 'Fe', 'Fd'],
#                 ['Dg', 'Fc', 'Fd', 'Fc', 'Fd', 'Fc', 'Fd', 'Fc', 'Fd'],
#                 ['Km', 'Fe', 'Fd', 'Fc', 'Fd']]
# #     # In[22]:
#     for d in range(3, 15):
#         start = time.time()
#         test_trie = Trie(depth=d).insert_sequences(malicious_seq_list)
# #         cal_trie_entropy(test_trie)
# #         normalize_trie(test_trie) 
#         preprocess_trie(test_trie)
#     #     # In[23]:
#     #     plot_trie(test_trie, use_marker=True)
#     #     # In[24]:
#     #     normalize_trie(test_trie)
#         split_seq = extract_episodes(test_trie, [malicious_seq_list[1]])
#         print("malicious depth: %d time: %f split_seq num: %d" % (d, time.time() - start, len(split_seq)))
#     for d in range(3, 15):
#         start = time.time()
#         test_trie = Trie(depth=d).insert_sequences(benign_seq_list)
# #         cal_trie_entropy(test_trie) 
# #         normalize_trie(test_trie)
#         preprocess_trie(test_trie)
#     #     # In[23]:
#     #     plot_trie(test_trie, use_marker=True)
#     #     # In[24]:
#     #     normalize_trie(test_trie)
#         split_seq = extract_episodes(test_trie, [benign_seq_list[1]])
#         print("benign depth: %d time: %f split_seq num: %d" % (d, time.time() - start, len(split_seq)))



if __name__ == "__main__":
    main()


