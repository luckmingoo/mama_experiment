#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-05

@author: mingo
@module: script_zm.find_call_line
'''

#     with open('92f3ae12c953d6f1f057dfacb070c358.txt', 'r') as f:
#         idx = 0
#         for line in f:
#             line = line.strip()
#             if line.split('==>')[1].find('android.content') != -1: # line.startswith('<android.app') and 
#                 print('%d: %s' % (idx, line.strip()))
#             idx += 1 
#     print('finish')

def find_v0():
    file_name = 'tmp_v0.txt'
    with open(file_name, 'r') as f:
        idx = 0
        for line in f:
            idx += 1
            line = line.strip().split('\t')
            if line[0] == 'selfdefined' and 'obfuscated' in line[1:]:
                print('%d: %s' % (idx, str(line)))

            
def find_v1():
    file_name = 'tmp_v0.txt'
    with open(file_name, 'r') as f:
        idx = 0
        for line in f:
            idx += 1
            line = line.strip().split('\t')
            if line[0] == 'android.app' and 'android.content' in line[1:]:
                print('%d: %s' % (idx, str(line))) 

if __name__ == "__main__":
    find_v0()
#     find_v1()
    print('finished')