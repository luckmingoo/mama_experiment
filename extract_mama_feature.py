#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-11-28

@author: mingo
@module: script_zm.extract_mama_feature
'''

import csv 
import argparse
import numpy
import os 
import time

parser = argparse.ArgumentParser()
parser.add_argument("-s","--source", type=str)
parser.add_argument("-o", "--output", type=str)
args = parser.parse_args()


#Dummy Coding for Markov Transition matrix
def dummycoding(imported,allnodes):
    DCVector=[]
    DNSCounter=0
    for i in range (0,len(imported)): 
        DCVector.append([])
        callsline=imported[i]
        for v in range (0,len(callsline)):    
            for s in range (0,len(allnodes)):
                if (callsline[v]==allnodes[s]):
                    DCVector[i].append(s)
    return DCVector

def matrixcreation (DCVector,allnodes):
    s = (len(allnodes),len(allnodes))
    MarkovTransition= numpy.zeros(s)
    MarkovFeats= numpy.zeros(s)
    for s in range (0,len(DCVector)):
        for i in range (1,len(DCVector[s])):
            MarkovTransition [DCVector[s][0],DCVector[s][i]] = MarkovTransition [DCVector[s][0],DCVector[s][i]]+1
    
    for i in range (0, len(MarkovTransition)):
        Norma= numpy.sum(MarkovTransition[i])
        if (Norma==0):
            MarkovFeats[i]=MarkovTransition[i]
        else:
            MarkovFeats[i]= MarkovTransition[i]/Norma

    return MarkovFeats  

def get_markove_features(imported, alln):   
    (DCV)= dummycoding(imported, alln)
    MarkovFeatures= matrixcreation(DCV, alln)
    return MarkovFeatures

def PackAbs(call, pos):
    partitions=call.split('.')
    package=''
    for i in range (0,len(partitions)):
        if partitions[i] in pos[i]:
            package=package+partitions[i]+'.'
        else:
            if package=="" or package=='com':
                package=None
            else:
                pointflag=0
                while pointflag==0:
                    if package.endswith('.'):
                        package=package[0:-1]
                    else:
                        pointflag=1
                        break
            if package=='com':
                package=None
            break
    return package

# def parse_file(graph_path):
#     with open(graph_path, 'r') as callseq:
#         specificapp=[]
#         for line in callseq:
#             specificapp.append(line)
#         callseq.close()
# 
#     call=[]
#     nextblock=[]
#     nextcall=[]
#     for line in specificapp:
#         if (line[0]=='<' and (line[1]=="'" or line[1].isalpha())):
#             call.append(str(line.split('(')[0]))
#             nextblock.append(str(line.split('==>')[1]))
# 
#     for j in range (0,len(nextblock)):
#         supporto=nextblock[j].translate(None, '[]\'\\')
#         supporto=supporto.replace('\n','')
#         nextcall.append([])
#         nextcall[j]=(supporto.split(',')) # if a method has two or above paras,
#     wholefile=[] 
#     for j in range (0, len(call)):
#         eachline=call[j]+'\t'
#         for k in range (0,len(nextcall[j])):
#             tagliaparam=nextcall[j][k].split('(')[0]
#             eachline=eachline+tagliaparam+'\t'
#         wholefile.append(eachline)
#     return wholefile


def parse_file(graph_path):
    with open(graph_path, 'r') as callseq:
        specificapp=[]
        for line in callseq:
            specificapp.append(line)
        callseq.close()   
         
    call=[]
    nextblock=[]
    nextcall=[]
    for line in specificapp:
        if (line[0]=='<' and (line[1]=="'" or line[1].isalpha())):
            call.append(str(line.split('(')[0]))
            nextblock.append(str(line.split('==>')[1]))

    for j in range (0,len(nextblock)):
        supporto=nextblock[j].translate(None, '[]\'')
        supporto=supporto.replace('\\n','')
        nextcall.append([])
#         nextcall[j]=(supporto.split(','))
        nextcall[j]=([ _ for _ in supporto.split(',') if (_.find('(')!= -1)]) # fix the bug that if a method have many parameters
    wholefile=[] 
    for j in range (0, len(call)):
        eachline=call[j]+'\t'
        for k in range (0,len(nextcall[j])):
            tagliaparam=nextcall[j][k].split('(')[0]
            eachline=eachline+tagliaparam+'\t'
        wholefile.append(eachline)
    return wholefile

def extract_families_feature(wholefile):
    PACKETS=[]
    with open('Families.txt') as packseq:
        for line in packseq:
            PACKETS.append(line.replace('\n',''))
        packseq.close()
    Packetsfile=[]
    for line in wholefile:
        Packetsline=[]
        for j in line.split('\t')[:-1]:
            match = False
            for y in PACKETS:
                x = y.partition('.')[2] 
                j = j.replace('<','')
                j = j.replace(' ','')
                if j.startswith(x):
                    match = x
                    break
            if match == False:
                splitted = j.split('.')
                obfcount=0
                for k in range (0,len(splitted)):
                    if len(splitted[k])<3:
                        obfcount+=1
                if obfcount>=len(splitted)/2:
                    match='obfuscated'
                else:
                    match='selfdefined'
            Packetsline.append(match)
        Packetsfile.append(Packetsline)
    return Packetsfile

def extract_packages_feature(wholefile):
    package_mapping = get_package_mapping()
    PACKETS=[]
    with open('Packages.txt') as packseq:
        for line in packseq:
            PACKETS.append(line.replace('\n',''))
        packseq.close()
    allpacks=[]
    for i in PACKETS:
        allpacks.append(i.split('.')[1:])
    pos=[[],[],[],[],[],[],[],[],[]]
    for i in allpacks:
        k=len(i)
        for j in range(0,k):
            if i[j] not in pos[j]:
                pos[j].append(i[j])
    Packetsfile=[]
    for line in wholefile:
        Packetsline=[]
        for j in line.split('\t')[:-1]: # the -1 because there is a '\t' in the last.
            match = None
            j = j.replace('<','')
            j = j.replace(' ','')
            j = j[:j.find(':')]
            match=PackAbs(j,pos)
            if match == None:
                splitted = j.split('.')
                obfcount=0
                for k in range (0,len(splitted)):
                    if len(splitted[k])<3:
                        obfcount+=1
                if obfcount >= len(splitted)/2:
                    match='obfuscated'
                else:
                    match='selfdefined'
            if match in package_mapping:
                if match == 'java.lang' and j.split('.')[-1] in ['ClassLoader', 'Process', 'ProcessBuilder', 'Runtime', 'SecurityManager', 'System']:
                    match = 'java.lang.system'
                else:
                    match = package_mapping[match]
            Packetsline.append(match)
        Packetsfile.append(Packetsline)
    return Packetsfile

def markov_feature(features, output_path):
    PACKETS=[]
    with open('package_uniq.txt', 'r') as packseq:
        for line in packseq:
            PACKETS.append(line.replace('\n',''))
        packseq.close()
    allnodes = PACKETS
    allnodes.append('selfdefined')
    allnodes.append('obfuscated')
    

#     Header=[]
#     for i in range (0,len(allnodes)):
#         for j in range (0,len(allnodes)):
#             Header.append(allnodes[i]+'To'+allnodes[j])

    MarkMat = get_markove_features(features, allnodes)
    MarkRow = []
    for i in range (0,len(MarkMat)):
        for j in range (0,len(MarkMat)):
            MarkRow.append(MarkMat[i][j])
    with open(output_path, 'wb') as f:
        writer = csv.writer(f)
        writer.writerow(MarkRow)

def extract_mama_feature(graph_path, output_path):
    wholefile = parse_file(graph_path)
    package_feature = extract_packages_feature(wholefile)
    markov_feature(package_feature, output_path)

def get_package_mapping():
    package_mapping = {}
    with open('package_mapping.txt', 'r') as f:
        for line in f:
            packages = line.strip().split(' ')
            package_mapping[packages[0]] = packages[1]
    return package_mapping
    
if __name__ == "__main__":
    graph_path = args.source
    output_path = args.output
#     graph_path = '92f3ae12c953d6f1f057dfacb070c358.txt'
#     output_path = '92f3ae12c953d6f1f057dfacb070c358.csv'
    start = time.time()
    if os.path.exists(graph_path) and not os.path.exists(output_path):
        extract_mama_feature(graph_path, output_path)
    print('process spend %f %s' % (time.time() - start, graph_path))