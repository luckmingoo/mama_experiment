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
import json

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


def extract_packages_feature(wholefile):
    special_package_rule = {
    "android.app": [[[1, "android.app.ActivityManager"], [1, "android.app.DownloadManager"], [1, "android.app.Notification"], 
                    [1, "android.app.Service"], [1, "android.app.IntentService"], [1, "android.app.AppOpsManager"], [1, "android.app.WallpaperManager"]], 
                    ["android.app.ActivityManager", "android.app.DownloadManager", "android.app.Notification", "android.app.Service",
                     "android.app.IntentService", "android.app.AppOpsManager", "android.app.WallpaperManager"]],
    "android.content":[[[1, "android.content.ContextWrapper"], [1, "android.content.Context"], [1, "android.content.Intent"]], 
                       ["android.content.ContextWrapper", "android.content.Context", "android.content.Intent"]],
    "android.content.pm": [[[1, "android.content.pm.Activity"], [1, "android.content.pm.Application"], [1, "android.content.pm.Permission"], 
                            [1, "android.content.pm.Service"], [1, "android.content.pm.Signature"], [1, "android.content.pm.Provider"], [1, "android.content.pm.Shortcut"]], 
                           ["android.content.pm.Activity", "android.content.pm.Application", "android.content.pm.Permission", "android.content.pm.Service",
                            "android.content.pm.Signature", "android.content.pm.Provider", "android.content.pm.Shortcut"]],
    "android.hardware":[[[1, "android.hardware.Camera"]], ["android.hardware.Camera"]],
    "android.net": [[[1, "android.net.ConnectivityManager"], [1, "android.net.LocalServerSocket"], [1, "android.net.LocalSocket"], 
                     [1, "android.net.Socket"], [1, "android.net.Network"], [1, "android.net.Proxy"], 
                     [1, "android.net.SSL"], [1, "android.net.Uri"], [1, "android.net.Url"], 
                     [1, "android.net.VpnService"], [1, "android.net.TrafficStats"]], 
                    ["android.net.ConnectivityManager", "android.net.LocalServerSocket", "android.net.LocalSocket",
                     "android.net.Socket", "android.net.Network", "android.net.Proxy", "android.net.SSL", "android.net.Uri", 
                     "android.net.Url", "android.net.VpnService", "android.net.TrafficStats"]],
    "android.os":[[[1, "android.os.BatteryManager"], [1, "android.os.Binder"], [1, "android.os.Build"], [1, "android.os.Bundle"], 
                   [1, "android.os.BaseBundle"], [1, "android.os.CpuUsageInfo"], [1, "android.os.Debug"], [1, "android.os.File"], 
                   [1, "android.os.Handler"], [1, "android.os.Message"], [1, "android.os.Parcel"], [1, "android.os.PowerManager"],
                   [1, "android.os.Process"], [1, "android.os.SharedMemory"], [1, "android.os.StrictMode"], [1, "android.os.SystemClock"], 
                   [1, "android.os.User"], [1, "android.os.Vibra"]], 
                  ["android.os.BatteryManager", "android.os.Binder", "android.os.Build", "android.os.Bundle",
                   "android.os.BaseBundle", "android.os.CpuUsageInfo", "android.os.Debug", "android.os.File",
                   "android.os.Process", "android.os.SharedMemory", "android.os.StrictMode", "android.os.SystemClock",
                   "android.os.User", "android.os.Vibra"]],
    "android.provider":[[[1, "android.provider.Calendar"], [1, "android.provider.Contacts"], [1, "android.provider.Media"], [1, "android.provider.Telephony"]], 
                        ["android.provider.Calendar", "android.provider.Contacts", "android.provider.Media", "android.provider.Telephony"]],
    "android.security":[[[1, "android.security.NetworkSecurityPolicy"]], 
                        ["android.security.NetworkSecurityPolicy"]],
    "android.telephony":[[[1, "android.telephony.Sms"], [1, "android.telephony.Phone"], [1, "android.telephony.TelephonyManager"]], 
                         ["android.telephony.Sms", "android.telephony.Phone", "android.telephony.TelephonyManager"]],
    "java.io":[[[2, "Reader"], [2, "InputStream"], [2, "Writer"], [2, "OutputStream"]], 
               ["java.io.Input", "java.io.Input", "java.io.Output", "java.io.Output"]],
    "java.lang":[[[1, "java.lang.ClassLoader"], [1, "java.lang.Process"], [1, "java.lang.Runtime"], [1, "java.lang.System"], [1, "java.lang.Thread"]], 
                 ["java.lang.ClassLoader", "java.lang.Process", "java.lang.Runtime", "java.lang.System", "java.lang.Thread"]]
    } # in rule, 1 index string startswith, 2 index string find
    packages_translate = get_package_mapping()
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
            if match in special_package_rule:
                for idx, rule in enumerate(special_package_rule[match][0]):
                    if rule[0] == 1:
                        if j.startswith(rule[1]):
                            match = special_package_rule[match][1][idx]
                            break
                    elif rule[0] == 2:
                        if j.find(rule[1]) != -1:
                            match = special_package_rule[match][1][idx]
                            break
            elif match in packages_translate:
                match = packages_translate[match]
            else:
                splitted = j.split('.')
                obfcount=0
                for k in range (0,len(splitted)):
                    if len(splitted[k])<3:
                        obfcount+=1
                if obfcount >= len(splitted)/2.0:
                    match='obfuscated'
                else:
                    match='selfdefined'
            Packetsline.append(match)
        Packetsfile.append(Packetsline)
#     with open('tmp_v4.txt', 'w') as f:
#         for line in Packetsfile:
#             f.write('\t'.join(line))
#             f.write('\n')
    return Packetsfile          

def markov_feature(features, output_path):
    PACKETS = []
    with open('uniq_package_v4.txt', 'r') as f:
        for line in f:
            package = line.strip()
            PACKETS.append(package)
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
    with open('manual_package_v4_mapping.txt', 'r') as f:
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