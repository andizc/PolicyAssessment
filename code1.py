#!/usr/bin/env python3

import subprocess
import csv
import multiprocessing
import os
import argparse
# This script processes PCAP files to extract DNS query and TCP SYN information
def run(x):
    try:
        p = subprocess.Popen(x, stdout=subprocess.PIPE, text=True)
        return p.stdout.readlines()
    except:
        return []
#extracts DNS queries, TCP SYNs, and DNS A records
def getInfo(f):
    doms = {}
    ips = {}
    names = set()

    a = ['tshark', '-r', f, '-Y', 'dns.qry.name && !udp.port==123 && !udp.port==37', '-T', 'fields', '-e', 'dns.qry.name', '-e', 'frame.len', '-E', 'separator=,', '-E', 'header=n']
    b = ['tshark', '-r', f, '-Y', 'tcp.flags.syn==1 && tcp.flags.ack==0 && !udp.port==123 && !udp.port==37', '-T', 'fields', '-e', 'ip.dst', '-e', 'frame.len', '-E', 'separator=,', '-E', 'header=n']
    c = ['tshark', '-r', f, '-Y', 'dns.a && !udp.port==123 && !udp.port==37', '-T', 'fields', '-e', 'dns.a', '-E', 'header=n']
#parse dns queries
    for i in run(a):
        try:
            parts = i.strip().split(',')
            if len(parts) < 2: continue
            if 'ntp' in parts[0].lower() or 'time' in parts[0].lower(): continue
            if parts[0] not in doms:
                doms[parts[0]] = [1, int(parts[1])]
            else:
                doms[parts[0]][0] += 1
                doms[parts[0]][1] += int(parts[1])
        except:
            pass
#parse SYNs
    for i in run(b):
        try:
            parts = i.strip().split(',')
            if len(parts) < 2: continue
            ip = parts[0]
            if ip not in ips:
                ips[ip] = [1, int(parts[1])]
            else:
                ips[ip][0] += 1
                ips[ip][1] += int(parts[1])
        except:
            pass
# parse IPs from DNS A records
    for i in run(c):
        try:
            for j in i.strip().split(','):
                if j: names.add(j)
        except:
            pass

    return doms, ips, names
#combining domain and ip dictionaries, sum counts
def comb(lst):
    final = {}
    for d in lst:
        for k in d:
            if k not in final:
                final[k] = [d[k][0], d[k][1]]
            else:
                final[k][0] += d[k][0]
                final[k][1] += d[k][1]
    return final
#write results to csv
def dump(name, cols, d):
    with open(name, 'w') as f:
        w = csv.writer(f)
        w.writerow(cols)
        for k in sorted(d.keys()):
            w.writerow([k] + d[k])
 #hangles command-line arguments and runs analysis
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap_list')
    parser.add_argument('output_dir')
    parser.add_argument('-p', type=int, default=4)
    args = parser.parse_args()
#read pcaps
    try:
        with open(args.pcap_list, 'r') as f:
            all_files = [x.strip() for x in f.readlines() if x.strip()]
    except:
        print("error loading list file")
        return

    p = multiprocessing.Pool(args.p)
    res = p.map(getInfo, all_files)

    domall, ipall, dnsips = [], [], []

    for x in res:
        domall.append(x[0])
        ipall.append(x[1])
        dnsips.append(x[2])

    finaldoms = comb(domall)
    finalips = comb(ipall)
    allips = set()
    for s in dnsips:
        allips.update(s)

    badips = {}
    for k in finalips:
        if k not in allips:
            badips[k] = finalips[k]
# create output dir if doesnt exist
    try:
        os.makedirs(args.output_dir)
    except:
        pass

    dump(args.output_dir + '/domains.csv', ['domain', 'queries', 'bytes'], finaldoms)
    dump(args.output_dir + '/ips.csv', ['ip', 'tcp_syns', 'bytes'], finalips)
    dump(args.output_dir + '/nodomips.csv', ['ip', 'tcp_syns', 'bytes'], badips)

if __name__ == '__main__':
    main()
