#!/usr/bin/env python3
print("variant,sign,speedup,verify,speedup,size")
import json

ht_file = 'results.txt'
ht_all = []
with open(ht_file) as fp:
    for line in fp:
        l = json.loads(line)
        # ht.append([l['variant'], l['sign']['mean_us'], l['verify']['mean_us'], l['sig_size_bytes']])
        ht_all.append(l)

orig_file = 'orig-results.txt'
with open(orig_file) as fp:
    i = 0
    for line in fp:
        l =  json.loads(line)
        orig = [l['variant'], l['sign']['mean_us'], l['verify']['mean_us'], l['sig_size_bytes']]
        ht = [ht_all[i]['variant'], ht_all[i]['sign']['mean_us'], ht_all[i]['verify']['mean_us'], ht_all[i]['sig_size_bytes']]
        assert(ht[0] == orig[0])
        print("{},{},{:.2f},{},{:.2f},{}".format(orig[0], ht[1], orig[1]/ht[1], ht[2], orig[2]/ht[2], ht[3]))
        i += 1

