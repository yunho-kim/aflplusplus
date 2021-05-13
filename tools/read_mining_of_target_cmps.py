import sys
import os
import glob

if len(sys.argv) < 2:
  print("python3 read_mining.py out_dir [id num]")
  exit(0)

if not os.path.isfile("{}/FRIEND/cmp_queue.stat".format(sys.argv[1])):
  print("Can't find cmp_queue.stat in {}".format(sys.argv[1]))
  exit(0)

target_cmps = set()
f1 = open("{}/FRIEND/cmp_queue.stat".format(sys.argv[1]), "r")
f1.readline()
f1.readline()
for line in f1:
  cmpid = int(line.split(",")[0])
  condition = int(line.split(",")[1])
  if condition != 3:
    target_cmps.add(cmpid)

f1.close()


if(len(target_cmps) == 0):
  print("zero targets!")
  exit()

print("# of targets : {}".format(len(target_cmps)))

f1 = open("{}/FRIEND/tc_graph.stat".format(sys.argv[1]), "r")

mining_cut = dict()

for line in f1:
  if "tc_idx" in line:
    line = line.strip().split(",")
    tc_idx = int(line[0].split(":")[1])
    frag_len = int(line[2].split(":")[1])
    frag_offset = int(line[3].split(":")[1])
    mining_cut[tc_idx] = (frag_len, frag_offset)

f1.close()


cmp_bytes = dict()

def read_mining(filename, frag_len, frag_offset):
  f1 = open(filename, "rb")
  data = f1.read()
  num_mining_set = int.from_bytes(data[:4], byteorder='little')
  readidx = 4
  byteidx = 0
  byteendidx = frag_offset

  for idx1 in range(num_mining_set):
#    print ("{}~{}:".format(byteidx, byteendidx), end="")
    num_change_cmps = int.from_bytes(data[readidx:readidx+4], byteorder='little') 
    readidx += 4
    num_change_val_cmps = int.from_bytes(data[readidx:readidx+4], byteorder='little') 
    readidx += 4
    num_abandoned_cmps = int.from_bytes(data[readidx:readidx+4], byteorder='little') 
    readidx += 4
    num_new_cmps = int.from_bytes(data[readidx:readidx+4], byteorder='little') 
    readidx += 4
    timeout = int.from_bytes(data[readidx:readidx+1], byteorder='little') 
    readidx += 1
#    print("{},{},{},{}".format(num_change_cmps, num_change_val_cmps, num_abandoned_cmps, num_new_cmps))
  
    if timeout == 0:
      cmps = set()
      for idx2 in range(num_change_cmps):
        cmpid = int.from_bytes(data[readidx:readidx+4], byteorder='little')
        cmps.add(cmpid)
        readidx += 4
      target_inters = cmps.intersection(target_cmps)
      if len(target_inters) > 0:
        print("change cmps : {}:{} -> {}".format(byteidx, byteendidx, target_inters))
      cmps = set()
      for idx2 in range(num_change_val_cmps):
        cmpid = int.from_bytes(data[readidx:readidx+4], byteorder='little')
        cmps.add(cmpid)
        readidx += 4
      target_inters = cmps.intersection(target_cmps)
      if len(target_inters) > 0:
        print("change val cmps : {}:{} -> {}".format(byteidx, byteendidx, target_inters))
      cmps = set()
      for idx2 in range(num_abandoned_cmps):
        cmpid = int.from_bytes(data[readidx:readidx+4], byteorder='little')
        cmps.add(cmpid)
        readidx += 4
      target_inters = cmps.intersection(target_cmps)
      #if len(target_inters) > 0:
      #  print("abandon cmps : {}".format(target_inters))
      cmps = set()
      for idx2 in range(num_new_cmps):
        cmpid = int.from_bytes(data[readidx:readidx+4], byteorder='little')
        cmps.add(cmpid)
        readidx += 4
      target_inters = cmps.intersection(target_cmps)
      #if len(target_inters) > 0:
      #  print("new cmps : {}".format(target_inters))

    byteidx = byteendidx
    byteendidx += frag_len
  f1.close()

if len(sys.argv) == 2:
  for mfile in glob.glob("{}/FRIEND/mining/*".format(sys.argv[1])):
    tc_idx = int(mfile.split("/")[-1].split(":")[-1])
    print("tc idx : {}".format(tc_idx))
    frag = mining_cut[tc_idx]
    read_mining(mfile, frag[0], frag[1])
else:
  frag = mining_cut[int(sys.argv[2])]
  read_mining("{}/FRIEND/mining/id:{}".format(sys.argv[1], '0' * (6 - len(sys.argv[2])) + sys.argv[2]), frag[0], frag[1] )

