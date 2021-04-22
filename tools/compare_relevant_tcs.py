import subprocess
import glob
import random
from gen_tree import tctree
import editdistance

NUM_PAIR = 1000

tclist = glob.glob("./queue/*")
num_tc = len(tclist)

tcs = []
for i in range(num_tc):
  tcs.append(tctree(i))


#tcid -> tclist idx
tclistidx = {}

for idx, tcline in enumerate(tclist):
  if "orig" in tcline or "sync" in tcline:
    continue

  tcid = int(tcline.split("/")[-1].split(",")[0][3:])
  tclistidx[tcid] = idx
  parents = tcline.split("/")[-1].split(",")[1][4:]
  if "+" in parents:
    parents = parents.split("+")
    tcs[tcid].add_parent(int(parents[0]))
    tcs[tcid].add_parent(int(parents[1]))
    tcs[int(parents[0])].add_child(tcid)
    tcs[int(parents[1])].add_child(tcid)
  else:
    tcs[tcid].add_parent(int(parents))
    tcs[int(parents)].add_child(tcid)
  #print("line : {}, id : {}, parents : {}".format(tcline, tcid, parents))


dists = []

while len(dists) < NUM_PAIR:
  print(len(dists))
  tc1 = random.randrange(0,num_tc)

  relevants = tcs[tc1].get_relevants(tcs)
  if tc1 in relevants:
    relevants.remove(tc1)

  if len(relevants) == 0:
    continue

  tc2 = random.choice(tuple(relevants))

  if tc1 not in tclistidx or tc2 not in tclistidx:
    continue

  f1 = open(tclist[tclistidx[tc1]], "rb")
  f2 = open(tclist[tclistidx[tc2]], "rb")
  bytes1 = f1.read()
  bytes2 = f2.read()
  f1.close()
  f2.close()

  if len(bytes1) > len(bytes2):
    bytes1, bytes2 = bytes2, bytes1

  dist = editdistance.eval(bytes1,bytes2)

  rel_dist = dist / len(bytes2)

  dists.append(rel_dist)
  
print("Avg. dist : {:.3f}%".format(sum(dists) / len(dists) * 100))
print("Max. dist : {:.3f}%".format(max(dists) * 100))

score_split = [0] * 21

for s in dists:
  score_split[int(s* 20)] += 1

f = open("byte_similarity.csv", "w")
f.write("0-5,5-10,10-15,15-20,20-25,25-30,30-35,35-40,40-45,45-50,50-55,55-60,60-65,65-70,70-75,75-80,80-85,85-90,90-95,95-100\n")
for s in score_split:
  f.write("{},".format(s))

f.close()
