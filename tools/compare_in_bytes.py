import os
import subprocess
import editdistance
import glob
import random


NUM_PAIR = 100

tclist = glob.glob("./queue/*")
num_tc = len(tclist)

dists = []

while len(dists) < NUM_PAIR:

  #print(len(dists))
  tc1 = random.randrange(0,num_tc)
  tc2 = random.randrange(0,num_tc)
  if tc1 == tc2:
    continue

  f1 = open(tclist[tc1], "rb")
  f2 = open(tclist[tc2], "rb")

  cmd = ["cp", tclist[tc1], "tmp1"]
  subprocess.run(cmd)

  cmd = ["cp", tclist[tc2], "tmp2"]
  subprocess.run(cmd)

  cmd = ["./distance"]

  try :
    out = subprocess.run(cmd, stdout=subprocess.PIPE, timeout=1).stdout
  except:
    continue

  dist = int(out.strip().split(b" ")[-1].decode())

  max_dist = max(os.stat(tclist[tc1]).st_size,os.stat(tclist[tc2]).st_size)

  rel_dist = dist / max_dist
  if rel_dist > 1.0:
    rel_dist = 1.0
  dists.append(rel_dist)


#print(dists)

#print("Avg. dist : {:.3f}%".format(sum(dists) / len(dists) * 100))

#print("Max. dist : {:.3f}%".format(max(dists) * 100))

score_split = [0] * 21

for s in dists:
  score_split[int(s* 20)] += 1

f = open("byte_similarity.csv", "w")
f.write("0-5,5-10,10-15,15-20,20-25,25-30,30-35,35-40,40-45,45-50,50-55,55-60,60-65,65-70,70-75,75-80,80-85,85-90,90-95,95-100\n")
for s in score_split:
  f.write("{},".format(s))

f.close()
