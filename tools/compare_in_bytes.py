import subprocess
import glob
import random


NUM_PAIR = 1000

tclist = glob.glob("./queue/*")
num_tc = len(tclist)

dists = []

i = 0


while i < NUM_PAIR:
  tc1 = random.randrange(0,num_tc)
  tc2 = random.randrange(0,num_tc)
  if tc1 == tc2:
    continue

  i += 1

  f1 = open(tclist[tc1], "rb")
  f2 = open(tclist[tc2], "rb")
  bytes1 = f1.read()
  bytes2 = f2.read()
  f1.close()
  f2.close()

  if len(bytes1) < len(bytes2):
    bytes1, bytes2 = bytes2, bytes1

  prev_row = range(len(bytes2) + 1)
  for i, b1 in enumerate(bytes1):
    cur_row = [i + 1]
    for j, b2 in enumerate(bytes2):
      insertions = prev_row[j+1] + 1
      deletions = cur_row[j] + 1
      substitutions = prev_row[j] + (b1 != b2)
      cur_row.append(min(insertions, deletions, substitutions))
    prev_row = cur_row

  dist = prev_row[-1]

  rel_dist = dist / len(bytes2)
  
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
