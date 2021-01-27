import subprocess
import glob
import random
from gen_tree import tctree

NUM_PAIR = 5000

tcs = []

tclist = glob.glob("./queue/*")
num_tc = len(tclist)

for i in range(num_tc):
  tcs.append(tctree(i))

for tcline in tclist:
  if "orig" in tcline or "sync" in tcline:
    continue
  
  tcid = int(tcline.split("/")[-1].split(",")[0][3:])

  parents = tcline.split("/")[-1].split(",")[1][4:]
  if "+" in parents:
    parents = parents.split("+")
    tcs[tcid].add_parent(int(parents[0]))
    tcs[tcid].add_parent(int(parents[1]))
    tcs[int(parents[0])].add_child(tcid)
    tcs[int(parents[1])].add_child(tcid)
  else:
    tcs[tcid].add_parent(int(parents))
    tcs[int(parents)].add_parent(tcid)

score_sum = 0
score_idx = 0
maxscore = 0

scores = []

i = 0
while i < NUM_PAIR:
  tc1 = random.randrange(0,num_tc)
  tc2 = random.randrange(0,num_tc)
  if tc1 == tc2:
    continue

  if not tcs[tc1].is_relevant(tcs, tc2):
    continue
  
  tmp1len = 0
  tmp2len = 0
  f1 = open(tclist[tc1], "rb")
  tmp1 = open("tmp1","wb")
  byte = f1.read(1)
  while byte:
    tmp1.write(byte + b"\n")
    tmp1len += 1
    byte = f1.read(1)
  tmp1.close()
  f1.close()

  f2 = open(tclist[tc2], "rb")
  tmp2 = open("tmp2","wb")
  byte = f2.read(1)
  while byte:
    tmp2len += 1
    tmp2.write(byte + b"\n")
    byte = f2.read(1)
  tmp2.close()
  f2.close()

  cmd = ["diff" , "-a", "tmp1", "tmp2"]

  out = subprocess.run(cmd, stdout=subprocess.PIPE).stdout;

  if tmp1len < tmp2len:
    tmplen = tmp2len
  else:
    tmplen = tmp1len

  num_diff = 0

  for b in out.split(b"\n"):
    if len(b) > 0 and b[0] == 62:
      num_diff += 1

  if num_diff > tmplen:
    tmp = 0
  else :
    tmp = 1.0 - (num_diff / tmplen)

  #print ("tmplen : {}, num_diff : {}, score : {:.1f}%".format(tmplen, num_diff, tmp * 100))
  
  if num_diff > tmplen:
    print("diff > len")
    #print("{}, {}".format(tclist[tc1],tclist[tc2]))
    #exit()

  score_sum += tmp
  if tmp > maxscore:
    maxscore = tmp
  score_idx += 1
  scores.append(tmp)
  i += 1

print("Avg. same percent : {:.3f}%".format(score_sum / score_idx * 100))
print("Max. same percent : {:.3f}%".format(maxscore * 100))

score_split = [0] * 21

for s in scores:
  score_split[int(s* 20)] += 1
  
f = open("rel_byte_similarity.csv", "w")
f.write("0-5,5-10,10-15,15-20,20-25,25-30,30-35,35-40,40-45,45-50,50-55,55-60,60-65,65-70,70-75,75-80,80-85,85-90,90-95,95-100\n")
for s in score_split:
  f.write("{},".format(s))

f.close()
  
