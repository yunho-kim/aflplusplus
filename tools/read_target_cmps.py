import sys

if len(sys.argv) != 3:
  print("python3 read_target_cmps.py cmp_queue.stat result.ir")
  exit()


cmps = set()

f1 = open(sys.argv[1], "r")

f1.readline()
f1.readline()

for line in f1:
  cmpid = int(line.split(",")[0])
  cmps.add(cmpid)
f1.close()

f2 = open(sys.argv[2], "r")
fo = open("target_cmps.txt", "w")

for line in f2:
  if "#### cmp id" in line:
    cmpid = int(line.strip().split("#### cmp id : ")[1])
    if cmpid in cmps:
      fo.write("{}\n".format(line.strip()))
      cmps.remove(cmpid)

f2.close()
fo.close()
print(cmps)
