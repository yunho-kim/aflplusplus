
import sys
import glob
import subprocess

if len(sys.argv) != 3:
  print("usage : python3 run_idx.py idx 'args'")
  exit()



idx = sys.argv[1]
filepath = glob.glob("./id:" + "0" * (6 - len(str(idx))) + str(idx)+ "*")

cmd = sys.argv[2].replace("@@", filepath[0]).split(" ")

run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);

try:
  print(run.stdout.decode("utr-8"))
except:
  for a in run.stdout.split(b"\n"):
    print(a)
