
import sys
import os

if len(sys.argv) != 4:
  print("python3 {} <subject> <argv file> <tc>\nAssume tc path id absolute and it contains argv id".format(sys.argv[0]))
  exit()

tc_path = sys.argv[3]
if tc_path[0] != "/":
  tc_path = os.getcwd() + "/" + tc_path
  print("using tc_path : {}".format(tc_path))
  
argv_id = None
for entry in tc_path.split("/")[-1].split(","):
  if "argv" in entry:
    argv_id = int(entry.split(":")[1])


if argv_id == None :
  print("can't get argv id")
  exit(1)

with open (sys.argv[2], "r") as f1:
  for line in f1:
    if "queue idx, argv idx" in line:
      print ("Can't find argv idx : {}".format(argv_id))
      exit()
    
    line = line.strip()
    argv_idx = int(line.split(" : ")[0])
    if argv_id == argv_idx :
      argv = " : ".join(line.split(" : ")[1:])
      break

input_name = "/home/cheong/friend/../results/{}/default/.cur_input".format(tc_path.split("/")[-4])


argv = argv.replace(input_name, tc_path)
argv = argv.split(" ")

for idx in range(len(argv)):
  if ".afl" in argv[idx] and "subjects_friend" in argv[idx]:
    argv[idx] = sys.argv[1]
  

with open("__tmp.sh", "w") as f1:
  f1.write(" ".join(argv))
