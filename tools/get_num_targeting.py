import sys

if len(sys.argv) != 2:
  print("python3 get_num_targeting.py FRIEND_debug.txt")
  exit(0)

f1 = open(sys.argv[1], "r")

num_target = 0
for line in f1:
  if "**** Mutating" in line:
    num_target += 1

f1.close()

print(num_target)
