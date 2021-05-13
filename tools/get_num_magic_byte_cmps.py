import sys

if len(sys.argv) != 2:
  print("python3 get_num_ma..py target_cmps.txt")
  exit(0)


f1 = open(sys.argv[1], "r")

magic = 0
nullcmp = 0
num_cmps = 0
for line in f1:
  num_cmps += 1
  line = line.strip().split(" ")
  if line[3] == "eq":
    idx = 5
    while not "," in line[idx]:
      idx += 1

    arg1 = line[idx]
    arg2 = line[idx+1]
    if arg2[-1] == ",":
      arg2 = arg2[:-1]

    #print(arg1, arg2)
    
    if "null" == arg2:
      nullcmp += 1
    else:
      try:
        arg2 = int(arg2)
      except:
        print(line)

      magic += 1

f1.close()

print("total : {}, null : {}, magic : {}".format(num_cmps, nullcmp, magic))
