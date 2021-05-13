
import sys

if len(sys.argv) != 2:
  print("python3 score_csv.py FRIEND_debug.txt")
  exit()


data = []

f1 = open(sys.argv[1], "r")
f2 = open("byte_out.csv", "w")

nextline = False
while True:
  line = f1.readline()
  if not line :
    break

  if nextline:
 
    bytesels = line.strip().split(",")[:-1]
    data.append(bytesels)
    nextline = False

  elif "threshold" in line:
    nextline = True

f1.close()

data = data[:1000]

data2 = []

for byte in data:
  for offset in byte:
    offset = int(offset)
    if len(data2) < offset + 1:
      data2 = data2 + [0] * (offset + 1 - len(data2))
    data2[offset] += 1 

for b in data2:
  f2.write("{}\n".format(b))

f2.close()

