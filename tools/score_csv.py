
import sys

if len(sys.argv) != 2:
  print("python3 score_csv.py FRIEND_debug.txt")
  exit()


data = []

f1 = open(sys.argv[1], "r")
f2 = open("score_out.csv", "w")
maxlen = 0


nextline = False
nextline2 = False
while True:
  line = f1.readline()
  if not line :
    break

  if nextline2:
    scores = line.strip().split(",")[:-1]
    data.append(scores)
    if len(scores) > maxlen:
      maxlen = len(scores)
    nextline2 = False

  elif nextline:
    nextline2 = True
    nextline = False

  elif "mutating" in line:
    nextline = True

f1.close()

data = data[:100]
maxlen = 0
for scores in data:
  if maxlen < len(scores):
    maxlen = len(scores)

print("maxlen : {}".format(maxlen))
f2.write(",")
for i in range(len(data)):
  f2.write("{},".format(i))
f2.write("\n")

for i in range(maxlen):
  f2.write("{},".format(i))
  for scores in data:
    if i < len(scores):
      f2.write("{},".format(scores[i]))
    else:
      f2.write("0,")
  f2.write("\n")

f2.close()

