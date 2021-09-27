
import random
import sys
import glob

if len(sys.argv) != 3:
  print("python {} <keywords_dir> <out_dir>".format(sys.argv[0]))
  exit(1)

facto = [1]

for i in range(1, 30):
  facto.append(i * facto[i-1])

for fn in glob.glob("{}/*".format(sys.argv[1])):

  subject_n = fn.split("/")[-1]

  if subject_n != "xmlwf":
    continue
  out_fn = "{}/{}".format(sys.argv[2], subject_n)

  words = []
  with open (fn, "r") as f1:
    for line in f1:
      words.append(line.strip())

    print ("{} : {} words".format(subject_n, len(words)))

  '''
  while len(facto) < (len(words) + 1):
    tmp = len(facto)
    facto.append(facto[tmp - 1] * tmp)

  prob = [0]
  for i in range(1, len(words) + 1):
    prob.append(facto[len(words)] / facto[len(words) - i])
  
  lens = list(range(len(words) + 1))
  '''
  if len(words) == 0:
    continue

  with open (out_fn, "w") as f1:
    for i in range(10):      
      #new_len = random.choices(lens, weights=prob)
      new_len = random.randrange(1, min(10, len(words)) + 1)
      idxs = list(range(len(words)))
      random.shuffle(idxs)
      argv = []
      for j in range(new_len):
        argv.append(words[idxs[j]])      

      argv[random.randrange(len(argv))] = "@@"
      f1.write(" ".join(argv) + "\n")
