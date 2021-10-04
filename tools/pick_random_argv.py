import random
import subprocess as subp
import sys
import glob

if len(sys.argv) != 3:
  print("python {} <keywords_dir> <out_dir>".format(sys.argv[0]))
  exit(1)


keywords = [b"usage", b"Usage", b"Invalid argument", b"Trailing options were found", b"Invalid loglevel",
  b"Expected number for ", b"extra operand", b"unrecognized option", b"invalid argument", b"invalid long option",
  b"To see the options list", b"exception in print action for ", b"exception in rename action",
  b"Unrecognized option", b"jasper --help", b"unknown optimization option", b"unrecognized error reporting format",
  b"unrecognised option" , b"Syntax must be either", b"Algorithm must be either", b"Unknown command",
  b"option requires an argument", b"Offset must be a numeric" , b"Rotation angle must be",
  b"Max viewport width cannot exceed", b"imagemask operator requires", b"Page orientation must be",
  b"is incompatible with", b"Use Only one of",  b"More info with:", b"unknown option",
  b"requires an integer argument", b"wrong syntax for `",  b"requires a string argument",
  b"too many `"
  ]

WHITE = ["pdftopng", "pdftops"]

facto = [1]

for i in range(1, 30):
  facto.append(i * facto[i-1])

for fn in glob.glob("{}/*".format(sys.argv[1])):

  subject_n = fn.split("/")[-1]
  if len(WHITE) > 0 and subject_n not in WHITE:
    continue
   
  out_fn = "{}/{}".format(sys.argv[2], subject_n)


  argvs = []
  words = []
  with open (fn, "r") as f1:
    for line in f1:
      words.append(line.strip())

    print ("{} : {} words".format(subject_n, len(words)))

  if len(words) == 0:
    continue

  while len(facto) < (len(words) + 1):
    tmp = len(facto)
    facto.append(facto[tmp - 1] * tmp)

  prob = [0]
  for i in range(1, 10 + 1):
    #prob.append((facto[len(words)] // facto[len(words) - i]) / facto[len(words)] )
    prob.append(1)
  
  lens = list(range(10 + 1))

  with open (out_fn, "w") as f1:
    num_argv = 0
    try:
      with open("./init_keywords/{}".format(subject_n), "r") as f2:
        for line in f2:
          if len(line.strip()) == 0 :
            continue
          f1.write(line)
          argvs.append(line.strip())
          num_argv += 1
    except:
      print ("can't open {}".format(subject_n))
      pass
 
    while num_argv < 10:
      new_len = random.choices(lens, weights=prob)[0]
      idxs = list(range(len(words)))
      random.shuffle(idxs)
      argv = []
      for j in range(new_len):
        argv.append(words[idxs[j]])      
      argv[random.randrange(len(argv))] = "@@"
      cmd = ["timeout" , "-k", "1", "1", "/home/cheong/subjects_gcov/{}/install_gcov/bin/{}".format(subject_n,subject_n)] + argv
      out = subp.run(cmd, stdout=subp.PIPE, stderr= subp.STDOUT).stdout
      found = False
      for line in out.split(b"\n"):
        for key in keywords:
          if key in line:
            found = True
            break
      if found:
        continue
      with open ("logs/{}_{}".format(subject_n, num_argv), "wb") as f3:
        f3.write(out)
     
      if " ".join(argv) in argvs:
        continue
      num_argv += 1
      f1.write(" ".join(argv) + "\n")
      print(num_argv)
