import glob
import sys
import subprocess


if len(sys.argv) != 3:
  print("Usage : python3 {} out_dir subjectcmd".format(sys.argv[0]))
  exit(0)

subject = sys.argv[2]

for i in range(1, 3 + 1):
  crash_dir = sys.argv[1] + "/" + str(i) + "/crashes"
  print(crash_dir)
  crashes = glob.glob(crash_dir + "/*")

  if len(crashes) == 0:
    print("No crashes")

  for c in crashes:
    sub_cmd = subject.replace("@@", c)
    cmd = ["gdb", "--batch", "--command=test.gdb",  "--args"] + sub_cmd.split(" ")
    res = subprocess.run(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    try:
      print(res.stdout.decode("utf-8"))
    except:
      print("Can't decode with utr-8!")
      for a in res.stdout.split(b"\n"):
        print(a)
