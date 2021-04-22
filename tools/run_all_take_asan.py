import sys
import glob
import subprocess


if len(sys.argv) != 3:
  print("usage : python3 run_all.py out_dir args")
  exit()

out_dir = sys.argv[1]

class Trace:
  def __init__(self, symptom, stack):
    self.symptom = symptom
    self.stack = stack

  def __hash__(self):
    ret = self.symptom, tuple(self.stack)
    return hash(ret)

  def __eq__(self, other):
    if len(self.stack) != len(other.stack):
      return False

    for i in range(len(self.stack)):
      if self.stack[i] != other.stack[i]:
        return False

    return self.symptom == self.symptom


asan = False

traces = set()
fullstacks = {}
filename = ""

curt = None
curs = b""
stack = []
fullstack = b""

asan1 = False
asan2 = False

for i in range(1, 3 + 1):
  out_tmp_dir = out_dir + "/" + str(i)
  queue_list = glob.glob(out_tmp_dir + "/queue/*") # + glob.glob(out_tmp_dir + "/crashes/*")
  for file_path in queue_list:
    filename = file_path 
    cmd = sys.argv[2].replace("@@", file_path).split(" ")
    timeout = False
    try:
      run = subprocess.run(cmd , stdout = subprocess.DEVNULL, stderr = subprocess.PIPE, timeout=5)
    except:
      timeout = True
    if not timeout and b"AddressSanitizer" in run.stderr and b"LeakSanitizer" not in run.stderr:
      for line in run.stderr.split(b"\n"):
        if asan:
          fullstack += line + b"\n"
          if asan2 and b" in " in line and b"#" in line:
            stack.append(line.split(b" ")[7])
            if len(stack) > 5:
              asan2 = False
          
        if b"=============================" in line:
          asan1 = True
        elif asan1:
          if b"LeakSanitizer" in line:
            asan1 = False
            continue
          fullstack = line
          line = line.strip().split(b" ")[2:]
          if len(line) > 4:
            line = line[:4]
          curs = b" ".join(line)
          stack = []
          asan = True
          asan1 = False
          asan2 = True

      if asan:
        asan = False
        asan1 = False
        asan2 = False
        newt = Trace(curs, stack)
        if not newt in traces:
          traces.add(newt)
          fullstacks[filename] = fullstack
        fullstack = b""
        stack = []
        curs = ""

for filename in fullstacks:
  print("**testcase : " + filename)
  for line in fullstacks[filename].split(b"\n"):
    print(line)
  print("\n")
