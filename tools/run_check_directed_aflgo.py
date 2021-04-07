
import subprocess
import glob
import sys
import os

if len(sys.argv) != 3:
  print("python3 run_check_directed.py out_dir target_idx")
  exit(1)

if os.getcwd() != "/home/cheong":
  print ("This scripts assume that executed in /home/cheong.")
  exit(1)

tmp = open("test.gdb", "w")
tmp.write("r\nbt\n")
tmp.close()

checks = [
 [b""],
 [b"pngerror.c:188"], # empty
 [b"pngrutil.c:1040"],
 [b"pngwutil.c:1572"],
 [b"register_Btype", b"SEGV"],
 [b"remember_Ktype"],
 [b"string_appendn", b"negative-size-param", b"gnu_special"],
 [b"d_unqualified_name", b"d_peek_char", b"SIGSEGV"],
 [b"d_print_comp_inner", b"stack-overflow", b"d_print_comp", b"#100"],
 [b"do_type", b"READ", b"SEGV on unknown address"],
 [b"do_type", b"stack-overflow", b"#100"],
]

subjects = ["/home/cheong/aflgo/subjects_aflgo/{}/pngtest.san @@"] * 3 + \
  ["cat @@ | /home/cheong/afl++/subjects_aflgo/{}/cxxfilt.san" ] * 7
  #["/home/cheong/aflgo/subjects_aflgo/{}/cxxfilt.san @@" ] * 7

outdir = sys.argv[1]
target_idx = int(sys.argv[2])
check = checks[target_idx]

min_queue_idx = -1
min_crash_idx = -1
min_queue_stdout = b""
min_crash_stdout = b""
min_queue_filename = ""
min_crash_filename = ""

tcs = glob.glob("/home/cheong/results/{}/queue/*".format(outdir)) + \
  glob.glob("/home/cheong/results/{}/crashes/*".format(outdir))

if len(tcs) == 0:
  print("Zero testcases!")
  exit(1)

num_tc = len(tcs)

idx = 0

for filename in tcs:
  if idx%10 == 0:
    print("executed {}/{}, current min idx : {},{}".format(idx, num_tc, min_queue_idx, min_crash_idx))
    pass
  idx+= 1
  if "id:" not in filename:
    continue

  file_idx = int(filename.split("/")[-1].split(",")[0][3:])
  if "queue" in filename : 
    if min_queue_idx != -1 and min_queue_idx < file_idx:
      continue
  else:
    if min_crash_idx != -1 and min_crash_idx < file_idx:
      continue
  if target_idx <= 3: 
    subject = subjects[target_idx - 1].replace("{}", str(target_idx)).replace("@@", filename)
    cmd = subject.split(" ")
    try:
      out = subprocess.run(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT, timeout = 2).stdout
    except Exception as e:
      print(e)
      continue

  else:
    subject = subjects[target_idx - 1].replace("{}", str(target_idx))
    '''
    tc = open(filename, "rb")

    tcstring = "$'"
    for b in tc.read():
      tcstring += "\\x" + hex(b)[2:]
    tcstring += "'"
    tc.close()
    '''
    cmd = subject.replace("@@", filename)

    bashscript = open("tmp.sh", "w")
    bashscript.write(cmd + "\n")
    bashscript.close()

    try:
      out = subprocess.run(["bash", "tmp.sh"], stdout=subprocess.PIPE, stderr = subprocess.STDOUT, timeout=2).stdout
    except Exception as e: 
      print(e)
      continue

 # if not b"No stack." in run.stdout:
 # if b"AddressSanitizer" in out:
 #   for t in out.split(b"\n"):   
 #     print(t)

  target_crashed = True
  for c in check:
    if c not in out:
      target_crashed = False
      break
   
  if target_crashed :
    if "queue" in filename:
      min_queue_idx = file_idx
      min_queue_stdout = out
      min_queue_filename = filename
    else:
      min_crash_idx = file_idx
      min_crash_stdout = out
      min_crash_filename = filename

if min_queue_idx == -1 and min_crash_idx == -1:
  print("Not detected")
  exit(0)

plot_file = open("/home/cheong/results/{}/plot_data".format(outdir), "r")
plot_file.readline()
firstline = plot_file.readline()
firsttime = int(firstline.split(", ")[0])
for line in plot_file:
  line = line.strip().split(", ")
  time = int(line[0]) - firsttime
  pcov = int(line[3])
  ccov = int(line[7])
  if min_queue_idx != -1 and  pcov > min_queue_idx:
    print("tc : {}\ntime : {}".format(min_queue_filename, time))
    for a in min_queue_stdout.split(b"\n"):
      print(a)
    break
  if min_crash_idx != -1 and ccov > min_crash_idx:
    print("tc : {}\ntime : {}".format(min_crash_filename, time))
    for a in min_crash_stdout.split(b"\n"):
      print(a)
    break

  

