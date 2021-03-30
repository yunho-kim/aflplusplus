import sys
import glob
import subprocess


if len(sys.argv) != 3:
  print("usage : python3 run_all.py out_dir args")
  exit()

out_dir = sys.argv[1]

for i in range(1, 3 + 1):
  out_tmp_dir = out_dir + "/" + str(i)
  print(out_tmp_dir)
  for file_path in glob.glob(out_tmp_dir + "/queue/*") + glob.glob(out_tmp_dir + "/crashes/*"):
    cmd = sys.argv[2].replace("@@", file_path).split(" ")
    timeout = False
    try:
      run = subprocess.run(cmd , stdout = subprocess.PIPE, stderr = subprocess.STDOUT, timeout=5)
    except:
      timeout = True
    if not timeout and b"AddressSanitizer" in run.stdout and b"LeakSanitizer" not in run.stdout:
      print(" ".join(cmd))
      for a in run.stdout.split(b"\n"):
        print(a)
