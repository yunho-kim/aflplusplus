import sys
import glob
import subprocess


if len(sys.argv) != 3:
  print("usage : python3 run_all.py out_dir args")
  exit()

out_dir = sys.argv[1]
run_args = sys.argv[2]

for i in range(1, 3 + 1):
  out_tmp_dir = out_dir + "/" + str(i)
  print(out_tmp_dir)
  traces = []
  trace_files = []
  for file_path in glob.glob(out_tmp_dir + "/crashes/*"):
    cmd = run_args.replace("@@", file_path).split(" ")
    cmd = ["gdb", "--batch", "--command=test.gdb", "--args"] + cmd
    try:
      run = subprocess.run(cmd , stdout = subprocess.PIPE, stderr = subprocess.STDOUT, timeout=10)
    except:
      continue

    trace_line = False
    trace = b""
    for a in run.stdout.split(b"\n"):
      if trace_line:
        if len(a) == 0 or a[0] != 35: ##
          trace_line = False
          if not trace in traces:
            trace_files.append(file_path)
            traces.append(trace)
        else:
          trace += a + b"\n"
      else:
        if a[:2] == b"#0":
          trace_line = True
          trace += a + b"\n"

  print("# of traces : {}".format(len(traces)))
  for i in range(len(traces)):
    print ("TRACE # {}".format(i))
    print (trace_files[i])
    for line in traces[i].split(b"\n"):
      print(line)

