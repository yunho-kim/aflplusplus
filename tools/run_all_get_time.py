import sys
import glob
import subprocess


if len(sys.argv) != 4:
  print("usage : python3 run_all.py out_dir args search_string")
  exit()

out_dir = sys.argv[1]
search_string = sys.argv[3].encode()

for i in range(1, 3 + 1):
  out_tmp_dir = out_dir + "/" + str(i)
  print(out_tmp_dir)
  min_queue_tc_idx = 1234567890
  min_crash_tc_idx = 1234567890
  min_time = 123456789000000
  for file_path in glob.glob(out_tmp_dir + "/queue/*") + glob.glob(out_tmp_dir + "/crashes/*"):
    cmd = sys.argv[2].replace("@@", file_path).split(" ")
    run = subprocess.run(cmd , stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    if search_string in run.stdout:
      tc_id = int(file_path.split("id:")[1][:6])
      if "queue" in file_path and tc_id < min_queue_tc_idx:
        min_queue_tc_idx = tc_id
      if "crash" in file_path and tc_id < min_crash_tc_idx:
        min_crash_tc_idx = tc_id
      if "time" in file_path:
        time = int(file_path.split("time:")[1].split(",")[0])
        if min_time > time:
          min_time = time
  print("min_queue_idx : {}, min_crash_idx : {}, min_time : {}\n".format(min_queue_tc_idx, min_crash_tc_idx, min_time))
