import os
import glob
import random
import subprocess

args = {"cflow" : "-o /dev/null @@", "exifdata" : "@@ xml" , "gifsicle" : "-I @@", "jq" : ". @@",
        "objdump" : "-d @@", "pal2rgb" : "@@ /dev/null", "size" : "@@", "tiff2pdf" : "@@ -o /dev/null",
        "tiff2ps" : "@@", "yasm" : "@@ -o /dev/null", "nm" : "-C @@", "ffmpeg" : "-i @@ -f mp4 -y /dev/null",
        "jhead" : "@@", "pngfix" : "@@", "tcpdump" : "-r @@", "jbig2dec" : "@@ -o /dev/null",
        "nasm" : "@@ -o /dev/null", "jasper" : "-f @@ -T bmp -F /dev/null",
        "cjpeg" : "@@", "bison" : "@@ -o /dev/null",  "exiv2" : "@@", "bsdtar" : "-xOf @@", "readelf" : "-a @@",
        "tar" : "-xOf @@", "xmllint": "@@", "sassc" : "@@", "exiv2json" : "@@"
}


#Assume in out_dir.

#os.stat(tc).st_size

crashes = {}

for tc in glob.glob("./*/crashes/*"):
  if "README" not in tc:
    crashes[os.stat(tc).st_size] = tc

if len(crashes) > 10:
  lens = list(crashes.keys())
  lens.sort()
  lens = lens[10:]
  for l in lens:
    del crashes[l]

for tc in glob.glob("./*/queue/*"):
  subject = os.getcwd().split("/")[-1].split("_")[1]
  cmd = [ "/home/cheong/subjects_asan/{}/{}.san".format(subject,subject)  ] +  args[subject].replace("@@", tc).split(" ")

  timeout = False
  try:
    run = subprocess.run(cmd, stdout = subprocess.DEVNULL, stderr = subprocess.PIPE, timeout= 3)
  except:
    timeout = True
   
  if not timeout and b"AddressSanitizer" in run.stderr and b"LeakSanitizer" not in run.stderr:
    if len(crashes) == 10:
      lens = list(crashes.keys())
      lens.sort()
      new_len = os.stat(tc).st_size
      if new_len < lens[9]:
        del crashes[lens[9]]
        crashes[new_len] = tc
    
    else:
      crashes[os.stat(tc).st_size] = tc

dist_file = open("crash_dists.csv", "w")

for crash_tc_len in crashes:
  tc = crashes[crash_tc_len]
  
  cmd = ["cp", tc, "tmp1"]
  subprocess.run(cmd)

  tcdir = "/".join(tc.split("/")[:-2])

  for anothertc in glob.glob(tcdir + "/queue/*"):
    if tc == anothertc:
      continue

    cmd = ["cp", anothertc, "tmp2"]
  
    subprocess.run(cmd)
    cmd = ["./distance"]

    try :
      out = subprocess.run(cmd, stdout=subprocess.PIPE, timeout=5).stdout
    except:
      continue

    dist = int(out.strip().split(b" ")[-1].decode())
    dist_file.write("{}\n".format(dist))

dist_file.close()
