import os
import glob
import random
import subprocess
import time

args = {"cflow" : "-o /dev/null @@", "exifdata" : "@@ xml" , "gifsicle" : "-I @@", "jq" : ". @@",
        "objdump" : "-d @@", "pal2rgb" : "@@ /dev/null", "size" : "@@", "tiff2pdf" : "@@ -o /dev/null",
        "tiff2ps" : "@@", "yasm" : "@@ -o /dev/null", "nm" : "-C @@", "ffmpeg" : "-i @@ -f mp4 -y /dev/null",
        "jhead" : "@@", "pngfix" : "@@", "tcpdump" : "-r @@", "jbig2dec" : "@@ -o /dev/null",
        "nasm" : "@@ -o /dev/null", "jasper" : "-f @@ -T bmp -F /dev/null",
        "cjpeg" : "@@", "bison" : "@@ -o /dev/null",  "exiv2" : "@@", "bsdtar" : "-xOf @@", "readelf" : "-a @@",
        "tar" : "-xOf @@", "xmllint": "@@", "sassc" : "@@", "exiv2json" : "@@"
}


#Assume in out_dir.

for tc in glob.glob("./*/crashes/*"):
  pass
  #get it from length script

f = open("time.csv", "w")
for tc in glob.glob("./*/queue/*"):
  subject = os.getcwd().split("/")[-1].split("_")[1]
  cmd = [ "/home/cheong/subjects_asan/{}/{}.afl".format(subject,subject)  ] +  args[subject].replace("@@", tc).split(" ")

  timeout = False
  starttime = time.time()
  try:
    subprocess.run(cmd, timeout= 3)
  except:
    timeout = True

  if timeout: 
    continue

  num_tc += 1
  exec_time = time.time() - starttime  
  f.write("{}\n".format(exec_time))

f.close()
