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

f = open("length.csv", "w")
for tc in glob.glob("./*/queue/*"):
  f.write("{}\n".format(os.stat(tc).st_size))
f.close()

f = open("crashes.list", "w")

for tc in glob.glob("./*/crashes/*"):
  if "README" not in tc:
    f.write("{}\n".format(tc))

for tc in glob.glob("./*/queue/*"):
  subject = os.getcwd().split("/")[-1].split("_")[1]
  cmd = [ "/home/cheong/subjects_asan/{}/{}.san".format(subject,subject)  ] +  args[subject].replace("@@", tc).split(" ")

  timeout = False
  try:
    run = subprocess.run(cmd, stdout = subprocess.DEVNULL, stderr = subprocess.PIPE, timeout= 3)
  except:
    timeout = True
   
  if not timeout and b"AddressSanitizer" in run.stderr and b"LeakSanitizer" not in run.stderr:
    f.write("{}\n".format(tc))


f.close()
