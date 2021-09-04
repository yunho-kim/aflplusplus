import glob
import sys

if len(sys.argv) != 2:
  print("usage : {} <queue dir>".format(sys.argv[0]))
  exit(0)

args = dict()
num_tcs = 0
for fn in glob.glob("{}/*".format(sys.argv[1])):
  print(fn)
  num_tcs +=1
  fn = fn.split("/")[-1]
  try:
    argv = int(fn.split("argv:")[1].split(',')[0])
  except:
    argv = 0
  if argv not in args:
    args[argv] = 0
  args[argv] += 1

print("num tcs : {}".format(num_tcs))
print(args)
