
import sys
import random
from operator import itemgetter

if len(sys.argv) != 3:
  print("usage : python3 {} <FRIEND dir> <subject dir>\n".format(sys.argv[0]))
  exit(0)


f1 = open("{}/FRIEND.stat".format(sys.argv[1]), "r")
num_func = int(f1.readline().strip().split(":")[1])
f1.close()

args = []
f1 = open("{}/argvs_init".format(sys.argv[1]), "r")
for line in f1:
  if "idx, # of input" in line:
    break
  else:
    argv = line.strip().split(" : ")[1:]
    argv = " : ".join(argv)
    args.append(argv)

num_arg_inputs = []
for line in f1:
  num_arg_inputs.append(int(line.strip().split(",")[1]))

f1.close()

f1 = open("{}/num_func_calls".format(sys.argv[1]), "r")
num_args = 0
total_calls = [0] * num_func
arg_calls = []

call_args = []
for idx in range(num_func):
  call_args.append([])

while True:
  calls = f1.readline()
  if calls == "":
    break
  calls = calls.strip().split(",")[:-1]
  arg_calls.append([])
  for idx in range(num_func):
    total_calls[idx] += int(calls[idx])
    if int(calls[idx]) != 0:
      call_args[idx].append(num_args)
      arg_calls[num_args].append(idx)
  num_args += 1

f1.close()

print("# args : {}, # func : {}".format(num_args, num_func))
for idx in range(num_func):
  if total_calls[idx] != 0:
    print("{}:{}, {}".format(idx, total_calls[idx], call_args[idx]))


num_call_args = []
for idx in range(num_args):
  num_call_args.append((idx, len(arg_calls[idx])))

#num_call_args.sort(key=itemgetter(1))

func_set = set()
arg_set = set()

arg_set.add(0)
for func_id in arg_calls[0]:
  func_set.add(func_id)

for p in num_call_args:
  for func_id in arg_calls[p[0]]:
    if not func_id in func_set:
      func_set.add(func_id)
      arg_set.add(p[0])

print(len(arg_set))
for argv_idx in arg_set:
  print("{} : {} : {}".format(argv_idx, num_arg_inputs[argv_idx], args[argv_idx]))

#random func rel...

rels = []
for idx1 in range(num_func):
  rels.append([0] * num_func)
for idx1 in range(num_func):
  rels[idx1][idx1] = 1.0
  for idx2 in range(idx1 + 1, num_func):
    rels[idx1][idx2] = random.random()
    rels[idx2][idx1] = rels[idx1][idx2]

args_rel = []
for idx1 in range(num_args):
  args_rel.append([0] * num_args)

for idx1 in range(num_args):
  for idx2 in range(idx1 + 1, num_args):
    num_pair = 0
    sum_rel = 0
    for func_id1 in arg_calls[idx1]:
      for func_id2 in arg_calls[idx2]:
        sum_rel += rels[func_id1][func_id2]
        num_pair += 1

    args_rel[idx1][idx2] = sum_rel / num_pair
    args_rel[idx2][idx1] = sum_rel / num_pair

'''
for idx in range(num_args):
  print("{} : ".format(idx), end = "")
  for idx2 in range(num_args):
    print("{},".format(args_rel[idx][idx2]), end="")
  print("")
'''


