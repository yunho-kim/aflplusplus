import glob

with open("cp.sh", "w") as f1:
  for fn in glob.glob("./keywords/*"):
    subjn = fn.split("/")[-1]
    f1.write("cp {} subjects_friend/{}/keywords.txt\n".format(fn, subjn))

  for fn in glob.glob("./random_argvs/*"):
    subjn = fn.split("/")[-1]
    f1.write("cp {} subjects_friend/{}/argvs.txt\n".format(fn, subjn))


