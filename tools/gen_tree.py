CHONSU = 3

class tctree:
  def __init__(self, id):
    self.id = id
    self.parents = []
    self.children = []

  def add_child(self, id):
    self.children.append(id)

  def add_parent(self, id):
    self.parents.append(id)

  def is_relevant(self, tcs, anotherid, chonsu = CHONSU):
    def get_relevants_set(tcid, chonsu, get_parent):
      if chonsu == 1:
        ret = set()
        for child in tcs[tcid].children:
          ret.add(child)

        if get_parent:
          for parent in tcs[tcid].parents:
            ret.add(parent)

        return ret

      ret = set()
      for child in tcs[tcid].children:
        ret = ret.union(get_relevants_set(child, chonsu - 1, False))

      for parent in tcs[tcid].parents:
        ret = ret.union(get_relevants_set(parent, chonsu - 1, True))

      return ret

    relevants = get_relevants_set(self.id, chonsu)
    return anotherid in relevants

  def __repr__(self):
    return "{}:{}:{}".format(self.id, ",".join(list(map(str, self.parents))), ",".join(list(map(str,self.children))))


if __name__ == "__main__":

  f = open("log", "r")
  num_tc = 0
  for line in f:
    num_tc += 1
  f.close()

  tcs = []

  for i in range(num_tc):
    tcs.append(tctree(i))


  f = open("log", "r")

  tcid = 0
  for line in f:
    if "orig" in line or "sync" in line:
      tcid += 1
      continue

    parents = line.strip().split(",")[1][4:]
    if "+" in parents:
      parents = parents.split("+")
      tcs[tcid].add_parent(int(parents[0]))
      tcs[tcid].add_parent(int(parents[1]))
      tcs[int(parents[0])].add_child(tcid)
      tcs[int(parents[1])].add_child(tcid)
    else:
      tcs[tcid].add_parent(int(parents))
      tcs[int(parents)].add_child(tcid)

    tcid += 1

