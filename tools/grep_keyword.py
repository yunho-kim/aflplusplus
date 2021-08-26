
import sys

if len(sys.argv) != 2:
  print("usage : python3 {} <html_file>".format(sys.argv[0]))
  exit(0)


f1 = open(sys.argv[1], "r")

b = f1.read(1)
stage = 0
keywords = []

def add_k(k):
  if len(k) == 0 : return

  if ' ' in k:
    for k2 in k.split(' '):
      add_k(k2)
    return

  if '[' in k and ']' in k:
    seg1 = k.split("[")[0]
    seg2 = k.split('[')[1].split(']')[0]
    seg3 = k.split(']')[1]
    if ',' in seg2:
      for b in seg2.split(','):
        tmp = seg1 + b + seg3
        if tmp not in keywords:
          keywords.append(tmp)
    else:
      for b in seg2:
        tmp = seg1 + b + seg3
        if tmp not in keywords:
          keywords.append(tmp)
    return

  if k not in keywords:
    keywords.append(k)

keyword = ''
while(b != ''):
  if stage == 0 :
    if b == '<' :
      if f1.read(1) == 'b' and f1.read(1) == '>':
        stage = 1
  elif stage == 1:
    if b == '<' :
      add_k(keyword)
      keyword = ''
      stage = 0
    else:
      keyword += b
  b = f1.read(1)

f2 = open("keywords.txt", "w")

for k in keywords:
  f2.write("{}\n".format(k))

f1.close()
f2.close()