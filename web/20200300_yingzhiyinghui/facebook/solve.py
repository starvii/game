#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import requests

URL = "http://10.0.0.10/facebook/index.php"

session = requests.session()
r = session.get(URL)
html = r.text

a = re.findall(r"\d+\s*\+\s*\d+\s*\=\s*\?", html, re.M)
assert len(a) > 0
a = a[0]
b = re.findall(r"\d+", a)
assert len(b) == 2
c = int(b[0]) + int(b[1])

r = session.post(URL, dict(
    username="admin",
    password="12345678",
    validcode=str(c),
    submit="submit",
))
print(r.text)
