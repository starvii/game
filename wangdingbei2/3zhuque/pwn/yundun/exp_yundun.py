#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
vim 2 <= %1$p
rm 2 free
cat 2 format

思路：
"""

import sys
from typing import Optional
from pwn import *
from pwnlib import gdb

context(arch="amd64", os="linux", log_level="debug")

fn = "./pwn@2.23"
elf = ELF(fn)
libc = elf.libc

if len(sys.argv) > 1:
    io = remote("59.110.243.101", 25413)
else:
    io = process(fn)

io.sendlineafter("> ", "vim 2")
io.sendlineafter()
io.interactive()
