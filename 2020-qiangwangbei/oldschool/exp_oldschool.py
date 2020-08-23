#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
如果依赖特定版本的libc，请使用patchelf对可执行文件修改
例如，使用x64的2.23版本的libc，

patchelf --set-interpreter /glibc/2.27/32/lib/ld-linux.so.2 ./oldschool_patched
patchelf --replace-needed libc.so.6 ./libc-2.27.so ./oldschool_patched

"""

import re, sys, os.path as path
from pwn import *
from pwnlib import gdb


context(arch="i386", os="linux")

elf_name = path.join(path.dirname(path.abspath(__file__)), "oldschool_patched")
_, host, port = re.split("\s+", "nc 106.14.214.3 2333")

elf = ELF(elf_name)
libc = elf.libc

io, context.log_level = (remote(host, port), "info") if len(sys.argv) > 1 else (process(elf_name), "debug")


def allocate(idx, size):
    io.sendlineafter("Your choice: ", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))


def delete(idx):
    io.sendlineafter("Your choice: ", "4")
    io.sendlineafter("Index: ", str(idx))

def show(idx):
    io.sendlineafter("Your choice: ", "3")
    io.sendlineafter("Index: ", str(idx))
    io.recvuntil("Content: ")
    return io.recvuntil("\n", drop=True)

def edit(idx, content):
    io.sendlineafter("Your choice: ", "2")
    io.sendlineafter("Index: ", str(idx))
    io.sendafter("Content: ", content)

def mmap_allocate(idx):
    io.sendlineafter("Your choice: ", "6")
    io.sendlineafter("Where do you want to start: ", str(idx))

def mmap_edit(idx, int_val):
    io.sendlineafter("Your choice: ", "7")
    io.sendlineafter("Index: ", str(idx))
    io.sendafter("Value: ", int_val)

def mmap_delete():
    io.sendlineafter("Your choice: ", "8")

def main():
    allocate(0, 0x40)
    allocate(1, 0x40)
    allocate(2, 0x40)
    allocate(3, 0x40)
    allocate(4, 0x40)
    allocate(5, 0x40)
    allocate(6, 0x40)
    allocate(7, 0x40)
    allocate(8, 0x40)
    allocate(9, 0x40)

    delete(9)
    delete(8)
    delete(7)
    delete(6)
    delete(5)
    delete(4)
    delete(3)
    delete(2)
    delete(1)
    delete(0)

    # TODO: 


    if isinstance(io, process):
        gdb.attach(io)
        pause()
    io.interactive()


if __name__ == "__main__":
    main()