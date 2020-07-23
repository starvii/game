#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
如果依赖特定版本的libc，请使用patchelf对可执行文件修改
例如，使用x64的2.23版本的libc，

patchelf --set-interpreter /glibc/2.27/64/lib/ld-linux-x86-64.so.2 easy_heap_patched
patchelf --replace-needed libc.so.6 /glibc/2.27/64/lib/libc.so.6 easy_heap_patched

"""

import re, sys, os.path as path
from pwn import *
from pwnlib import gdb


context(arch="amd", os="linux")

elf_name = path.join(path.dirname(path.abspath(__file__)), "easy_heap_patched")
_, host, port = re.split("\s+", "nc 127.0.0.1 4444")

elf = ELF(elf_name)
libc = elf.libc

io, context.log_level = (remote(host, port), "info") if len(sys.argv) > 1 else (process(elf_name), "debug")


def main():
    if isinstance(io, process):
        gdb.attach(io, gdbscript="b *0x88888888")
        pause()
    io.interactive()


if __name__ == "__main__":
    main()
