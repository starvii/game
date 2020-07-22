#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii

patchelf --set-interpreter /glibc/2.27/64/lib/ld-linux-x86-64.so.2 ./baby_tcache_patched
patchelf --replace-needed libc.so.6 ./libc.so.6 ./baby_tcache_patched

"""

import re, sys, os.path as path
from pwn import *
from pwnlib import gdb


context(arch="amd64", os="linux")

elf_name = path.join(path.dirname(path.abspath(__file__)), "baby_tcache_patched")
_, host, port = re.split("\s+", "nc 127.0.0.1 4444")

elf = ELF(elf_name)
libc = elf.libc

io, context.log_level = (remote(host, port), "info") if len(sys.argv) > 1 else (process(elf_name), "debug")


def main():
    N = 0x100
    
    if isinstance(io, process):
        gdb.attach(io, gdbscript="b *0x88888888")
        pause()
    io.interactive()


if __name__ == "__main__":
    main()
