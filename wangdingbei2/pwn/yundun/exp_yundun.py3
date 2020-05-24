#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
vim 2 <= %1$p
cat 2
"""

import sys
from typing import Optional
from pwn import *
from pwnlib import gdb

context(arch="amd64", os="linux", log_level="debug")

class Config:
    def __init__(self,
            elf: str,
            remote_host: Optional[str]=None,
            remote_port: Optional[int]=None,
            libc_ver: Optional[str]=None,
            remote_libc: Optional[str]=None) -> None:
        self.elf: str = elf
        if remote_host is not None and remote_port is not None and 0 < remote_port < 65536:
            self.remote = (remote_host, remote_port)
        else:
            self.remote = None
        if libc_ver is None:
            if context.arch.lower() == "amd64":
                self.ld = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
                self.libc = "/lib/x86_64-linux-gnu/libc.so.6"
            elif context.arch.lower() == "i386":
                self.ld = "/lib/i386-linux-gnu/ld-linux.so.2"
                self.libc = "/lib/i386-linux-gnu/libc.so.6"
            else:
                self.ld = None
                self.libc = None
        else:
            assert libc_ver in {"2.19", "2.23", "2.24", "2.27", "2.28", "2.29", "2.30", "2.31"}
            assert context.arch.lower() in {"amd64", "i386"}
            arch = 64 if context.arch.lower() == "amd64" else 32
            ld = "ld-linux-x86-64.so.2" if arch == 64 else "ld-linux.so.2"
            self.ld = f"/glibc/{libc_ver}/{arch}/lib/{ld}"
            self.libc = f"/glibc/{libc_ver}/{arch}/lib/libc.so.6"
        self.remote_libc = self.libc if remote_libc is None else remote_libc


cfg = Config("./pwn", "59.110.243.101", 54621, "2.23")
elf = ELF(cfg.elf)

if len(sys.argv) > 1:
    io = remote(cfg.remote[0], cfg.remote[1])
    libc = ELF(cfg.remote_libc)
else:
    io = process([cfg.ld, cfg.elf], env={"LD_PRELOAD": cfg.libc})
    libc = ELF(cfg.libc)


def main():
    io.interactive()

if __name__ == "__main__":
    main()